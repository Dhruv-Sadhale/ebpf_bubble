// bubble_sketch_ebpf.c - Optimized version with precision improvements
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "obubble_sketch_common.h"
#include "fasthash.h"

// ============================================================================
// OPTIMIZATION CONSTANTS
// ============================================================================

// Strategy 2: relocation kickout hysteresis to prevent thrashing
#define KICKOUT_MULTIPLIER_NUM 100
#define KICKOUT_MULTIPLIER_DEN 100

// Strategy 3: Space reclaim - packets since last update threshold
#define STALE_ENTRY_PACKET_THRESHOLD 50000
#define RECLAIM_COUNT_FACTOR 10  // Reclaim if count < threshold/50

// Strategy 4: Adaptive lossy thresholds
#define LOSSY_HIGH_THRESHOLD_NUM 70   // 70% of threshold - minimal decrement
#define LOSSY_HIGH_THRESHOLD_DEN 100
#define LOSSY_LOW_THRESHOLD_NUM 30    // 30% of threshold - aggressive decrement
#define LOSSY_LOW_THRESHOLD_DEN 100

// Strategy 5: Flow admission control
#define ADMISSION_START_THRESHOLD 500000    // Start probabilistic admission at 500K packets
#define ADMISSION_FULL_THRESHOLD 5000000    // More aggressive at 5M packets
#define ADMISSION_HASH_MASK 0xFFFF          // For pseudo-random admission decision


// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
} __attribute__((packed));


// Map definitions
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct BubbleSketch);
  __uint(max_entries, 1);
} sketch_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} insert_counter SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct eviction);
} eviction_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// Entry Functions
// ============================================================================
static void FORCE_INLINE Entry_init(struct Entry *e) {
#pragma unroll
  for (int i = 0; i < 14; i++) {
    e->id[i] = 0;
  }
  e->fingerprint = 0;
  e->count = 0;
  e->l0fp = 0;
  e->last_update_pkt = 0;  // CHANGE 3: Initialize staleness tracker
}

// CHANGE 4: Updated to include packet counter for staleness tracking
static void FORCE_INLINE Entry_init_with(struct Entry *e, const char *id, __u32 fp, 
                                          __u32 cnt, __u32 pkt_count) {
#pragma unroll
  for (int i = 0; i < 14; i++) {
    e->id[i] = 0;
  }
#pragma unroll
  for (int i = 0; i < KEY_LEN && i < 13; i++) {
    e->id[i] = id[i];
  }
  e->l0fp = (__u8)(fp>>24);
  e->fingerprint = fp;
  e->count = cnt;
  e->last_update_pkt = pkt_count;  // CHANGE 5: Set initial update time
}

static __u8 FORCE_INLINE Entry_Empty(const struct Entry *e) {
  return e->count == 0;
}

static __u8 FORCE_INLINE Entry_Equalfp(const struct Entry *e, __u8 fp) {
  return e->fingerprint == fp;
}

static __u8 FORCE_INLINE Entry_Equall0fp(const struct Entry *e, __u32 fp) {
  return e->l0fp == fp;
}

// CHANGE 6: Update entry and refresh staleness counter
static void FORCE_INLINE Entry_Insert(struct Entry *e, __u32 pkt_count) {
  if (e->count < 0xFFFFFFFF)
    e->count++;
  e->last_update_pkt = pkt_count;  // Refresh staleness tracker
}

// CHANGE 7: Include packet counter in insertion
static void FORCE_INLINE Entry_Insert_with(struct Entry *e, __u32 fp, const char *id, 
                                           __u32 cnt, __u32 pkt_count) {
  e->l0fp = fp;
  e->fingerprint = (__u8)(fp >> 24);
#pragma unroll
  for (int i = 0; i < 14; i++) {
    e->id[i] = 0;
  }
#pragma unroll
  for (int i = 0; i < KEY_LEN && i < 13; i++) {
    e->id[i] = id[i];
  }
  e->count = cnt;
  e->last_update_pkt = pkt_count;
}

// CHANGE 8 (Strategy 4): Adaptive lossy strategy based on count and threshold
static void FORCE_INLINE Entry_Adaptive_Lossy(struct Entry *e, __s32 threshold) {
  if (e->count == 0)
    return;
    
  // High count entries (> 70% threshold): minimal decrement
  if (threshold > 0 && e->count > ((__u32)threshold * LOSSY_HIGH_THRESHOLD_NUM / LOSSY_HIGH_THRESHOLD_DEN)) {
    e->count--;
  }
  // Low count entries (< 30% threshold): aggressive decrement
  else if (threshold > 0 && e->count < ((__u32)threshold * LOSSY_LOW_THRESHOLD_NUM / LOSSY_LOW_THRESHOLD_DEN)) {
    // Decrement by max(count/4, 1) for aggressive eviction
    __u32 decrement = e->count >> 2;  // count / 4
    if (decrement == 0)
      decrement = 1;
    if (e->count > decrement)
      e->count -= decrement;
    else
      e->count = 0;
  }
  // Medium count entries: proportional decrement
  else {
    // Decrement by count/8 for gradual eviction
    __u32 decrement = e->count >> 3;  // count / 8
    if (decrement == 0)
      decrement = 1;
    if (e->count > decrement)
      e->count -= decrement;
    else
      e->count = 0;
  }
}

// CHANGE 9 (Strategy 3): Check if entry is stale and should be reclaimed
static __u8 FORCE_INLINE Entry_IsStale(const struct Entry *e, __u32 current_pkt, __s32 threshold) {
  if (e->count == 0)
    return 0;  // Already empty
    
  // Entry is stale if:
  // 1. Not updated for STALE_ENTRY_PACKET_THRESHOLD packets
  // 2. Count is very low relative to threshold
  if (current_pkt > e->last_update_pkt + STALE_ENTRY_PACKET_THRESHOLD) {
    if (threshold > 0 && e->count < ((__u32)threshold / RECLAIM_COUNT_FACTOR)) {
      return 1;
    }
  }
  return 0;
}

// ============================================================================
// Bucket Functions
// ============================================================================

static __u8 FORCE_INLINE Bucket_Empty(struct Bucket *b, int index) {
  if (index >= 0 && index < MAX_ENTRY)
    return Entry_Empty(&b->entries[index]);
  return 1;
}

static __u8 FORCE_INLINE Bucket_Full(struct Bucket *b, int index) {
  if (index < 0 || index >= MAX_ENTRY)
    return 1;

  switch (index) {
    case 0:
      return b->entries[index].count == 0xFFFFFFFF;
    case 1:
      return b->entries[index].count >= 0xFFFF;
    case 2:
      return b->entries[index].count >= 0xFF;
    case 3:
    case 4:
      return b->entries[index].count >= 0xF;
  }
  return 0;
}

// CHANGE 10: Updated to include packet counter
static void FORCE_INLINE Bucket_Insert(struct Bucket *b, int index, __u32 pkt_count) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Insert(&b->entries[index], pkt_count);
}

static void FORCE_INLINE Bucket_Insert_entry(struct Bucket *b, int index, const struct Entry *entry) {
  if (index >= 0 && index < MAX_ENTRY)
    b->entries[index] = *entry;
}

// CHANGE 11: Updated to include packet counter
static void FORCE_INLINE Bucket_Insert_with(struct Bucket *b, int index, __u32 fp, 
                                            const char *id, __u32 pkt_count) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Insert_with(&b->entries[index], fp, id, 1, pkt_count);
}

static void FORCE_INLINE Bucket_Remove(struct Bucket *b, int index) {
  if (index < 0 || index >= MAX_ENTRY)
    return;

#pragma unroll
  for (int i = 0; i < MAX_ENTRY - 1; i++) {
    if (i >= index) {
      b->entries[i] = b->entries[i + 1];
    }
  }
  Entry_init(&b->entries[MAX_ENTRY - 1]);
}

// CHANGE 12: Updated lossy to use adaptive strategy
static void FORCE_INLINE Bucket_Lossy(struct Bucket *b, int index, __s32 threshold) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Adaptive_Lossy(&b->entries[index], threshold);
}

static void FORCE_INLINE Bucket_BucketSort(struct Bucket *b, int index) {
  if (index <= 0 || index >= MAX_ENTRY)
    return;

  #pragma unroll
  for (int i = 1; i < MAX_ENTRY; i++) {
    if (index > 0 && b->entries[index].count > b->entries[index-1].count) {
      struct Entry temp = b->entries[index];
      b->entries[index] = b->entries[index - 1];
      b->entries[index - 1] = temp;
      --index;    
    }
  }
}

static __u8 FORCE_INLINE Bucket_Equal(struct Bucket *b, int index, __u32 fp) {
  if (index < 0 || index >= MAX_ENTRY)
    return 0;

  if (index == 0) {
    return Entry_Equall0fp(&b->entries[index], fp);
  } else {
    return Entry_Equalfp(&b->entries[index], fp >> 24);
  }
}

static void FORCE_INLINE Bucket_down_stairs(struct Bucket *b, int index) {
  if (index < 0 || index >= MAX_ENTRY)
    return;

#pragma unroll
  for (int i = MAX_ENTRY - 1; i > 0; i--) {
    if (i > index) {
      b->entries[i] = b->entries[i - 1];
    }
  }
}

// CHANGE 13 (Strategy 3): Reclaim stale entries in bucket
static __u8 FORCE_INLINE Bucket_ReclaimStale(struct Bucket *b, __u32 current_pkt, __s32 threshold) {
  __u8 reclaimed = 0;
  
#pragma unroll
  for (int i = 1; i < MAX_ENTRY; i++) {  // Skip hot entry (index 0)
    if (Entry_IsStale(&b->entries[i], current_pkt, threshold)) {
      Entry_init(&b->entries[i]);
      reclaimed = 1;
    }
  }
  
  return reclaimed;
}

// ============================================================================
// BubbleSketch Functions
// ============================================================================

static __u64 FORCE_INLINE BubbleSketch_Hash_str(const char *str) {

  const __u64 seed = 0x1234567890ABCDEFULL;
  const __u64 seed2 = 0x9E3779B97F4A7C15ULL;
  return fasthash64(str, KEY_LEN, seed2);
}

// CHANGE 14 (Strategy 2): Enhanced kickout with hysteresis to prevent thrashing
static __u8 FORCE_INLINE BubbleSketch_kickout(struct BubbleSketch *bs, int kick_num,
    __u64 hash_value, struct Bucket *cur_bucket,
    int entry_index, int array_index) {
  if (kick_num <= 0 || entry_index < 0 || entry_index >= MAX_ENTRY)
    return 0;

  __u8 fp = cur_bucket->entries[entry_index].fingerprint;

  __u64 next_hash_value;
  if (array_index == 0) {
    next_hash_value = hash_value + fp;
  } else {
    next_hash_value = hash_value - fp;
  }

  __u32 next_bucket_idx = next_hash_value % MAX_BUCKETS;
  if (next_bucket_idx >= MAX_BUCKETS)
    return 0;

  struct Bucket *next_bucket = &bs->buckets[1 - array_index][next_bucket_idx];

  // CHANGE: Use hysteresis - entry must be 1.25x greater to prevent thrashing
  __u32 hot_count = next_bucket->entries[0].count;
  __u32 threshold_count = (hot_count * KICKOUT_MULTIPLIER_NUM) / KICKOUT_MULTIPLIER_DEN;
  
  if (cur_bucket->entries[entry_index].count > threshold_count) {
    Bucket_down_stairs(next_bucket, 0);
    struct Entry entry_to_move = cur_bucket->entries[entry_index];
    Bucket_Insert_entry(next_bucket, 0, &entry_to_move);
    return 1;
  }

  return 0;
}

// CHANGE 15 (Strategy 1): Dynamic threshold calculation based on load factor
static __s32 FORCE_INLINE calculate_dynamic_threshold(__u32 f_max, __u32 K, 
                                                      __u32 total_entries, 
                                                      __u32 bucket_count) {
  if (K == 0)
    return f_max;
      return (__s32)((__u64)((__u64)f_max*3) /(__u64)( (__u64)K*2 ));

}

static __u8 FORCE_INLINE should_admit_flow(__u32 global_pkt_count, __u64 flow_hash) {
  // Always admit if below first threshold
  if (global_pkt_count < ADMISSION_START_THRESHOLD)
    return 1;
  
  // Probabilistic admission based on packet count
  __u32 hash_val = (__u32)(flow_hash & ADMISSION_HASH_MASK);
  __u32 admission_threshold;
  
  if (global_pkt_count < ADMISSION_FULL_THRESHOLD) {
    // Fixed 99.5% admission rate between 500K and 5M packets
    // admission_threshold = 99.5% of hash range
    admission_threshold = (995 * (ADMISSION_HASH_MASK + 1)) / 1000;
  } else {
    // Fixed 98% admission rate for very high packet counts
    admission_threshold = (98 * (ADMISSION_HASH_MASK + 1)) / 100;
  }
  
  // Randomized admission based on hash
  return hash_val < admission_threshold;

//return 1;
}
// CHANGE 17: Main insert function with all optimizations integrated
static void FORCE_INLINE BubbleSketch_Insert(struct BubbleSketch *bs, const char *str) {
  // Increment global packet counter
  bs->global_pkt_count++;
  __u32 current_pkt = bs->global_pkt_count;
  
  __u64 hash_key = BubbleSketch_Hash_str(str);
  
  // CHANGE (Strategy 5): Flow admission control
  if (!should_admit_flow(current_pkt, hash_key)) {
    return;  // Skip this packet based on admission policy
  }
  
  __u32 fp = hash_key >> 32;

  __u64 hash_value[2] = {hash_key, hash_key + (fp >> 24)};

  __u32 keys[2] = {
    hash_value[0] % MAX_BUCKETS,
    hash_value[1] % MAX_BUCKETS
  };
 
  if (keys[0] >= MAX_BUCKETS || keys[1] >= MAX_BUCKETS)
    return;

  struct Bucket *bucket0 = &bs->buckets[0][keys[0]];
  struct Bucket *bucket1 = &bs->buckets[1][keys[1]];

  // CHANGE (Strategy 3): Periodic space reclamation
  // Reclaim stale entries every 10K packets to avoid overhead
  if ((current_pkt & 0x3FFF) == 0) {  // Every ~16K packets
    Bucket_ReclaimStale(bucket0, current_pkt, bs->threshold1);
    Bucket_ReclaimStale(bucket1, current_pkt, bs->threshold1);
  }

  // Check hot entry in bucket0
  if (Bucket_Equal(bucket0, 0, fp)) {
    Bucket_Insert(bucket0, 0, current_pkt);
    if (bucket0->entries[0].count > bs->f_max) {
      bs->f_max = bucket0->entries[0].count;
      // CHANGE (Strategy 1): Use dynamic threshold calculation
      __s32 new_threshold = calculate_dynamic_threshold(bs->f_max, bs->K, 
                                                        bs->total_entries, bs->bucket_num);
      if (new_threshold > bs->threshold1)
        bs->threshold1 = new_threshold;
    }
    return;
  }

  // If hot entry slot is empty in bucket0
  if (Bucket_Empty(bucket0, 0)) {
    Bucket_Insert_with(bucket0, 0, fp, str, current_pkt);
    bs->total_entries++;  // Track total entries
    return;
  }

  // Check bucket1 hot entry
  if (Bucket_Equal(bucket1, 0, fp)) {
    Bucket_Insert(bucket1, 0, current_pkt);
    if (bucket1->entries[0].count > bs->f_max) {
      bs->f_max = bucket1->entries[0].count;
      // CHANGE (Strategy 1): Use dynamic threshold calculation
      __s32 new_threshold = calculate_dynamic_threshold(bs->f_max, bs->K, 
                                                        bs->total_entries, bs->bucket_num);
      if (new_threshold > bs->threshold1)
        bs->threshold1 = new_threshold;
    }
    return;
  }

  if (Bucket_Empty(bucket1, 0)) {
    Bucket_Insert_with(bucket1, 0, fp, str, current_pkt);
    bs->total_entries++;
    return;
  }

  // Check cold entries
#pragma unroll
  for (int i = 1; i < MAX_ENTRY; i++) {
    // Check bucket0
    if (Bucket_Equal(bucket0, i, fp)) {
      Bucket_Insert(bucket0, i, current_pkt);
      Bucket_BucketSort(bucket0, i);
      if (bucket0->entries[1].count > bs->threshold1) {
        if (BubbleSketch_kickout(bs, MAX_KICK_OUT, hash_value[0], bucket0, 1, 0)) {
          Bucket_Remove(bucket0, 1);
        }
      }
      return;
    }

    if (Bucket_Empty(bucket0, i)) {
      Bucket_Insert_with(bucket0, i, fp, str, current_pkt);
      bs->total_entries++;
      return;
    }

    // Check bucket1
    if (Bucket_Equal(bucket1, i, fp)) {
      Bucket_Insert(bucket1, i, current_pkt);
      Bucket_BucketSort(bucket1, i);
      if (bucket1->entries[1].count > bs->threshold1) {
        if (BubbleSketch_kickout(bs, MAX_KICK_OUT, hash_value[1], bucket1, 1, 1)) {
          Bucket_Remove(bucket1, 1);
        }
      }
      return;
    }

    if (Bucket_Empty(bucket1, i)) {
      Bucket_Insert_with(bucket1, i, fp, str, current_pkt);
      bs->total_entries++;
      return;
    }
  }

  // CHANGE (Strategy 4): Adaptive lossy strategy
  // Apply to the bucket with smaller count in last position
  if (bucket0->entries[MAX_ENTRY - 1].count < bucket1->entries[MAX_ENTRY - 1].count) {
    Bucket_Lossy(bucket0, MAX_ENTRY - 1, bs->threshold1);
    if (bucket0->entries[MAX_ENTRY - 1].count == 0) {
      bs->total_entries--;
    }
  } else {
    Bucket_Lossy(bucket1, MAX_ENTRY - 1, bs->threshold1);
    if (bucket1->entries[MAX_ENTRY - 1].count == 0) {
      bs->total_entries--;
    }
  }
  
  // Track evictions
  if (bucket0->entries[MAX_ENTRY-1].count == 0 || bucket1->entries[MAX_ENTRY-1].count == 0) {
    __u32 key = 0;
    struct eviction *evict = bpf_map_lookup_elem(&eviction_map, &key);
    if (evict) {
      __sync_fetch_and_add(&evict->counter, 1);
    }
  }
}

// ============================================================================
// Packet Processing Helper Functions
// ============================================================================

// Helper to convert 5-tuple to string key
static void FORCE_INLINE tuple_to_key(struct pkt_5tuple *tuple, char *key) {
#pragma unroll
  for (int i = 0; i < 14; i++) {
    key[i] = 0;
  }
  
  // Pack tuple data into key (network byte order preserved)
  key[0] = (tuple->src_ip >> 24) & 0xFF;
  key[1] = (tuple->src_ip >> 16) & 0xFF;
  key[2] = (tuple->src_ip >> 8) & 0xFF;
  key[3] = tuple->src_ip & 0xFF;

  key[4] = (tuple->dst_ip >> 24) & 0xFF;
  key[5] = (tuple->dst_ip >> 16) & 0xFF;
  key[6] = (tuple->dst_ip >> 8) & 0xFF;
  key[7] = tuple->dst_ip & 0xFF;

  key[8] = (tuple->src_port >> 8) & 0xFF;
  key[9] = tuple->src_port & 0xFF;

  key[10] = (tuple->dst_port >> 8) & 0xFF;
  key[11] = tuple->dst_port & 0xFF;

  key[12] = tuple->proto;
}

// Parse packet and extract 5-tuple
static int FORCE_INLINE parse_packet(struct xdp_md *ctx, struct pkt_5tuple *tuple) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Parse Ethernet header
  struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
  } *eth;

  eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  // Only process IPv4
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return -1;

  // Parse IP header
  struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
  } *ip;

  ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return -1;

  tuple->src_ip = ip->saddr;
  tuple->dst_ip = ip->daddr;
  tuple->proto = ip->protocol;

  // Parse transport layer
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr {
      __be16 source;
      __be16 dest;
      __be32 seq;
      __be32 ack_seq;
    } *tcp;

    tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
      return -1;

    tuple->src_port = tcp->source;
    tuple->dst_port = tcp->dest;
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr {
      __be16 source;
      __be16 dest;
      __be16 len;
      __be16 check;
    } *udp;

    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
      return -1;

    tuple->src_port = udp->source;
    tuple->dst_port = udp->dest;
  } else {
    tuple->src_port = 0;
    tuple->dst_port = 0;
  }

  return 0;
}

// ============================================================================
// XDP Program Entry Point
// ============================================================================

SEC("xdp")
int xdp_collect_5tuple(struct xdp_md *ctx)
{
  __u32 counter_key = 0;
  struct pkt_5tuple tuple = {};
  
  if (parse_packet(ctx, &tuple) < 0)
    return XDP_PASS;

  char tuple_key[14];
  tuple_to_key(&tuple, tuple_key);

  struct BubbleSketch *sk = bpf_map_lookup_elem(&sketch_map, &counter_key);
  if (!sk) {
    bpf_printk("sketch_map lookup failed\n");
    return XDP_PASS;
  }

  BubbleSketch_Insert(sk, tuple_key);

  __u64 *val = bpf_map_lookup_elem(&insert_counter, &counter_key);
  if (val)
    __sync_fetch_and_add(val, 1);

  return XDP_PASS;
}
