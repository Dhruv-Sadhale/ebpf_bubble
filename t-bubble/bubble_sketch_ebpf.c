// bubble_sketch_ebpf_tailcalls.c - Tail call version
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "bubble_sketch_common.h"
#include "fasthash.h"

// Tail call program indices
#define PROG_PARSE_AND_HASH     0
#define PROG_INSERT_HOT_BUCKET0 1
#define PROG_INSERT_HOT_BUCKET1 2
#define PROG_INSERT_COLD        3
#define PROG_KICKOUT_CHECK      4

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
} __attribute__((packed));

// Context passed between tail calls
struct insert_context {
  char tuple_key[14];
  __u64 hash_value[2];
  __u32 fp;
  __u32 keys[2];
  __u8 stage;  // Track which stage we're in
  __u8 bucket_idx;  // Which bucket we're processing
  __u8 entry_idx;   // Which entry we're processing
  __u8 pad;
};

// Maps
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

// Context map for passing data between tail calls
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct insert_context);
} context_map SEC(".maps");

// Tail call program map
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 5);
  __type(key, __u32);
  __type(value, __u32);
} tail_call_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// Entry Functions (same as before)
// ============================================================================
static void FORCE_INLINE Entry_init(struct Entry *e) {
#pragma unroll
  for (int i = 0; i < 14; i++) {
    e->id[i] = 0;
  }
  e->fingerprint = 0;
  e->count = 0;
  e->l0fp = 0;
}

static void FORCE_INLINE Entry_init_with(struct Entry *e, const char *id, __u32 fp, __u32 cnt) {
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

static void FORCE_INLINE Entry_Insert(struct Entry *e) {
  if (e->count < 0xFFFFFFFF)
    e->count++;
}

static void FORCE_INLINE Entry_Insert_with(struct Entry *e, __u32 fp, const char *id, __u32 cnt) {
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
}

static void FORCE_INLINE Entry_Lossy(struct Entry *e) {
  if (e->count > 0)
    e->count--;
}

// ============================================================================
// Bucket Functions (same as before)
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

static void FORCE_INLINE Bucket_Insert(struct Bucket *b, int index) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Insert(&b->entries[index]);
}

static void FORCE_INLINE Bucket_Insert_entry(struct Bucket *b, int index, const struct Entry *entry) {
  if (index >= 0 && index < MAX_ENTRY)
    b->entries[index] = *entry;
}

static void FORCE_INLINE Bucket_Insert_with(struct Bucket *b, int index, __u32 fp, const char *id) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Insert_with(&b->entries[index], fp, id, 1);
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

static void FORCE_INLINE Bucket_Lossy(struct Bucket *b, int index) {
  if (index >= 0 && index < MAX_ENTRY)
    Entry_Lossy(&b->entries[index]);
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

// ============================================================================
// Hash and Helper Functions
// ============================================================================
static __u64 FORCE_INLINE BubbleSketch_Hash_str(const char *str) {
  const __u64 seed2 = 0x9E3779B97F4A7C15ULL;
  return fasthash64(str, KEY_LEN, seed2);
}

static __s32 FORCE_INLINE calculate_threshold(__u32 f_max, __u32 K) {
  if ((__u64)((__u64)K)*2 == 0)
    return f_max;
  return (__s32)((__u64)((__u64)f_max*3) /(__u64)( (__u64)K*2 ));
}

static void FORCE_INLINE tuple_to_key(struct pkt_5tuple *tuple, char *key) {
#pragma unroll
  for (int i = 0; i < 14; i++) {
    key[i] = 0;
  }
  
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

static int FORCE_INLINE parse_packet(struct xdp_md *ctx, struct pkt_5tuple *tuple) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  __u16 h_proto;
  if (bpf_core_read(&h_proto, sizeof(h_proto), &eth->h_proto) < 0)
    return -1;

  if (bpf_ntohs(h_proto) != ETH_P_IP)
    return -1;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return -1;

  __u8 protocol;
  __be32 saddr, daddr;
  __u8 version_ihl;
  
  if (bpf_core_read(&protocol, sizeof(protocol), &ip->protocol) < 0)
    return -1;
  if (bpf_core_read(&saddr, sizeof(saddr), &ip->saddr) < 0)
    return -1;
  if (bpf_core_read(&daddr, sizeof(daddr), &ip->daddr) < 0)
    return -1;
  if (bpf_core_read(&version_ihl, sizeof(version_ihl), (__u8 *)ip) < 0)
    return -1;
  
  __u8 ihl_byte = version_ihl & 0x0F;

  tuple->src_ip = saddr;
  tuple->dst_ip = daddr;
  tuple->proto = protocol;

  void *l4_hdr = (void *)ip + (ihl_byte * 4);
  
  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = l4_hdr;
    if ((void *)(tcp + 1) > data_end)
      return -1;

    __be16 source, dest;
    if (bpf_core_read(&source, sizeof(source), &tcp->source) < 0)
      return -1;
    if (bpf_core_read(&dest, sizeof(dest), &tcp->dest) < 0)
      return -1;

    tuple->src_port = source;
    tuple->dst_port = dest;
  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4_hdr;
    if ((void *)(udp + 1) > data_end)
      return -1;

    __be16 source, dest;
    if (bpf_core_read(&source, sizeof(source), &udp->source) < 0)
      return -1;
    if (bpf_core_read(&dest, sizeof(dest), &udp->dest) < 0)
      return -1;

    tuple->src_port = source;
    tuple->dst_port = dest;
  } else {
    tuple->src_port = 0;
    tuple->dst_port = 0;
  }

  return 0;
}

// ============================================================================
// TAIL CALL PROGRAMS
// ============================================================================

// Stage 1: Check and insert into hot entry of bucket 0
SEC("xdp")
int xdp_insert_hot_bucket0(struct xdp_md *ctx)
{

  volatile unsigned char stack_filler1[600] = {0};
  __u32 key = 0;
  struct insert_context *ictx = bpf_map_lookup_elem(&context_map, &key);
  if (!ictx)
    return XDP_PASS;

  struct BubbleSketch *bs = bpf_map_lookup_elem(&sketch_map, &key);
  if (!bs)
    return XDP_PASS;

  if (ictx->keys[0] >= MAX_BUCKETS)
    return XDP_PASS;

  struct Bucket *bucket0 = &bs->buckets[0][ictx->keys[0]];

  // Check if hot entry matches
  if (Bucket_Equal(bucket0, 0, ictx->fp)) {
    Bucket_Insert(bucket0, 0);
    if (bucket0->entries[0].count > bs->f_max) {
      bs->f_max = bucket0->entries[0].count;
      __s32 new_threshold = calculate_threshold(bs->f_max, bs->K);
      if (new_threshold > bs->threshold1)
        bs->threshold1 = new_threshold;
    }
    return XDP_PASS;  // Done
  }

  // If hot entry is empty, insert
  if (Bucket_Empty(bucket0, 0)) {
    Bucket_Insert_with(bucket0, 0, ictx->fp, ictx->tuple_key);
    return XDP_PASS;  // Done
  }

  // Move to next stage - check bucket1 hot entry
  bpf_tail_call(ctx, &tail_call_map, PROG_INSERT_HOT_BUCKET1);
  return XDP_PASS;
}

// Stage 2: Check and insert into hot entry of bucket 1
SEC("xdp")
int xdp_insert_hot_bucket1(struct xdp_md *ctx)
{
  __u32 key = 0;
  struct insert_context *ictx = bpf_map_lookup_elem(&context_map, &key);
  if (!ictx)
    return XDP_PASS;

  struct BubbleSketch *bs = bpf_map_lookup_elem(&sketch_map, &key);
  if (!bs)
    return XDP_PASS;

  if (ictx->keys[1] >= MAX_BUCKETS)
    return XDP_PASS;

  struct Bucket *bucket1 = &bs->buckets[1][ictx->keys[1]];

  // Check if hot entry matches
  if (Bucket_Equal(bucket1, 0, ictx->fp)) {
    Bucket_Insert(bucket1, 0);
    if (bucket1->entries[0].count > bs->f_max) {
      bs->f_max = bucket1->entries[0].count;
      __s32 new_threshold = calculate_threshold(bs->f_max, bs->K);
      if (new_threshold > bs->threshold1)
        bs->threshold1 = new_threshold;
    }
    return XDP_PASS;  // Done
  }

  // If hot entry is empty, insert
  if (Bucket_Empty(bucket1, 0)) {
    Bucket_Insert_with(bucket1, 0, ictx->fp, ictx->tuple_key);
    return XDP_PASS;  // Done
  }

  // Move to cold entries stage
  ictx->entry_idx = 1;
  bpf_tail_call(ctx, &tail_call_map, PROG_INSERT_COLD);
  return XDP_PASS;
}

// Stage 3: Check and insert into cold entries
SEC("xdp")
int xdp_insert_cold(struct xdp_md *ctx)
{
  __u32 key = 0;
  struct insert_context *ictx = bpf_map_lookup_elem(&context_map, &key);
  if (!ictx)
    return XDP_PASS;

  struct BubbleSketch *bs = bpf_map_lookup_elem(&sketch_map, &key);
  if (!bs)
    return XDP_PASS;

  if (ictx->keys[0] >= MAX_BUCKETS || ictx->keys[1] >= MAX_BUCKETS)
    return XDP_PASS;

  struct Bucket *bucket0 = &bs->buckets[0][ictx->keys[0]];
  struct Bucket *bucket1 = &bs->buckets[1][ictx->keys[1]];

  // Process cold entries
#pragma unroll
  for (int i = 1; i < MAX_ENTRY; i++) {
    // Check bucket0
    if (Bucket_Equal(bucket0, i, ictx->fp)) {
      Bucket_Insert(bucket0, i);
      Bucket_BucketSort(bucket0, i);
      
      // Check if kickout needed
      if (bucket0->entries[1].count > bs->threshold1) {
          // Perform kickout inline for simplicity
          __u8 fp_kick = bucket0->entries[1].fingerprint;
          __u64 next_hash = ictx->hash_value[0] + fp_kick;
          __u32 next_idx = next_hash % MAX_BUCKETS;

         if(next_idx >= MAX_BUCKETS){
          return XDP_PASS;
         }
            struct Bucket *next_bucket = &bs->buckets[1][next_idx];
         if(bucket0->entries[1].count > next_bucket->entries[0].count){
            Bucket_down_stairs(next_bucket, 0);
            Bucket_Insert_entry(next_bucket, 0, &bucket0->entries[1]);

        Bucket_Remove(bucket0, 1);
          }
        
      }
      return XDP_PASS;
    }

    if (Bucket_Empty(bucket0, i)) {
      Bucket_Insert_with(bucket0, i, ictx->fp, ictx->tuple_key);
      return XDP_PASS;
    }

    // Check bucket1

    if (Bucket_Equal(bucket1, i, ictx->fp)) {
      Bucket_Insert(bucket1, i);
      Bucket_BucketSort(bucket1, i);
      
      // Check if kickout needed
      if (bucket1->entries[1].count > bs->threshold1) {
          // Perform kickout inline for simplicity
          __u8 fp_kick = bucket1->entries[1].fingerprint;
          __u64 next_hash = ictx->hash_value[1] - fp_kick;
          __u32 next_idx = next_hash % MAX_BUCKETS;

         if(next_idx >= MAX_BUCKETS){
          return XDP_PASS;
         }
            struct Bucket *next_bucket = &bs->buckets[0][next_idx];
         if(bucket1->entries[1].count > next_bucket->entries[0].count){
            Bucket_down_stairs(next_bucket, 0);
            Bucket_Insert_entry(next_bucket, 0, &bucket1->entries[1]);

        Bucket_Remove(bucket1, 1);
          }
        
      }
      return XDP_PASS;
    }

    if (Bucket_Empty(bucket1, i)) {
      Bucket_Insert_with(bucket1, i, ictx->fp, ictx->tuple_key);
      return XDP_PASS;
    }
  }

  // Lossy strategy - all positions full
  if (bucket0->entries[MAX_ENTRY - 1].count < bucket1->entries[MAX_ENTRY - 1].count) {
    Bucket_Lossy(bucket0, MAX_ENTRY - 1);
  } else {
    Bucket_Lossy(bucket1, MAX_ENTRY - 1);
  }

  if(bucket0->entries[MAX_ENTRY-1].count==0 || bucket1->entries[MAX_ENTRY-1].count==0){
    struct eviction *evict = bpf_map_lookup_elem(&eviction_map, &key);
    if (evict) {
      __sync_fetch_and_add(&evict->counter, 1);
    }
  }

  return XDP_PASS;
}

// ============================================================================
// MAIN XDP PROGRAM
// ============================================================================
SEC("xdp")
int xdp_collect_5tuple(struct xdp_md *ctx)
{

//  volatile unsigned char stack_filler1[200] = {0};
  __u32 key = 0;
  struct pkt_5tuple tuple = {};
  
  if (parse_packet(ctx, &tuple) < 0)
    return XDP_PASS;

  // Prepare context for tail calls
  struct insert_context *ictx = bpf_map_lookup_elem(&context_map, &key);
  if (!ictx)
    return XDP_PASS;

  tuple_to_key(&tuple, ictx->tuple_key);
  
  __u64 hash_key = BubbleSketch_Hash_str(ictx->tuple_key);
  ictx->fp = hash_key >> 32;
  ictx->hash_value[0] = hash_key;
  ictx->hash_value[1] = hash_key + (ictx->fp >> 24);
  ictx->keys[0] = ictx->hash_value[0] % MAX_BUCKETS;
  ictx->keys[1] = ictx->hash_value[1] % MAX_BUCKETS;
  ictx->stage = 0;

  // Update insert counter
  __u64 *val = bpf_map_lookup_elem(&insert_counter, &key);
  if (val)
    __sync_fetch_and_add(val, 1);

  // Start tail call chain
  bpf_tail_call(ctx, &tail_call_map, PROG_INSERT_HOT_BUCKET0);
  
  // Fallback if tail call fails
  return XDP_PASS;
}
