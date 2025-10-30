#ifndef __BUBBLE_SKETCH_COMMON_H
#define __BUBBLE_SKETCH_COMMON_H

#define MAX_ENTRY   5
#define MAX_BUCKETS 8192
#define MAX_ARRAYS  2
#define MAX_RET    1000
#define MAX_KICK_OUT 1
#define MAX_ROW 2
#define KEY_LEN 13

#define PRIME64_DEFAULT 1229

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* IPv4 */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#define FORCE_INLINE inline __attribute__((__always_inline__))

// CHANGE: Enhanced Entry structure with staleness tracking for space reclamation
struct Entry {
    char id[14];
    __u8 fingerprint;
    __u32 count;
    __u32 l0fp;
    __u32 last_update_pkt;  // NEW: Tracks when entry was last updated for staleness detection
};

struct Bucket {
    struct Entry entries[MAX_ENTRY];
    __s32 col_index;
};

// CHANGE: Enhanced BubbleSketch structure with load tracking and admission control
struct BubbleSketch {
    __s32 bucket_num;
    __s32 threshold1;
    struct Bucket buckets[MAX_ARRAYS][MAX_BUCKETS];
    __s32 lossy_func_id;
    __s32 K;
    __s32 f_max;
    __u32 total_entries;     // NEW: Tracks total active entries for load factor calculation
    __u32 global_pkt_count;  // NEW: Global packet counter for admission control and staleness
};

struct eviction {
  __u64 counter;
};

#endif /* __BUBBLE_SKETCH_COMMON_H */
