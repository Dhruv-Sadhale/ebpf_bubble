#ifndef __BUBBLE_SKETCH_COMMON_H
#define __BUBBLE_SKETCH_COMMON_H

#define MAX_ENTRY   5
#define MAX_BUCKETS 2048
#define MAX_ARRAYS  2
#define MAX_RET     1000
#define MAX_KICK_OUT 1
#define MAX_ROW 2
#define KEY_LEN 13

#define PRIME64_DEFAULT 1229

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
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
struct Entry {
    char id[14];
    __u8 fingerprint;
    __u32 count;
    __u32 l0fp;
};

struct Bucket {
    struct Entry entries[MAX_ENTRY];
    __s32 col_index;
};

struct BubbleSketch {
    __s32 bucket_num;
    __s32 threshold1;
    struct Bucket buckets[MAX_ARRAYS][MAX_BUCKETS];
    __s32 lossy_func_id;
    __s32 K;
    __s32 f_max;
};
struct eviction{
  __u64 counter;
};

#endif /* __BUBBLE_SKETCH_COMMON_H */

