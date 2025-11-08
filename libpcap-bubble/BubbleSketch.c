#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <stdbool.h>

// Configuration constants
#define BUCKETSIZE 128
#define MAX_BUCKETS 8192//todo: adjust this value
#define MAX_ARRAYS 2
#define MAX_RET 20000 //todo: adjust this value for max results stored
#define MAX_KICK_OUT 1
#define MAX_ENTRY 5  // B = 5 entries per bucket
#define MAX_ROW 2


// CONVERTED: BOBHASH64 structure and declarations from BOBHASH64.h
#define MAX_PRIME64 1229
#define MAX_BIG_PRIME64 50

typedef unsigned int uint;
typedef unsigned long long int uint64;

//Entry structure
typedef struct {
    /*
    *this was a key change made from 5->14
    *why 14 bytes? since the string passed from main.c is 13 (KEY_LEN)
    *and 1 byte for '\0'
    */
    char ID[14]; 
    uint8_t fingerprint;  
    uint32_t count;    
    uint32_t l0fp; 
} Entry;

//Bucket structure
typedef struct {
    Entry entries[MAX_ENTRY];
    int col_index;
} Bucket;


//Hash structure
typedef struct {
    uint prime64Num;
} BOBHash64;

// Bubble Sketch structure
typedef struct {
    int _bucket_num;
    int _threshold1;
    Bucket _buckets[MAX_ARRAYS][MAX_BUCKETS];
    BOBHash64 *_bobhash;
    void (*_lossy_func)(uint32_t *);
    Entry _ret[MAX_RET];
    int _K;
    int _f_max;
} BubbleSketch;

//Entry methods
void Entry_init(Entry *e);
void Entry_init_with(Entry *e, const char *id, uint32_t fp, uint32_t cnt);
uint32_t Entry_Empty(Entry *e);
bool Entry_Equalfp(Entry *e, uint8_t fp);
bool Entry_Equall0fp(Entry *e, uint32_t fp);
void Entry_Insert(Entry *e);
void Entry_Insert_with(Entry *e, uint32_t fp, const char *id, uint32_t cnt);
void Entry_Lossy(Entry *e, void (*lossy_func)(uint32_t *));
int Entry_compare(const void *a, const void *b);


// Bucket methods
void Bucket_init(Bucket *b);
void Bucket_Clear(Bucket *b);
bool Bucket_Empty(Bucket *b, int index);
bool Bucket_Full(Bucket *b, int index);
void Bucket_Insert(Bucket *b, int index);
void Bucket_Insert_entry(Bucket *b, int index, const Entry *entry);
void Bucket_Insert_with(Bucket *b, int index, uint32_t fp, const char *id);
void Bucket_Remove(Bucket *b, int index);
void Bucket_Lossy(Bucket *b, int index, void (*lossy_func)(uint32_t *));
void Bucket_BucketSort(Bucket *b, int index);
bool Bucket_Equal(Bucket *b, int index, uint32_t fp);
void Bucket_down_stairs(Bucket *b, int index);

//Hash methods
BOBHash64* BOBHash64_create(uint prime64Num);
void BOBHash64_destroy(BOBHash64 *hash);
void BOBHash64_initialize(BOBHash64 *hash, uint prime64Num);
uint64 BOBHash64_run(BOBHash64 *hash, const char *str, uint len);

// Lossy strategy function (you'll need to implement this)
void MinusOneStrategy(uint32_t *count);

//BubbleSketch methods
void BubbleSketch_init(BubbleSketch *bs, int threshold1, int K, int MEM);
void BubbleSketch_destroy(BubbleSketch *bs);
void BubbleSketch_clear(BubbleSketch *bs);
void BubbleSketch_Insert(BubbleSketch *bs, const char *str);
void BubbleSketch_Query(BubbleSketch *bs, int k, char *out_str, int *out_val);
void BubbleSketch_work(BubbleSketch *bs);
const char* BubbleSketch_get_name(BubbleSketch *bs);
void BubbleSketch_PrintMaxFrequency(BubbleSketch *bs);
uint64_t BubbleSketch_Hash_str(BubbleSketch *bs, const char *str);
uint64_t BubbleSketch_Hash_fp(BubbleSketch *bs, uint8_t fp);
bool BubbleSketch_kickout(BubbleSketch *bs, int kick_num,
                          uint64_t *hash_value, Bucket *cur_bucket,
                          int entry_index, int array_index);

// Utility functions
int max_int(int a, int b);
void swap_entries(Entry *a, Entry *b);

// ============================================================================
// IMPLEMENTATIONS
// ============================================================================

void Entry_init(Entry *e) {
    e->ID[0] = '\0';
    e->fingerprint = 0;
    e->count = 0;
    e->l0fp = 0;
    return;
}

void Entry_init_with(Entry *e, const char *id, uint32_t fp, uint32_t cnt) {
    strncpy(e->ID, id, sizeof(e->ID)-1);
    e->ID[sizeof(e->ID)-1] = '\0'; 
    e->fingerprint = fp;
    e->count = cnt;
    e->l0fp = fp >> 24;
    return;
}

uint32_t Entry_Empty(Entry *e) {
    return (e->count == 0);
}

bool Entry_Equalfp(Entry *e, uint8_t fp) {
    return fp == e->fingerprint;
}

bool Entry_Equall0fp(Entry *e, uint32_t fp) {
    return fp == e->l0fp;
}

void Entry_Insert(Entry *e) {
    ++(e->count);
    return;
}

void Entry_Insert_with(Entry *e, uint32_t fp, const char *id, uint32_t cnt) {
    e->l0fp = fp;
    e->fingerprint = fp >> 24;
    strncpy(e->ID, id, sizeof(e->ID)-1);
    e->ID[sizeof(e->ID)-1] = '\0';  
    e->count = cnt;
    return;
}

void Entry_Lossy(Entry *e, void (*lossy_func)(uint32_t *)) {
    if (e && lossy_func) {
        lossy_func(&e->count);
    }
}


int Entry_compare(const void *a, const void *b) {
    const Entry *ea = (const Entry*)a;
    const Entry *eb = (const Entry*)b;
    return ea->count > eb->count ? -1 : (ea->count < eb->count ? 1 : 0);
}

void Bucket_init(Bucket *b) {
    if (b) {
        memset(b->entries, 0, sizeof(b->entries));
        b->col_index = 0;
    }
}

void Bucket_Clear(Bucket *b) {
    if (!b) return;
    memset(b->entries, 0, sizeof(Entry) * MAX_ENTRY);
    b->col_index = 0;
}

bool Bucket_Empty(Bucket *b, int index) {
    return Entry_Empty(&(b->entries[index]));
}

bool Bucket_Full(Bucket *b, int index) {
    switch (index) {
        case 0:
            return (b->entries[index]).count == 0xffffffff;
        case 1:
            return (b->entries[index]).count >= 0xffff;
        case 2:
            return (b->entries[index]).count >= 0xff;
        case 3:
        case 4:
            return (b->entries[index]).count >= 0xf;
    }
    return false;
}

void Bucket_Insert(Bucket *b, int index) {
    Entry_Insert(&(b->entries[index]));
    return;
}

void Bucket_Insert_entry(Bucket *b, int index, const Entry *entry) {
    b->entries[index] = *entry;
    return;
}

void Bucket_Insert_with(Bucket *b, int index, uint32_t fp, const char *id) {
    Entry_Insert_with(&(b->entries[index]), fp, id, 1);
    return;
}

void Bucket_Remove(Bucket *b, int index) {
    while (index + 1 < MAX_ENTRY) {
        b->entries[index] = b->entries[index + 1];
        index++;
    }
    return;
}

void Bucket_Lossy(Bucket *b, int index, void (*lossy_func)(uint32_t *)) {
    if (b && lossy_func && index >= 0 && index < MAX_ENTRY) {
      Entry_Lossy(&b->entries[index], lossy_func);
    }
    return;
}

void Bucket_BucketSort(Bucket *b, int index) {
    while (index > 0 && b->entries[index].count > b->entries[index-1].count) {
        Entry temp = b->entries[index];
        b->entries[index] = b->entries[index - 1];
        b->entries[index - 1] = temp;
        --index;
    }
}

bool Bucket_Equal(Bucket *b, int index, uint32_t fp) {
    if (index == 0) {
        return Entry_Equall0fp(&b->entries[index], fp);
    } else {
        return Entry_Equalfp(&b->entries[index], fp >> 24);
    }
}


void Bucket_down_stairs(Bucket *b, int index) {
    int cur_index = MAX_ENTRY - 1;
    while (cur_index > index) {
        b->entries[cur_index] = b->entries[cur_index-1];
        --cur_index;
    }
}

void BubbleSketch_init(BubbleSketch *bs, int threshold1, int K, int MEM) {
    bs->_bucket_num = 0;
    for (; bs->_bucket_num * BUCKETSIZE * MAX_ROW <= MEM * 1000 * 8; ++bs->_bucket_num) {
        if (bs->_bucket_num >= MAX_BUCKETS) break;  
    }
    --(bs->_bucket_num);
    
    for (int i = 0; i < MAX_ARRAYS; i++) {
        for (int j = 0; j < bs->_bucket_num; j++) {
            Bucket_init(&bs->_buckets[i][j]);
        }
    }
    bs->_threshold1 = threshold1;
    bs->_K = K;
    bs->_f_max = 0;
    bs->_bobhash = BOBHash64_create(1005);
    bs->_lossy_func = MinusOneStrategy;
}

void BubbleSketch_destroy(BubbleSketch *bs) {
    if (bs && bs->_bobhash) {
        BOBHash64_destroy(bs->_bobhash);
        bs->_bobhash = NULL;
    }
}

void BubbleSketch_clear(BubbleSketch *bs) {
    for (int i = 0; i < MAX_ARRAYS; i++) {
        for (int j = 0; j < bs->_bucket_num; j++) {
            Bucket_Clear(&bs->_buckets[i][j]);
        }
    }
}

void BubbleSketch_Insert(BubbleSketch *bs, const char *str) {
    uint64_t hash_key = BubbleSketch_Hash_str(bs, str);
    uint32_t fp = hash_key >> 32;

    uint64_t hash_value[2] = {hash_key, hash_key + (fp >> 24)};

    uint64_t keys[2] = {hash_value[0] % bs->_bucket_num,
                        hash_value[1] % bs->_bucket_num};

    Bucket *bucket0 = &bs->_buckets[0][keys[0]];
    Bucket *bucket1 = &bs->_buckets[1][keys[1]];

    if (Bucket_Equal(bucket0, 0, fp)) {
        Bucket_Insert(bucket0, 0);
        if (bucket0->entries[0].count > bs->_f_max) {
            bs->_f_max = bucket0->entries[0].count;
            bs->_threshold1 = max_int(bs->_threshold1, (int)(bs->_f_max * 1.5 / bs->_K));
        }
        return;
    }

    // If hot entry slot is empty in bucket0
    if (Bucket_Empty(bucket0, 0)) {
        Bucket_Insert_with(bucket0, 0, fp, str);
        return;
    }

    // Check bucket1 hot entry
    if (Bucket_Equal(bucket1, 0, fp)) {
        Bucket_Insert(bucket1, 0);
        if (bucket1->entries[0].count > bs->_f_max) {
            bs->_f_max = bucket1->entries[0].count; 
            bs->_threshold1 = max_int(bs->_threshold1, (int)(bs->_f_max * 1.5 / bs->_K));
        }
        return;
    }

    if (Bucket_Empty(bucket1, 0)) {
        Bucket_Insert_with(bucket1, 0, fp, str);
        return;
    }

    // Check cold entries
    for (int i = 1; i < MAX_ENTRY; i++) {
        // Check bucket0
        if (Bucket_Equal(bucket0, i, fp)) {
            Bucket_Insert(bucket0, i);
            Bucket_BucketSort(bucket0, i);
            if (bucket0->entries[1].count > bs->_threshold1) {
                if (BubbleSketch_kickout(bs, MAX_KICK_OUT, &hash_value[0], bucket0, 1, 0)) {
                    Bucket_Remove(bucket0, 1);
                }
            }
            return;
        }
        
        if (Bucket_Empty(bucket0, i)) {
            Bucket_Insert_with(bucket0, i, fp, str);
            return;
        }

        // Check bucket1
        if (Bucket_Equal(bucket1, i, fp)) {
            Bucket_Insert(bucket1, i);
            Bucket_BucketSort(bucket1, i);
            if (bucket1->entries[1].count > bs->_threshold1) {
                if (BubbleSketch_kickout(bs, MAX_KICK_OUT, &hash_value[1], bucket1, 1, 1)) {
                    Bucket_Remove(bucket1, 1);
                }
            }
            return;
        }
        
        if (Bucket_Empty(bucket1, i)) {
            Bucket_Insert_with(bucket1, i, fp, str);
            return;
        }
    }

    // Lossy strategy - all positions are full
    if (bucket0->entries[MAX_ENTRY - 1].count < 
        bucket1->entries[MAX_ENTRY - 1].count) {
        Bucket_Lossy(bucket0, MAX_ENTRY - 1, bs->_lossy_func);
    } else {
        Bucket_Lossy(bucket1, MAX_ENTRY - 1, bs->_lossy_func);
    }
}

void BubbleSketch_Query(BubbleSketch *bs, int k, char *out_str, int *out_val) {
    if (k < MAX_RET && bs->_ret[k].count > 0) {
        strcpy(out_str, bs->_ret[k].ID);
        *out_val = bs->_ret[k].count;
    } else {
        out_str[0] = '\0';
        *out_val = 0;
    }
}

void BubbleSketch_work(BubbleSketch *bs) {
    int ret_index=0;
    for (int i = 0; i < MAX_ROW ; i++) {
        printf("bucket work number: %d\n",bs->_bucket_num); 
        for (int j = 0; j < bs->_bucket_num; j++) {
            bs->_ret[i*(bs->_bucket_num)+j] = bs->_buckets[i][j].entries[0];
            ret_index++;
        }
    }
    qsort(bs->_ret, ret_index, sizeof(Entry), Entry_compare);
}

// CONVERTED: BubbleSketch_get_name function
const char* BubbleSketch_get_name(BubbleSketch *bs) {
    return "BubbleSketch";
}

// CONVERTED: Hash functions using proper BOBHASH64 API
uint64_t BubbleSketch_Hash_str(BubbleSketch *bs, const char *str) {
    return BOBHash64_run(bs->_bobhash, str, strlen(str));
}

uint64_t BubbleSketch_Hash_fp(BubbleSketch *bs, uint8_t fp) {
    return BOBHash64_run(bs->_bobhash, (char*)&fp, 1);
}

// CONVERTED: BubbleSketch_kickout function
bool BubbleSketch_kickout(BubbleSketch *bs, int kick_num,
                          uint64_t *hash_value, Bucket *cur_bucket,
                          int entry_index, int array_index) {
    if (kick_num == 0) {
        return false;
    }

    uint8_t fp = cur_bucket->entries[entry_index].fingerprint;
    
    // TEST1 version
    uint64_t next_hash_value = *hash_value;
    if (array_index == 0) {
        next_hash_value += fp;
    } else {
        next_hash_value -= fp;
    }

    Bucket *next_bucket = &bs->_buckets[1 - array_index][next_hash_value % bs->_bucket_num];

    // Check if current entry can be moved to next bucket's hot slot
    if (cur_bucket->entries[entry_index].count > 
        next_bucket->entries[0].count) {
        Bucket_down_stairs(next_bucket, 0);
        Entry entry_to_move = cur_bucket->entries[entry_index];
        Bucket_Insert_entry(next_bucket, 0, &entry_to_move);
        return true;
    }

    // Recursive kickout (will return false since MAX_KICK_OUT is 1)
    if (BubbleSketch_kickout(bs, kick_num - 1, &next_hash_value, next_bucket, 0, 1 - array_index)) {
        Bucket_down_stairs(next_bucket, 0);
        Entry entry_to_move = cur_bucket->entries[entry_index];
        Bucket_Insert_entry(next_bucket, 0, &entry_to_move);
        return true;
    }
    
    return false;
}

// CONVERTED: BubbleSketch_PrintMaxFrequency function
void BubbleSketch_PrintMaxFrequency(BubbleSketch *bs) {
    printf("Max Frequency: %d\n", bs->_f_max);
}

// CONVERTED: Utility functions
int max_int(int a, int b) {
    return (a > b) ? a : b;
}

void swap_entries(Entry *a, Entry *b) {
    Entry temp = *a;
    *a = *b;
    *b = temp;
}

// CONVERTED: BOBHASH64 implementation from BOBHASH64.h
// Prime arrays from original C++ code
uint64 big_prime64[MAX_BIG_PRIME64] = {
    20177, 20183, 20201, 20219, 20231, 20233, 20249, 20261, 20269, 20287,
    20297, 20323, 20327, 20333, 20341, 20347, 20353, 20357, 20359, 20369,
    20389, 20393, 20399, 20407, 20411, 20431, 20441, 20443, 20477, 20479,
    20483, 20507, 20509, 20521, 20533, 20543, 20549, 20551, 20563, 20593,
    20599, 20611, 20627, 20639, 20641, 20663, 20681, 20693, 20707, 20717
};

uint64 prime64[MAX_PRIME64] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997,
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061,
    1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
    1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
    1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361,
    1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
    1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
    1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627,
    1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721,
    1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
    1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
    1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973,
    1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029,
    2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
    2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203,
    2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273,
    2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
    2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
    2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503,
    2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593,
    2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677,
    2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
    2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
    2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887,
    2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969,
    2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
    3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
    3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251,
    3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323,
    3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
    3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
    3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557,
    3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631,
    3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
    3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
    3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881,
    3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947,
    3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
    4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129,
    4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219,
    4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283,
    4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
    4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481,
    4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561,
    4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649,
    4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
    4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813,
    4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931,
    4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993,
    4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077,
    5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167,
    5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261,
    5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351,
    5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437,
    5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507,
    5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591,
    5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683,
    5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779,
    5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849,
    5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923,
    5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043,
    6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121,
    6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211,
    6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287,
    6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359,
    6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451,
    6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563,
    6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659,
    6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733,
    6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827,
    6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907,
    6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983,
    6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069,
    7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187,
    7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253,
    7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369,
    7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487,
    7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549,
    7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621,
    7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703,
    7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817,
    7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901,
    7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009,
    8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093,
    8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191,
    8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273,
    8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369,
    8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461,
    8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573,
    8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663,
    8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731,
    8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819,
    8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893,
    8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001,
    9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091,
    9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181,
    9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277,
    9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349,
    9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433,
    9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511,
    9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623,
    9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719,
    9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791,
    9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871,
    9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967,
    9973
};

// BOB Hash mixing function - converted from C++ macro
#define mix64(a,b,c) \
{  \
  a -= b; a -= c; a ^= (c>>43); \
  b -= c; b -= a; b ^= (a<<9); \
  c -= a; c -= b; c ^= (b>>8); \
  a -= b; a -= c; a ^= (c>>38); \
  b -= c; b -= a; b ^= (a<<23); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>35); \
  b -= c; b -= a; b ^= (a<<49); \
  c -= a; c -= b; c ^= (b>>11); \
  a -= b; a -= c; a ^= (c>>12); \
  b -= c; b -= a; b ^= (a<<18); \
  c -= a; c -= b; c ^= (b>>22); \
}

BOBHash64* BOBHash64_create(uint prime64Num) {
    BOBHash64 *hash = (BOBHash64*)malloc(sizeof(BOBHash64));
    if (hash) {
        hash->prime64Num = prime64Num;
    }
    return hash;
}

void BOBHash64_destroy(BOBHash64 *hash) {
    if (hash) {
        free(hash);
    }
}

void BOBHash64_initialize(BOBHash64 *hash, uint prime64Num) {
    if (hash) {
        hash->prime64Num = prime64Num;
    }
}

// CONVERTED: Main BOBHash64 run function from C++ implementation
uint64 BOBHash64_run(BOBHash64 *hash, const char *str, uint len) {
    uint64 a, b, c;
    
    /* Set up the internal state */
    a = b = 0x9e3779b97f4a7c13LL;  /* the golden ratio; an arbitrary value */
    c = prime64[hash->prime64Num]; /* the previous hash value */

    /*---------------------------------------- handle most of the key */
    while (len >= 24) {
        a += (str[0]+((uint64)str[1]<< 8)+((uint64)str[2]<<16)+((uint64)str[3]<<24)
         +((uint64)str[4]<<32)+((uint64)str[5]<<40)+((uint64)str[6]<<48)+((uint64)str[7]<<56));
        b += (str[8]+((uint64)str[9]<< 8)+((uint64)str[10]<<16)+((uint64)str[11]<<24)
         +((uint64)str[12]<<32)+((uint64)str[13]<<40)+((uint64)str[14]<<48)+((uint64)str[15]<<56));
        c += (str[16]+((uint64)str[17]<< 8)+((uint64)str[18]<<16)+((uint64)str[19]<<24)
         +((uint64)str[20]<<32)+((uint64)str[21]<<40)+((uint64)str[22]<<48)+((uint64)str[23]<<56));
        mix64(a,b,c);
        str += 24;
        len -= 24;
    }

    /*------------------------------------- handle the last 23 bytes */
    c += len;
    switch(len) {             /* all the case statements fall through */
        case 23: c+=((uint64)str[22]<<56);
        case 22: c+=((uint64)str[21]<<48);
        case 21: c+=((uint64)str[20]<<40);
        case 20: c+=((uint64)str[19]<<32);
        case 19: c+=((uint64)str[18]<<24);
        case 18: c+=((uint64)str[17]<<16);
        case 17: c+=((uint64)str[16]<<8);
          /* the first byte of c is reserved for the length */
        case 16: b+=((uint64)str[15]<<56);
        case 15: b+=((uint64)str[14]<<48);
        case 14: b+=((uint64)str[13]<<40);
        case 13: b+=((uint64)str[12]<<32);
        case 12: b+=((uint64)str[11]<<24);
        case 11: b+=((uint64)str[10]<<16);
        case 10: b+=((uint64)str[ 9]<<8);
        case  9: b+=((uint64)str[ 8]);
        case  8: a+=((uint64)str[ 7]<<56);
        case  7: a+=((uint64)str[ 6]<<48);
        case  6: a+=((uint64)str[ 5]<<40);
        case  5: a+=((uint64)str[ 4]<<32);
        case  4: a+=((uint64)str[ 3]<<24);
        case  3: a+=((uint64)str[ 2]<<16);
        case  2: a+=((uint64)str[ 1]<<8);
        case  1: a+=((uint64)str[ 0]);
          /* case 0: nothing left to add */
    }
    mix64(a,b,c);
    /*-------------------------------------------- report the result */
    return c;
}

// Lossy strategy implementation
void MinusOneStrategy(uint32_t *count) {
    if (*count > 0) {
        (*count)--;
    }
}
