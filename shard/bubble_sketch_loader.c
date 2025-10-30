#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include "bubble_sketch_common.h"
#include "bubble_sketch_ebpf.skel.h"

static volatile bool exiting = false;
static struct bubble_sketch_ebpf *skel;
static int sketch_shard_fds[SHARD_COUNT];
static int counter_fd;
static int eviction_map_fd;
struct pkt_5tuple {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
};
static void key_to_tuple(const char *key, struct pkt_5tuple *tuple) {
  // Extract src_ip (bytes 0-3)
  tuple->src_ip = (((__u32)(unsigned char)key[0]) << 24) |
    (((__u32)(unsigned char)key[1]) << 16) |
    (((__u32)(unsigned char)key[2]) << 8) |
    ((__u32)(unsigned char)key[3]);

  // Extract dst_ip (bytes 4-7)
  tuple->dst_ip = (((__u32)(unsigned char)key[4]) << 24) |
    (((__u32)(unsigned char)key[5]) << 16) |
    (((__u32)(unsigned char)key[6]) << 8) |
    ((__u32)(unsigned char)key[7]);

  // Extract src_port (bytes 8-9)
  tuple->src_port = (((__u16)(unsigned char)key[8]) << 8) |
    ((__u16)(unsigned char)key[9]);

  // Extract dst_port (bytes 10-11)
  tuple->dst_port = (((__u16)(unsigned char)key[10]) << 8) |
    ((__u16)(unsigned char)key[11]);

  // Extract protocol (byte 12)
  tuple->proto = (unsigned char)key[12];
}
static const char* proto_to_string(__u8 proto) {
  switch(proto) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    default: return "OTHER";
  }
}
static int is_valid_entry(const struct Entry *entry) {
  if (entry->count == 0) {
    return 0;
  }

  // Check if id has any non-zero bytes (indicating it was actually set)
  for (int i = 0; i < 13; i++) {
    if (entry->id[i] != 0) {
      return 1;
    }
  }
  return 0;
}
/* Signal handler */
static void handle_signal(int sig)
{
  exiting = true;
}

/* Compare function for qsort */
static int cmp_entries(const void *a, const void *b) {
  const struct Entry *ea = a;
  const struct Entry *eb = b;
  return (int)eb->count - (int)ea->count; // descending order
}
/* Radix sort for counting sort - works great for packet counts */
static void counting_sort_by_digit(struct Entry *arr, int n, int exp) {
  struct Entry output[n];
  int count[256] = {0};

  // Count occurrences (treat as unsigned for descending)
  for (int i = 0; i < n; i++) {
    int digit = (arr[i].count / exp) % 256;
    count[255 - digit]++;  // Reverse for descending order
  }

  // Cumulative count
  for (int i = 1; i < 256; i++)
    count[i] += count[i - 1];

  // Build output array (go backwards for stability)
  for (int i = n - 1; i >= 0; i--) {
    int digit = (arr[i].count / exp) % 256;
    output[count[255 - digit] - 1] = arr[i];
    count[255 - digit]--;
  }

  // Copy back
  memcpy(arr, output, n * sizeof(struct Entry));
}

static void radix_sort(struct Entry *arr, int n, __s32 f_max) {
  __u32 max = (__u32)f_max;
  // Sort by each byte (4 bytes for __u32)
  for (__u32 exp = 1; max / exp > 0; exp *= 256)
    counting_sort_by_digit(arr, n, exp);
}
/* Stable partition function - separates elements based on predicate */
static int stable_partition(struct Entry *arr, int start, int end, __u32 div) {
  int n = end - start;
  if (n <= 0) return start;

  struct Entry *temp = malloc(n * sizeof(struct Entry));
  int sorted_idx = 0;
  int active_idx = 0;

  // Separate into two groups
  struct Entry *active_temp = malloc(n * sizeof(struct Entry));

  for (int i = start; i < end; i++) {
    if ((arr[i].count / div) == 0) {
      // Already sorted (smaller values)
      temp[sorted_idx++] = arr[i];
    } else {
      // Still needs sorting (larger values)
      active_temp[active_idx++] = arr[i];
    }
  }

  // Copy back: sorted elements first, then active elements
  memcpy(&arr[start], temp, sorted_idx * sizeof(struct Entry));
  memcpy(&arr[start + sorted_idx], active_temp, active_idx * sizeof(struct Entry));

  free(temp);
  free(active_temp);

  return start + sorted_idx;  // Return where active region starts
}

/* Counting sort by digit for DESCENDING order */
static void counting_sort_descending(struct Entry *arr, int start, int end,
                                     __u32 div, int base) {
  int n = end - start;
  if (n <= 1) return;

  int *count = calloc(base, sizeof(int));
  struct Entry *output = malloc(n * sizeof(struct Entry));

  // Count occurrences
  for (int i = start; i < end; i++) {
    int digit = ((arr[i].count / div) % base);
    count[digit]++;
  }

  // Cumulative count for DESCENDING order (reverse)
  for (int i = base - 2; i >= 0; i--) {
    count[i] += count[i + 1];
  }

  // Build output array (backwards for stability)
  for (int i = end - 1; i >= start; i--) {
    int digit = ((arr[i].count / div) % base);
    output[count[digit] - 1] = arr[i];
    count[digit]--;
  }

  // Copy back
  memcpy(&arr[start], output, n * sizeof(struct Entry));

  free(count);
  free(output);
}

/* SLPR Sort - optimized for descending order */
static void slpr_sort(struct Entry *arr, int n, __s32 f_max) {
  if (n <= 1) return;

  // Find maximum value
  __u32 max_val = (__u32)f_max;

  if (max_val == 0) return;

  // Calculate number of rounds using base-n
  int R = 1;
  __u32 temp = max_val;
  while (temp >= n) {
    temp /= n;
    R++;
  }

  if (R <= 1) {
    counting_sort_descending(arr, 0, n, 1, n);
    return;
  }

  // Round 1: Sort entire array by least significant "digit" (base n)
  counting_sort_descending(arr, 0, n, 1, n);

  int first_active = 0;

  // Rounds 2 to R-1: Partition and sort active region only
  for (int r = 2; r < R; r++) {
    // Calculate divisor: n^(r-1)
    __u32 div = 1;
    for (int p = 0; p < r - 1; p++) {
      div *= n;
    }

    // Partition: elements where (count/div) == 0 are already in final position
    int partition_point = stable_partition(arr, first_active, n, div);

    // Sort only the active region (elements still needing sorting)
    if (partition_point < n) {
      counting_sort_descending(arr, partition_point, n, div, n);
    }

    first_active = partition_point;

    // Early exit if everything is sorted
    if (first_active >= n) {
      return;
    }
  }

  // Final round R: Sort remaining active region
  if (first_active < n) {
    __u32 div = 1;
    for (int p = 0; p < R - 1; p++) {
      div *= n;
    }
    counting_sort_descending(arr, first_active, n, div, n);
  }
}
/* Called at exit to fetch sketch and display Top-K */
static void dump_results(void)
{
  int TOTAL= SHARD_COUNT * 2 * MAX_BUCKETS;
  struct Entry sorted[TOTAL];
  int entry_count = 0;
  __u32 key = 0;
  int f_max=0; 
  // Collect entries from all shards
  for (int shard = 0; shard < SHARD_COUNT; shard++) {
    struct BubbleSketch sk;
    if(sk.f_max > f_max){
      f_max = sk.f_max;
    }
    if (bpf_map_lookup_elem(sketch_shard_fds[shard], &key, &sk) != 0) {
      fprintf(stderr, "Failed to read sketch shard %d\n", shard);
      continue;
    }
    
    if (shard == 0) {
      printf("Shard 0: bucket_num=%d, threshold1=%d, K=%d, f_max=%d\n",
             sk.bucket_num, sk.threshold1, sk.K, sk.f_max);
    }
    
    // Extract entries from this shard
    for (int i = 0; i < MAX_ARRAYS; i++) {
      for (int j = 0; j < MAX_BUCKETS; j++) {
        if (is_valid_entry(&sk.buckets[i][j].entries[0])) {
          sorted[entry_count++] = sk.buckets[i][j].entries[0];
        }
      }
    }
  }
  
  printf("\nCollected %d total entries from %d shards\n", entry_count, SHARD_COUNT);
  
    struct Entry sorted_qsort[TOTAL];
  struct Entry sorted_radix[TOTAL];
  struct Entry sorted_slpr[TOTAL];
  memcpy(sorted_qsort, sorted, sizeof(sorted));
  memcpy(sorted_radix, sorted, sizeof(sorted));
  memcpy(sorted_slpr, sorted, sizeof(sorted));

  // Timing for qsort
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  qsort(sorted_qsort,TOTAL , sizeof(struct Entry), cmp_entries);
  clock_gettime(CLOCK_MONOTONIC, &end);
  double time_qsort = (end.tv_sec - start.tv_sec) * 1e6 +
                      (end.tv_nsec - start.tv_nsec) / 1000.0;

  // Timing for standard radix sort (your current implementation)
  clock_gettime(CLOCK_MONOTONIC, &start);
  radix_sort(sorted_radix, TOTAL, f_max);
  clock_gettime(CLOCK_MONOTONIC, &end);
  double time_radix = (end.tv_sec - start.tv_sec) * 1e6 +
                      (end.tv_nsec - start.tv_nsec) / 1000.0;

  // Timing for SLPR (optimized from paper)
  clock_gettime(CLOCK_MONOTONIC, &start);
  slpr_sort(sorted_slpr, TOTAL, f_max);
  clock_gettime(CLOCK_MONOTONIC, &end);
  double time_slpr = (end.tv_sec - start.tv_sec) * 1e6 +
                     (end.tv_nsec - start.tv_nsec) / 1000.0;

  printf("\n=== SORTING PERFORMANCE ===\n");
  printf("qsort time:          %.2f microseconds\n", time_qsort);
  printf("Standard radix time: %.2f microseconds (%.2fx vs qsort)\n",
         time_radix, time_qsort / time_radix);
  printf("SLPR time:           %.2f microseconds (%.2fx vs qsort, %.2fx vs radix)\n",
         time_slpr, time_qsort / time_slpr, time_radix / time_slpr);
  printf("===========================\n\n");

for (int i=0;i<MAX_RET;i++){
  printf("qsort: %u radix: %u slpr: %u\n", sorted_qsort[i].count, sorted_radix[i].count, sorted_slpr[i].count);
}
  printf("%-4s %-18s %-6s %-18s %-6s %-8s %-6s %-8s %-10s\n",
      "No", "Src IP", "S.Port", "Dst IP", "D.Port", "Proto", "Count", "Fingerprint", "L0FP");

  for (int j = 0; j < MAX_RET; j++) {
    struct Entry *entry = &sorted_radix[j];
    struct pkt_5tuple tuple;

    // Convert binary id back to 5-tuple
    key_to_tuple(entry->id, &tuple);

    // Convert IPs to readable format
    struct in_addr src_addr = { .s_addr = tuple.src_ip };
    struct in_addr dst_addr = { .s_addr = tuple.dst_ip };
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

    printf("%-4d %-18s %-6u %-18s %-6u %-8s %-6u %-8u %-10u\n",
        j + 1,
        src_ip_str,
        ntohs(tuple.src_port),
        dst_ip_str, 
        ntohs(tuple.dst_port),
        proto_to_string(tuple.proto),
        entry->count,
        entry->fingerprint,
        entry->l0fp);
  }


  printf("=================================\n");
  
  struct eviction e;
  //printf("sketch_fd =%d\n", sketch_fd);
  if (bpf_map_lookup_elem(eviction_map_fd, &key, &e) != 0) {
    fprintf(stderr, "Failed to read BubbleSketch from map\n");
    return;
  }
  printf("Eviction count:%llu\n", e.counter);
}

static void Entry_init(struct Entry *e){
  for(int i=0;i<14;i++){
    e->id[i] =0;
  }
  e->fingerprint=0;
  e->count=0;
  e->l0fp=0;	

}
static void Bucket_init(struct Bucket *b){
  for(int i=0;i<MAX_ENTRY;i++){
    Entry_init(&b->entries[i]);
  }
  b->col_index=0;
}
static void BubbleSketch_init(struct BubbleSketch *bs, __s32 threshold1, __s32 K) {                      
  bs->bucket_num = MAX_BUCKETS;
  bs->threshold1 = threshold1;       
  bs->K = K;
  bs->f_max = 0;
  bs->lossy_func_id = 1; // MinusOneStrategy                                 

  for (int i = 0; i < MAX_ARRAYS; i++) {                                     
    for (int j = 0; j < MAX_BUCKETS; j++) { 
      Bucket_init(&bs->buckets[i][j]);                                   
    }       
  }                                  

}
static void print_throughput(int map_fd)
{
  __u32 key = 0;
  __u64 vals[64]; // enough for MAX possible CPUs
  int nr_cpus = libbpf_num_possible_cpus();

  if (bpf_map_lookup_elem(map_fd, &key, &vals) != 0) {
    perror("bpf_map_lookup_elem");
    return;
  }

  __u64 total = 0;
  for (int i = 0; i < nr_cpus; i++)
    total += vals[i];

  printf("Total inserts: %llu\n", total);
}


int main(int argc, char **argv)
{
  struct bpf_program *prog;
  struct bpf_link *link = NULL;
  int ifindex;
  int err = 0;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
    return 1;
  }

  ifindex = if_nametoindex(argv[1]);
  if (!ifindex) {
    perror("if_nametoindex");
    return 1;
  }

  /* Open and load skeleton */
  skel = bubble_sketch_ebpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open/load skeleton\n");
    return 1;
  }

  /* Get map FD */
  sketch_shard_fds[0] = bpf_map__fd(skel->maps.sketch_shard_0);
  sketch_shard_fds[1] = bpf_map__fd(skel->maps.sketch_shard_1);
  sketch_shard_fds[2] = bpf_map__fd(skel->maps.sketch_shard_2);
  sketch_shard_fds[3] = bpf_map__fd(skel->maps.sketch_shard_3);

  __u32 key = 0;
  
  // Initialize all shards
  for (int i = 0; i < SHARD_COUNT; i++) {
    struct BubbleSketch sk = {};
    BubbleSketch_init(&sk, 10, 10000);
    
    if (bpf_map_update_elem(sketch_shard_fds[i], &key, &sk, BPF_ANY) != 0) {
      fprintf(stderr, "Failed to initialize sketch shard %d\n", i);
      perror("bpf_map_update_elem");
      goto cleanup;
    }
  }
  
  printf("Multi-Map Sharded BubbleSketch initialized (%d shards).\n", SHARD_COUNT);


  prog = skel->progs.xdp_collect_5tuple;
  /* Attach XDP program */
  link = bpf_program__attach_xdp(prog, ifindex);
  if (!link) {
    fprintf(stderr, "Failed to attach XDP program to %s\n", argv[1]);
    err = 1;
    goto cleanup;
  }

//eviction counter mechanism:
  eviction_map_fd = bpf_map__fd(skel->maps.eviction_map);
  struct eviction e ={};
  //now we initialize the eviction struct and update using the same __u32 key
  e.counter = 0; 
  if(bpf_map_update_elem(eviction_map_fd, &key, &e, BPF_ANY)!=0){
    perror("bpf_map_update_elem");
    goto cleanup;
  }
//eviction counter mechanism ends  


  printf("Running on %s (ifindex %d)... Ctrl+C to stop\n", argv[1], ifindex);

  counter_fd = bpf_map__fd(skel->maps.insert_counter);
  __u64 prev_total = 0;
  while (!exiting) {
    sleep(1);

    __u32 key = 0;
    __u64 vals[64];
    int nr_cpus = libbpf_num_possible_cpus();

    if (bpf_map_lookup_elem(counter_fd, &key, &vals) == 0) {
      __u64 total = 0;
      for (int i = 0; i < nr_cpus; i++)
        total += vals[i];

      printf("Insert throughput: %llu pkt/s\n", total - prev_total);
      prev_total = total;
    }
  }

  /* On exit */
  dump_results();

cleanup:
  if (link)
    bpf_link__destroy(link);
  bubble_sketch_ebpf__destroy(skel);
  return -err;
}

