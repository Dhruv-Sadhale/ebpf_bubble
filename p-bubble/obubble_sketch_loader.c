#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>

#include "obubble_sketch_common.h"
#include "obubble_sketch_ebpf.skel.h"

static volatile bool exiting = false;
static struct obubble_sketch_ebpf *skel;
static int sketch_fd;
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

/* Called at exit to fetch sketch and display Top-K */
static void dump_results(void)
{
  struct BubbleSketch sk;
  __u32 key = 0;
  //printf("sketch_fd =%d\n", sketch_fd);
  if (bpf_map_lookup_elem(sketch_fd, &key, &sk) != 0) {
    fprintf(stderr, "Failed to read BubbleSketch from map\n");
    return;
  }

  printf("bucket_num=%d\n threshold1=%d\n lossy_func_id=%d\n K=%d\n f_max=%d\n",
      sk.bucket_num, sk.threshold1, sk.lossy_func_id, sk.K, sk.f_max);

  // Sort the return array
  //struct Entry sorted[MAX_RET];// ye galat he
  struct Entry sorted[2*MAX_BUCKETS];
  int ret_index=0;
  for(int i=0;i<MAX_ARRAYS;i++){
    for(int j=0;j<MAX_BUCKETS;j++){
      sorted[ret_index]=sk.buckets[i][j].entries[0];
      ret_index++;
    }
  }
  /*
     for(int i=0;i<MAX_ARRAYS;i++){
     for(int j=0;j<MAX_BUCKETS;j++){
     printf("entry[%d][%d][0]: %d\n",i,j, sk.buckets[i][j].entries[0].count);
     }

     printf("===========================\n");
     }
   */
  qsort(sorted, 2*MAX_BUCKETS, sizeof(struct Entry), cmp_entries);
  printf("%-4s %-18s %-6s %-18s %-6s %-8s %-6s %-8s %-10s\n",
      "No", "Src IP", "S.Port", "Dst IP", "D.Port", "Proto", "Count", "Fingerprint", "L0FP");

  for (int j = 0; j < MAX_RET; j++) {
    struct Entry *entry = &sorted[j];
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
  skel = obubble_sketch_ebpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open/load skeleton\n");
    return 1;
  }

  /* Get map FD */
  sketch_fd = bpf_map__fd(skel->maps.sketch_map);


  struct BubbleSketch sk = {};
  BubbleSketch_init(&sk, 10, 1000);        
  __u32 key = 0;
  if (bpf_map_update_elem(sketch_fd, &key, &sk, BPF_ANY) != 0) {
    perror("bpf_map_update_elem");
    goto cleanup;
  }
  printf("BubbleSketch initialized in userspace.\n");


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
  obubble_sketch_ebpf__destroy(skel);
  return -err;
}

