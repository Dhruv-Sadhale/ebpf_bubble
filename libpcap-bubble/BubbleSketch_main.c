// FIXED: Define feature macros FIRST before any includes
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include "BubbleSketch.c"


/*
*this will change with the change in .dat file
*/
#define MAX_INSERT 45996697 // Maximum number of packets to process
#define KEY_LEN 13          // Length of each key in the dataset


/*this value is AI generated, need to think which to use here*/
#define HASH_MAP_SIZE 1000000
typedef struct HashEntry {
    char key[KEY_LEN + 1];
    int value;
    struct HashEntry* next;
} HashEntry;

typedef struct HashMap {
    HashEntry* buckets[HASH_MAP_SIZE];
    int size;
} HashMap;

// CONVERTED: Hash map functions
unsigned int hash_string(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_MAP_SIZE;
}

HashMap* HashMap_create() {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    memset(map->buckets, 0, sizeof(map->buckets));
    map->size = 0;
    return map;
}

void HashMap_put(HashMap* map, const char* key, int value) {
    unsigned int index = hash_string(key);
    HashEntry* entry = map->buckets[index];
    
    // Check if key already exists
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }
    
    // Create new entry
    entry = (HashEntry*)malloc(sizeof(HashEntry));
    strcpy(entry->key, key);
    entry->value = value;
    entry->next = map->buckets[index];
    map->buckets[index] = entry;
    map->size++;
}

int HashMap_get(HashMap* map, const char* key) {
    unsigned int index = hash_string(key);
    HashEntry* entry = map->buckets[index];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return 0;  // Return 0 if not found
}

void HashMap_increment(HashMap* map, const char* key) {
    HashMap_put(map, key, HashMap_get(map, key) + 1);
}

void HashMap_destroy(HashMap* map) {
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = map->buckets[i];
        while (entry) {
            HashEntry* temp = entry;
            entry = entry->next;
            free(temp);
        }
    }
    free(map);
}

// CONVERTED: Structure to replace C++ pair for sorting
typedef struct FlowPair {
    char key[KEY_LEN + 1];
    int frequency;
} FlowPair;

// CONVERTED: Comparison function for qsort (descending order by frequency)
int flow_compare(const void* a, const void* b) {
    const FlowPair* fa = (const FlowPair*)a;
    const FlowPair* fb = (const FlowPair*)b;
    return fb->frequency - fa->frequency;  // Descending order
}

// CONVERTED: Function to collect all entries from HashMap into array
int HashMap_to_array(HashMap* map, FlowPair** flows) {
    *flows = (FlowPair*)malloc(map->size * sizeof(FlowPair));
    int count = 0;
    
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        HashEntry* entry = map->buckets[i];
        while (entry) {
            strcpy((*flows)[count].key, entry->key);
            (*flows)[count].frequency = entry->value;
            count++;
            entry = entry->next;
        }
    }
    return count;
}

// CONVERTED: Main function - BubbleSketch only implementation
int main(int argc, char** argv) {
    int MEM = 300;  // Memory in KB
    int K = 1000;   // Top-K parameter
    int c;
    char dataset[40] = {'\0'};
    
    // CONVERTED: Command line argument parsing
    while ((c = getopt(argc, argv, "d:m:k:")) != -1) {
        switch (c) {
            case 'd':
                strcpy(dataset, optarg);
                break;
            case 'm':
                MEM = atoi(optarg);
                break;
            case 'k':
                K = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-d dataset] [-m memory_kb] [-k top_k]\n", argv[0]);
                return -1;
        }
    }
    
    printf("MEM=%dKB\n", MEM);
    printf("Find top %d\n\n", K);
    
    // CONVERTED: Initialize BubbleSketch
    printf("Initializing BubbleSketch\n");
    BubbleSketch sketch;
    BubbleSketch_init(&sketch, 10, K, MEM);  // threshold=10 as in original
    printf("BubbleSketch initialized with %d buckets\n\n", sketch._bucket_num);
    
    // CONVERTED: Setup dataset file reading
    char default_dataset[40] = "./10.dat";
    if (dataset[0] == '\0') {
        strcpy(dataset, default_dataset);
    }
    printf("Dataset: %s\n\n", dataset);
    
    FILE* fin = fopen(dataset, "rb");
    if (!fin) {
        printf("Dataset not exists!\n");
        return -1;
    }
    
    // CONVERTED: Data structures for ground truth and processing
    HashMap* ground_truth = HashMap_create();  // Replaces map B
    HashMap* top_k_truth = HashMap_create();   // Replaces map C
    char** strings = (char**)malloc(MAX_INSERT * sizeof(char*));
    char tmp[KEY_LEN];
    
    // CONVERTED: Read dataset and build ground truth
    printf("Reading dataset and building ground truth...\n");
    int packet_num = 0;
    for (int i = 0; i < MAX_INSERT; i++) {
        if (feof(fin)) {
            break;
        }
        
        size_t bytes_read = fread(tmp, 1, KEY_LEN, fin);
        if (bytes_read != KEY_LEN) {
            break;
        }
        
        strings[i] = (char*)malloc((KEY_LEN ) * sizeof(char));
        memcpy(strings[i], tmp, KEY_LEN);
        
        HashMap_increment(ground_truth, strings[i]);
        packet_num++;
    }
    fclose(fin);
    
    printf("Total packets processed: %d\n\n", packet_num);
    
    // CONVERTED: Measure insertion throughput
    printf("*************Throughput (insert)************\n");
    struct timespec time1, time2;
    long long resns;
    
    clock_gettime(CLOCK_MONOTONIC, &time1);
    for (int i = 0; i < packet_num; i++) {
        BubbleSketch_Insert(&sketch, strings[i]);
        
    }
    clock_gettime(CLOCK_MONOTONIC, &time2);
    
    resns = (long long)(time2.tv_sec - time1.tv_sec) * 1000000000LL + 
            (time2.tv_nsec - time1.tv_nsec);
    double throughput = (double)1000.0 * packet_num / resns;
    printf("Throughput of %s (insert): %.6lf Mips\n\n", 
           BubbleSketch_get_name(&sketch), throughput);
    
    // CONVERTED: Process results
    printf("*************Processing Results************\n");
    BubbleSketch_work(&sketch);
    
    // CONVERTED: Build sorted ground truth for top-K
    printf("Preparing true flow rankings...\n");
    FlowPair* all_flows;
    int flow_count = HashMap_to_array(ground_truth, &all_flows);
    qsort(all_flows, flow_count, sizeof(FlowPair), flow_compare);
    
    // Store top K+10 flows for comparison
    int comparison_size = (K + 10 < flow_count) ? K + 10 : flow_count;
    for (int i = 0; i < comparison_size; i++) {
        HashMap_put(top_k_truth, all_flows[i].key, all_flows[i].frequency);
    }
    
    printf("Ground truth prepared (top %d flows)\n\n", comparison_size);
    
    // CONVERTED: Calculate metrics (PRE, ARE, AAE)
    printf("*************Calculating Metrics************\n");
    int accepted = 0;
    double total_aae = 0.0;
    double total_are = 0.0;
    char result_str[KEY_LEN + 1];
    int result_val;
    
//    printf("Top-%d results from BubbleSketch:\n", K);
  //  printf("Rank\tPredicted\tActual\t\tKey\n");
 //   printf("----\t---------\t------\t\t---\n");
    
    for (int i = 0; i < K; i++) {
        BubbleSketch_Query(&sketch, i, result_str, &result_val);
        
        if (result_val == 0 || result_str[0] == '\0') {
    //       printf("%d\t%d\t\t-\t\t%s\n", i+1, result_val, result_str);
            continue;
        }
        
        int actual_freq = HashMap_get(top_k_truth, result_str);
      //  printf("%d\t%d\t\t%d\t\t%s\n", i+1, result_val, actual_freq, result_str);
        
        if (actual_freq > 0) {
            accepted++;
            int absolute_error = abs(actual_freq - result_val);
            double relative_error = (double)absolute_error / actual_freq;
            
            total_aae += absolute_error;
            total_are += relative_error;
        }
    }
    
    printf("\n*************Final Results************\n");
    printf("%s:\n", BubbleSketch_get_name(&sketch));
    printf("\tAccepted: %d/%d (%.10f)\n", accepted, K, (double)accepted / K);
    printf("\tARE: %.10f\n", total_are / K);
    printf("\tAAE: %.10f\n", total_aae / K);
    printf("\tMax Frequency: %d\n", sketch._f_max);
    
    // CONVERTED: Cleanup
    printf("\nCleaning up...\n");
    for (int i = 0; i < packet_num; i++) {
        free(strings[i]);
    }
    free(strings);
    free(all_flows);
    HashMap_destroy(ground_truth);
    HashMap_destroy(top_k_truth);
    BubbleSketch_destroy(&sketch);
    
    printf("Done!\n");
    return 0;
}

// CONVERTED: Note about compilation
/*
To compile this program, you need:
1. The BubbleSketch.c implementation (either included or linked)
2. Compile with: gcc -o main main.c -lm -std=c99

Usage examples:
./main -d dataset.dat -m 100 -k 1000
./main -m 200 -k 500
./main (uses defaults: ./1.dat, 100KB, top-1000)
*/
