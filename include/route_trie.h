#ifndef ROUTE_TRIE_H
#define ROUTE_TRIE_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// trie structure for the routing table convertion

typedef struct trie_node_t {
    void *data; // pointer to the data to be set when it is reached end of the route (is_end = true)
    struct trie_node_t **children; // the bits 0 and 1
    bool is_end; // mark the end of the route
    int nr_children; // number of children (0 and 1)
} trie_node_t;

typedef struct route_trie_t {
    trie_node_t *root; // root of the trie
    int size;          // number of routes in the route table
    int data_size;     // size of the data to be stored in the trie
    int nr_bits;       // it will be 2 obvs (0 and 1), but for the sake of the generality (alphabet and alphabet size)
} route_trie_t;

trie_node_t *create_trie_node(int data_size);
route_trie_t *create_route_trie(int data_size);
void free_route_trie(route_trie_t *trie);
void insert_route(route_trie_t *trie, uint32_t key, int mask, void *data);
void *search_route(route_trie_t *trie, uint32_t route);

#endif // ROUTE_TRIE_H