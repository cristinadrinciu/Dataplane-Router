#include "route_trie.h"
#include <lib.h>

#define NR_BITS 2

trie_node_t *create_trie_node(int data_size)
{
    trie_node_t *node = (trie_node_t *)malloc(sizeof(trie_node_t));
    DIE(node == NULL, "Failed to alloc a node\n");
    
    node->data = calloc(1, data_size);
    DIE(node->data == NULL, "Failed to alloc data\n");

    node->children = calloc(NR_BITS, sizeof(trie_node_t *));

    node->nr_children = 0;

    node->is_end = false;

    return node;
}

route_trie_t *create_route_trie(int data_size)
{
    route_trie_t *trie = (route_trie_t *)malloc(sizeof(route_trie_t));
    DIE(trie == NULL, "Failed to alloc trie\n");

    trie->root = create_trie_node(data_size);
    trie->size = 0;
    trie->data_size = data_size;
    trie->nr_bits = NR_BITS;

    return trie;
}

void free_trie_helper(route_trie_t *trie, trie_node_t *node)
{
    if (node == NULL)
        return;

    for (int i = 0; i < trie->nr_bits && node->nr_children; i++)
    {
        // free the subtree for each child
        if(!node->children[i])
            continue;
        free_trie_helper(trie, node->children[i]);
        node->children[i] = NULL;
        node->nr_children--;
    }

    if(node->data)
        free(node->data);

    free(node->children);
    free(node);
}

void free_route_trie(route_trie_t *trie)
{
    free_trie_helper(trie, trie->root);
    free(trie);
}

int get_first_bit(uint32_t key)
{
    // get the first bit of the key
    return (key >> 31) & 1;
}

void insert_route_helper(route_trie_t *trie, trie_node_t *curr_node, int key, int mask, void *data)
{
    if (mask == 0) {
        // copy the data to the node (the terminal node has the full data)
        memcpy(curr_node->data, data, trie->data_size);

        // mark the end of the route
        curr_node->is_end = true;

        // increment the number of routes in the table
        trie->size++;
        return;
    }

    // create a node and insert it in the trie
    int bit = get_first_bit(key);
    if (curr_node->children[bit] == NULL) {
        curr_node->nr_children++;
        curr_node->children[bit] = create_trie_node(trie->data_size);
    }

    insert_route_helper(trie, curr_node->children[bit], key << 1, mask << 1, data);
}

void insert_route(route_trie_t *trie, uint32_t key, int mask, void *data)
{
    if(!trie) {
        DIE(true, "Trie is NULL\n");
        return;
    }
    // convert first the key to the host byte order
    key = ntohl(key);
    
    // conver the mask to the host byte order
    mask = ntohl(mask);

    insert_route_helper(trie, trie->root, key, mask, data);
}

void *search_route_helper(route_trie_t *trie, trie_node_t *curr_node, uint32_t route)
{
    int bit = get_first_bit(route);
    trie_node_t *next_node = curr_node->children[bit];

     if (!next_node) { // if it is a leaf or does not have the child
        // If the current node is an end node, return its data
        if (curr_node->is_end) { // is a valid route in the routing table
            return curr_node->data;
        } else { // the route is not in the routing table
            return NULL;
        }
    }

    return search_route_helper(trie, curr_node->children[bit], route << 1);
}

void *search_route(route_trie_t *trie, uint32_t route)
{
    if(!trie) {
        DIE(true, "Trie is NULL\n");
        return NULL;
    }

    // convert first the key to the host byte order
    route = ntohl(route);

    return search_route_helper(trie, trie->root, route);
}