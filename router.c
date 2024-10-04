#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "route_trie.h"

#define MAX_RTABLE_ENTRIES 100000
#define MAX_ARP_ENTRIES 100
#define ETH_ALEN 6



// return the best route for a given IP in the routing trie
struct route_table_entry *get_best_route(uint32_t ip_dest, route_trie_t *routing_trie) {
	return search_route(routing_trie, ip_dest);
	
}

// function that return the arp entry for a given ip
struct arp_table_entry *get_arp_entry(uint32_t ip_dest, struct arp_table_entry *arp_table, int arp_table_len) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}
	return NULL;
}

// this function will generate the ICMP messages, based on the type and code(errors and echo reply)
void generate_icmp_message(struct ether_header *eth_hdr ,struct iphdr *ip_hdr, char buf[], int interface, int type, int code)
{
    // calculate the length of the ICMP message
    int icmp_msg_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
    char icmp_buf[MAX_PACKET_LEN];

    // pointers to the ICMP message's IP and ICMP headers within icmp_buf
    struct iphdr *new_ip_hdr = (struct iphdr *)icmp_buf;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_buf + sizeof(struct iphdr));

    // populate the new IP header
    memcpy(new_ip_hdr, ip_hdr, sizeof(struct iphdr));
    new_ip_hdr->tot_len = htons(icmp_msg_len);
    new_ip_hdr->protocol = IPPROTO_ICMP;
    new_ip_hdr->ttl = 64; // standard TTL for ICMP messages
    inet_pton(AF_INET, get_interface_ip(interface), &new_ip_hdr->saddr);
    new_ip_hdr->daddr = ip_hdr->saddr; // send back to the original sender
    new_ip_hdr->check = 0; // recompute checksum
    new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));

    // populate the ICMP header
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->checksum = 0; // initialize to 0 before computing the checksum

    // copy the original IP header + first 8 bytes of the payload into the ICMP data field
    memcpy((char *)icmp_hdr + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr) + 8);

    // compute the ICMP checksum
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

    // Create a new buffer to hold both the Ethernet header and ICMP message
    char send_buf[sizeof(struct ether_header) + icmp_msg_len];

    // Copy the Ethernet header into send_buf
    memcpy(send_buf, eth_hdr, sizeof(struct ether_header));

    // Swap Ethernet addresses
    memcpy(((struct ether_header *)send_buf)->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
    get_interface_mac(interface, ((struct ether_header *)send_buf)->ether_shost);

    // Copy the ICMP message (IP header + ICMP header + data) into send_buf
    memcpy(send_buf + sizeof(struct ether_header), icmp_buf, icmp_msg_len);

    // Send the message
    send_to_link(interface, send_buf, sizeof(struct ether_header) + icmp_msg_len);
}


void generate_arp_request(uint32_t target_ip, int interface) {
    // create a buffer large enough to hold both headers
    char buffer[sizeof(struct ether_header) + sizeof(struct arp_header)];
    
    // assign pointers to locations within the buffer for each header
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    struct arp_header *arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));

    // fill in the Ethernet header
    eth_hdr->ether_type = htons(ARP_ETHERTYPE); // Ethertype for ARP
    get_interface_mac(interface, eth_hdr->ether_shost); // Source MAC
    memset(eth_hdr->ether_dhost, 0xFF, ETH_ALEN); // Broadcast MAC address

    // fill in the ARP header
    arp_hdr->htype = htons(1); // hardware type Ethernet
    arp_hdr->ptype = htons(IP_ETHERTYPE); // protocol type IPv4
    arp_hdr->hlen = ETH_ALEN; // length of hardware address
    arp_hdr->plen = 4; // length of protocol address
    arp_hdr->op = htons(1); // ARP request opcode

    // convert source IP address from string to network byte order integer
    arp_hdr->spa = inet_addr(get_interface_ip(interface)); // Source protocol address

    memset(arp_hdr->tha, 0x0, ETH_ALEN); // Target hardware address (unknown)
    arp_hdr->tpa = target_ip; // Target protocol address

	// set sha to the mac address of the interface
	get_interface_mac(interface, arp_hdr->sha);

    // send the buffer as the ARP request
    send_to_link(interface, (char *)buffer, sizeof(buffer));
}

// function that will generate an arp reply
void generate_arp_reply(char *buff, size_t len, int interface)
{
	// extract the ARP header
	struct arp_header *arp_hdr = (struct arp_header *)(buff + sizeof(struct ether_header));

	// declare the header of the ARP reply
	struct ether_header *eth_hdr = (struct ether_header *)buff;

	// fill the ARP header
	arp_hdr->op = htons(2); // ARP reply, opcode 2
	memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ALEN); // sender MAC address
	get_interface_mac(interface, arp_hdr->sha); // target MAC address

	// swap the IP addresses
	uint32_t cpy_ip_d = arp_hdr->tpa;
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = cpy_ip_d;

	// fill the Ethernet header
	get_interface_mac(interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_hdr->tha, ETH_ALEN);

	// send the ARP reply
	send_to_link(interface, buff, len);
}

// function that will enqueue a package to be sent later
void enqueue_waiting_package(char* buf, size_t len, struct route_table_entry *next_hop, queue waiting_packets) {
	// create the package structure for the queue
	q_package *package = malloc(sizeof(q_package));
	package->buff = malloc(len);
	memcpy(package->buff, buf, len);
	package->len = len;
	package->next_hop = next_hop;
	queue_enq(waiting_packets, package);
}


void ip_packet_processing(struct ether_header *eth_hdr, int interface, size_t len, char buf[], route_trie_t *routing_trie, struct arp_table_entry *arp_table, int arp_table_len, queue waiting_packets) {
    // the following lines are mostly from lab04

    // extract the IP header
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

    // verify if this is the destination of the package (if the packet is for the router)
    // verify if it is a broadcast
    uint32_t ip_address = inet_addr(get_interface_ip(interface));
    if (ip_hdr->daddr == ip_address || ip_hdr->daddr == 0xFFFFFFFF) {
        // check if it is an ICMP ECHO REQUEST
        generate_icmp_message(eth_hdr, ip_hdr, buf, interface, 0, 0);
        return;
    }

    // check the ip_hdr integrity using checksum
    uint16_t sum_received = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    uint16_t sum_computed = checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4);
    if (sum_received != sum_computed) {
        // drop the packet, it is corrupted
        return;
    }

    // check if the TTL is 0
    if (ip_hdr->ttl <= 1) {
        // send an ICMP Time Exceeded message
        generate_icmp_message(eth_hdr, ip_hdr, buf, interface, 11, 0);
        return;
    } else {
        // decrement the TTL
        ip_hdr->ttl--;
    }

    // find the best route
    struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, routing_trie);

    // check if the destination is reachable
    if (best_route == NULL) {
        // send an ICMP Destination Unreachable message
        generate_icmp_message(eth_hdr, ip_hdr, buf, interface, 3, 0);
        return;
    }

    // update the IP checksum
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));

    // update the ethernet header
    // find the next ARP entry
    struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop, arp_table, arp_table_len);
    if (arp_entry == NULL) {
		printf("ARP entry not found\n");
		printf("%d\n", arp_table_len);
        // enqueue the packet to be sent later
        enqueue_waiting_package(buf, len, best_route, waiting_packets);

        // send an ARP request
        generate_arp_request(best_route->next_hop, best_route->interface);
        return;
    }

    // find the MAC address of the interface
    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));

    // send the packet
    send_to_link(best_route->interface, buf, len);
}


void send_queue_packets(queue waiting_packets, struct arp_header *arp_hdr) {
	if(waiting_packets == NULL) {
		return;
	}

	queue new_waiting_packets = queue_create();

	while(!queue_empty(waiting_packets)) {
		// get the first package from the queue
		q_package *package = queue_deq(waiting_packets);

		struct ether_header *eth_hdr = (struct ether_header *)package->buff;

		if (package->next_hop->next_hop == arp_hdr->spa) {
			// update the MAC address
			memcpy(eth_hdr->ether_dhost, arp_hdr->sha, ETH_ALEN);
			send_to_link(package->next_hop->interface, package->buff, package->len);
		} else {
			// enqueue the packet to be sent later
			queue_enq(new_waiting_packets, package);
		}
	}

	waiting_packets = new_waiting_packets;
}

void arp_packet_processing(char *buf, size_t len, int interface, struct arp_table_entry *arp_table, int *arp_table_len, queue waiting_packets) {
	// extract the ARP header
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// check what type of ARP packet is
	if (ntohs(arp_hdr->op) == 1) {
		// it is an ARP request
		// check if the target IP is the IP of the interface
		uint32_t ip_address = inet_addr(get_interface_ip(interface));
		if (arp_hdr->tpa == ip_address) {
			// generate an ARP reply
			generate_arp_reply(buf, len, interface);
		}
	} else if (ntohs(arp_hdr->op) == 2) {
		// it is an ARP reply, add the entry to the ARP table
		arp_table[*arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[*arp_table_len].mac, arp_hdr->sha, ETH_ALEN);
		(*arp_table_len)++;

		// send the packets that were waiting for this ARP reply
		send_queue_packets(waiting_packets, arp_hdr);
	}
}

route_trie_t *convert_routing_table_to_trie(struct route_table_entry *rtable, int rtable_len) {
	route_trie_t *trie = create_route_trie(sizeof(struct route_table_entry));

	for (int i = 0; i < rtable_len; i++) {
		insert_route(trie, rtable[i].prefix, rtable[i].mask, &rtable[i]);
	}

	return trie;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// declare the routing table and allocate memory for it
	struct route_table_entry *routing_table = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
	DIE(routing_table == NULL, "No memory for routing table.");

	// declare the ARP table and allocate memory for it
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_ENTRIES);
	DIE(arp_table == NULL, "No memory for ARP table.");

	// parse the routing table to find its length
	int rtable_len = read_rtable(argv[1], routing_table);
	//int arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	int arp_table_len = 0;

	// convert the routing table to a trie
	route_trie_t *routing_trie = convert_routing_table_to_trie(routing_table, rtable_len);

	// create the waiting packets queue
	queue waiting_packets = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// check the ethernet type
		if (ntohs(eth_hdr->ether_type) == IP_ETHERTYPE) {
			// process the IP packet
			ip_packet_processing(eth_hdr, interface, len, buf, routing_trie, arp_table, arp_table_len, waiting_packets);
		} else if (ntohs(eth_hdr->ether_type) == ARP_ETHERTYPE) {
			// process the ARP packet
			arp_packet_processing(buf, len, interface, arp_table, &arp_table_len, waiting_packets);
		}
	}

	free(routing_table);
	free(arp_table);
	free_route_trie(routing_trie);
	return 0;
}