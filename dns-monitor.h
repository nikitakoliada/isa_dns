// dns-monitor.h
// Description: Header file for dns-monitor.c
// Author: Nikita Koliada xkolia00

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define DNSPORT 53

#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_MX 15
#define DNS_AAAA 28
#define DNS_SRV 33

const char *dns_type_to_str(unsigned short type);

int get_size_of_domain_name(u_char *payload, char *name);

// DNS header
struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount; // number of questions
    uint16_t ancount; // number of answers
    uint16_t nscount; // number of authoritative records
    uint16_t arcount; // number of additional records
};

int line_exists_in_file(FILE *file, const char *line_to_check);

void append_domain_if_not_exists(FILE *file, const char *domain);

void append_transaction_if_not_exists(FILE *file, const char *domain, const char *ip_address);

const char *print_timestamp();

void print_ip_address(struct ip *ip_header);

const char *print_dns_flags(uint16_t flags);

void extract_domain_name(u_char *payload, u_char *msg_buffer, char *domain_name);

int process_dns_question(char *output_buffer, u_char **payload, u_char *buffer, FILE *domain_file, int verbose);

void process_dns_records(u_char **payload, u_char *buffer, unsigned short count, FILE *translation_file, FILE *domain_file, int verbose);

void process_dns(const u_char *packet, int packet_size, int verbose, FILE *domain_file, FILE *translation_file);

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void capture_packets(const char *source, int is_pcap_file, int verbose, FILE *domain_file, FILE *translation_file);

#endif
