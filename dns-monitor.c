// Description: A simple DNS monitor that captures DNS packets from a given interface or a PCAP file.
// Author: Nikita Koliada xkolia00

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

// DNS question types
#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_MX 15
#define DNS_AAAA 28
#define DNS_SRV 33

const char *dns_type_to_str(unsigned short type)
{
    switch (type)
    {
    case DNS_A:
        return "A";
    case DNS_NS:
        return "NS";
    case DNS_CNAME:
        return "CNAME";
    case DNS_SOA:
        return "SOA";
    case DNS_MX:
        return "MX";
    case DNS_AAAA:
        return "AAAA";
    case DNS_SRV:
        return "SRV";
    default:
        return "UNKNOWN";
    }
}

int get_size_of_domain_name(u_char *payload, char *name)
{
    return (*payload & 0xC0) == 0xC0 ? 2 : strlen(name) + 1;
}

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

// Function to print timestamp
void print_timestamp()
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", t);
    printf("%s ", buf);
}

// Function to print IP address
void print_ip_address(struct ip *ip_header)
{
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("%s -> %s ", src_ip, dst_ip);
}

void print_dns_flags(uint16_t flags)
{
    uint16_t qr = (flags & 0x8000) >> 15;     // QR (Query/Response)
    uint16_t opcode = (flags & 0x7800) >> 11; // Opcode (4 bits)
    uint16_t aa = (flags & 0x0400) >> 10;     // Authoritative Answer
    uint16_t tc = (flags & 0x0200) >> 9;      // Truncated
    uint16_t rd = (flags & 0x0100) >> 8;      // Recursion Desired
    uint16_t ra = (flags & 0x0080) >> 7;      // Recursion Available
    uint16_t ad = (flags & 0x0020) >> 5;      // Authenticated Data (AD)
    uint16_t cd = (flags & 0x0010) >> 4;      // Checking Disabled (CD)
    uint16_t rcode = flags & 0x000F;          // Response Code

    printf("FLAGS: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           qr, opcode, aa, tc, rd, ra, ad, cd, rcode);
}

void extract_domain_name(u_char *payload, u_char *msg_buffer, char *domain_name)
{
    unsigned int idx = 0;
    unsigned int length;

    while (1)
    {
        length = payload[idx++];

        // End of domain name
        if (length == 0)
        {
            break;
        }
        // Check for message compression (11XX XXXX format)
        if ((length & 0xC0) == 0xC0)
        {
            // Extract offset for compression pointer
            unsigned int offset = ((length & 0x3F) << 8) | payload[idx++];
            // Recursively extract the compression domain name from the offset in the message buffer
            extract_domain_name(msg_buffer + offset, msg_buffer, domain_name);
            return;
        }
        else
        {
            // Append each character in the label to the result
            for (unsigned int i = 0; i < length; i++)
            {
                domain_name[strlen(domain_name)] = payload[idx++];
            }
            domain_name[strlen(domain_name)] = '.';
        }
    }
}

void process_dns_question(u_char **payload, u_char *buffer, FILE *domain_file)
{
    // Parse the DNS name from the question section

    char dns_name[256] = {0}; // Changed from char* to char array
    extract_domain_name((*payload), buffer, dns_name);
    *payload += get_size_of_domain_name(*payload, dns_name); // Adjusted the offset after parsing the domain name

    // Read the type and class
    unsigned short qtype = ntohs(*(unsigned short *)(*payload));
    unsigned short qclass = ntohs(*(unsigned short *)(*payload + 2));
    *payload += 4;

    const char *record_type = dns_type_to_str(qtype);
    if (qclass == 1)
    {
        printf("%s IN %s\n", dns_name, record_type);
    }
    // Print the result in the format "<dns name> IN <type of record>"
    // fprintf(domain_file, "%s IN %s\n", dns_name, record_type);
}

void process_dns_records(u_char **payload, u_char *buffer, unsigned short count, FILE *translation_file)
{
    for (unsigned short i = 0; i < count; i++)
    {
        // Parse the DNS name
        char dns_name[256] = {0};

        extract_domain_name((*payload), buffer, dns_name);
        // Move past the name reference (2 bytes)
        // TODO check if this is correct
        *payload += get_size_of_domain_name(*payload, dns_name);

        // dns packet example

        //| DNS Name | rtype | rclass | ttl     | rdlength | RDATA       |
        // |----------|-------|--------|---------|----------|-------------|
        // | example.com | 1     | 1      | 3600    | 4        | 192.0.2.1   |

        // Read the type and class
        unsigned short rtype = ntohs(*(unsigned short *)(*payload));
        // unsigned short rclass = ntohs(*(unsigned short *)(*payload + *offset + 2));
        // unsigned int ttl = ntohl(*(unsigned int *)(*payload + *offset + 4));
        unsigned short rdlength = ntohs(*(unsigned short *)(*payload + 8));

        *payload += 10; // Move past type, class, TTL, and RDLength

        // Read the resource data
        // const u_char *rdata = *payload + *offset;
        // Process the resource data based on the type
        switch (rtype)
        {
        case DNS_A:
        {
            struct in_addr addr;
            memcpy(&addr, *payload, sizeof(addr));
            printf("%s IN A %s\n", dns_name, inet_ntoa(addr));
            break;
        }
        case DNS_NS:
        {
            char ns_name[256] = {0};
            // pass not the rdata but the *payload???
            extract_domain_name(*payload, buffer, ns_name);
            printf("%s IN NS %s\n", dns_name, ns_name);
            break;
        }
        case DNS_CNAME:
        {
            char cname[256] = {0};
            extract_domain_name(*payload, buffer, cname);
            printf("%s IN CNAME %s\n", dns_name, cname);
            break;
        }
        case DNS_SOA:
        {
            char mname[256] = {0}, rname[256] = {0};
            // Parse MNAME
            extract_domain_name(*payload, buffer, mname);

            *payload += get_size_of_domain_name(*payload,  mname);

            // Parse RNAME
            extract_domain_name(*payload, buffer, rname);

            *payload += get_size_of_domain_name(*payload, rname);

            // Read the rest of the fields ( oprionl, more to understand the format)
            unsigned int serial = ntohl(*(unsigned int *)(*payload));
            unsigned int refresh = ntohl(*(unsigned int *)(*payload + 4));
            unsigned int retry = ntohl(*(unsigned int *)(*payload + 8));
            unsigned int expire = ntohl(*(unsigned int *)(*payload + 12));
            unsigned int minimum = ntohl(*(unsigned int *)(*payload + 16));

            printf("%s IN SOA %s %s %u %u %u %u %u\n", dns_name, mname, rname, serial, refresh, retry, expire, minimum);
            break;
        }
        case DNS_MX:
        {
            unsigned short preference = ntohs(*(unsigned short *)(*payload));
            char mx_name[256] = {0};
            extract_domain_name((*payload + 2), buffer, mx_name);
            printf("%s IN MX %u %s\n", dns_name, preference, mx_name);
            break;
        }
        case DNS_AAAA:
        {
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, *payload, addr, sizeof(addr));
            printf("%s IN AAAA %s\n", dns_name, addr);
            break;
        }
        case DNS_SRV:
        {
            unsigned short priority = ntohs(*(unsigned short *)(*payload));
            unsigned short weight = ntohs(*(unsigned short *)((*payload) + 2));
            unsigned short port = ntohs(*(unsigned short *)((*payload) + 4));
            char srv_name[256] = {0};
            // SRV starts with 6 bytes for priority, weight, and port
            extract_domain_name((*payload + 6), buffer, srv_name);
            printf("%s IN SRV %u %u %u %s\n", dns_name, priority, weight, port, srv_name);
            break;
        }
        default:
            printf("%s IN UNKNOWN (Type: %u)\n", dns_name, rtype);
            break;
        }

        // Move the offset past the RDATA
        *payload += rdlength;
    }
}

// Process DNS packets
void process_dns(const u_char *packet, int packet_size, int verbose, FILE *domain_file, FILE *translation_file)
{
    struct ip *ip_header = (struct ip *)(packet + 14); 
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    struct dnshdr *dns_header = (struct dnshdr *)(packet + 14 + (ip_header->ip_hl * 4) + sizeof(struct udphdr));
    // Pointer to the start of the DNS payload so could be used to parse the DNS compression name references
    u_char *buffer = (u_char *)(packet + 14 + (ip_header->ip_hl * 4) + sizeof(struct udphdr));
    u_char *payload = (u_char *)(packet + 14 + (ip_header->ip_hl * 4) + sizeof(struct udphdr) + sizeof(struct dnshdr));

    if (ntohs(udp_header->uh_dport) == DNSPORT || ntohs(udp_header->uh_sport) == DNSPORT)
    {

        if (!verbose)
        {
            print_timestamp();
            print_ip_address(ip_header);
            printf("(%c %d/%d/%d/%d)\n",
                   (ntohs(dns_header->flags) & 0x8000) ? 'R' : 'Q',
                   ntohs(dns_header->qdcount), ntohs(dns_header->ancount),
                   ntohs(dns_header->nscount), ntohs(dns_header->arcount));
        }
        else
        {
            printf("Timestamp: ");
            print_timestamp();
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
            printf("\nSrcIP: %s\nDstIP: %s", src_ip, dst_ip);
            printf("\nSrcPort: UDP/%d\nDstPort: UDP/%d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            printf("Identifier: 0x%X\n", ntohs(dns_header->id));
            print_dns_flags(dns_header->flags);

            // Process DNS questions
            printf("\n[Question Section]\n");
            for (int i = 0; i < ntohs(dns_header->qdcount); i++)
            {
                process_dns_question(&payload, buffer, domain_file);
            }

            // Process DNS answers
            if (ntohs(dns_header->ancount) > 0)
            {
                printf("\n[Answer Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->ancount), translation_file);
            }

            // Process Authority records
            if (ntohs(dns_header->nscount) > 0)
            {
                printf("\n[Authority Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->nscount), translation_file);
            }
            // Process Additional records
            if (ntohs(dns_header->arcount) > 0)
            {
                printf("\n[Additional Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->arcount), translation_file);
            }
            printf("====================\n");
        }
    }
}

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE **files = (FILE **)args;
    process_dns(packet, header->caplen, files[0] != NULL, files[1], files[2]);
}

// Function to capture packets from a given interface
void capture_packets(const char *source, int is_pcap_file, int verbose, FILE *domain_file, FILE *translation_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    FILE *files[3] = {NULL, domain_file, translation_file};

    // Set verbose flag if needed
    if (verbose)
    {
        files[0] = (FILE *)1; // Non-NULL to indicate verbose mode
    }

    if (is_pcap_file)
    {
        // Open the pcap file instead of live capturing
        handle = pcap_open_offline(source, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", source, errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        // Live capture from the interface
        handle = pcap_open_live(source, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't read interface %s: %s\n", source, errbuf);
            exit(EXIT_FAILURE);
        }
    }

    // Set a BPF filter for DNS UDP packets (only for live capture)
    if (!is_pcap_file)
    {
        struct bpf_program filter;
        const char *filter_exp = "udp and (port 53)";
        if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &filter) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, (u_char *)files);

    // Close the capture handle
    pcap_close(handle);
}

// Main function
int main(int argc, char *argv[])
{
    int verbose = 0;
    char *interface = NULL;
    char *pcap_file = NULL;
    int use_pcap_file = 0;

    FILE *domain_file = NULL;
    FILE *translation_file = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            interface = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {
            use_pcap_file = 1;
            pcap_file = argv[++i];
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
        {
            domain_file = fopen(argv[++i], "a");
            if (!domain_file)
            {
                fprintf(stderr, "Error opening domain file\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            translation_file = fopen(argv[++i], "a");
            if (!translation_file)
            {
                fprintf(stderr, "Error opening translation file\n");
                return 1;
            }
        }
    }

    if (interface != NULL && !use_pcap_file)
    {
        // Live capture mode
        capture_packets(interface, 0, verbose, domain_file, translation_file);
    }
    else if (use_pcap_file && pcap_file != NULL)
    {
        // PCAP file capture mode
        capture_packets(pcap_file, 1, verbose, domain_file, translation_file);
    }
    else
    {
        printf("Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n");
    }

    if (domain_file)
        fclose(domain_file);
    if (translation_file)
        fclose(translation_file);

    return 0;
}
