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
    int size = 0;
    unsigned int length;

    while (1)
    {
        length = payload[size];

        // Check for message compression (high two bits set to 1)
        if ((length & 0xC0) == 0xC0)
        {
            // Compressed domain name - this is 2 bytes in total
            size += 2;
            break;
        }

        // End of domain name (null byte)
        if (length == 0)
        {
            size += 1;
            break;
        }

        // Normal label: move size by the length of the label + 1 for the length byte
        size += length + 1;
    }

    return size;
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

// Utility function to check if an exact line exists in the file
int line_exists_in_file(FILE *file, const char *line_to_check)
{
    char line[512];
    rewind(file); // Move the file pointer to the beginning
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\r\n")] = 0; // Remove trailing newline

        if (strcmp(line, line_to_check) == 0)
        {
            return 1; // Exact line exists in the file
        }
    }
    return 0; // Line not found
}

// Append a domain name to the file if it doesn't already exist
void append_domain_if_not_exists(FILE *file, const char *domain)
{
    if (file && !line_exists_in_file(file, domain))
    {
        fprintf(file, "%s\n", domain);
        fflush(file); // Ensure the line is written to the file immediately
    }
}

// Append a domain name + ip address to the file if it doesn't already exist
void append_transaction_if_not_exists(FILE *file, const char *domain, const char *ip_address)
{
    char *line = (char *)malloc(strlen(domain) + strlen(ip_address) + 2);
    sprintf(line, "%s %s", domain, ip_address);
    if (file && !line_exists_in_file(file, line))
    {
        fprintf(file, "%s\n", line);
        fflush(file); // Ensure the line is written to the file immediately
    }
}

// Function to print timestamp
const char *print_timestamp()
{
    static char timestamp[64]; // Static buffer to hold the timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info); // Format the timestamp
    return timestamp;
}
// Function to print IP address
void print_ip_address(struct ip *ip_header)
{
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("%s -> %s ", src_ip, dst_ip);
}

const char *print_dns_flags(uint16_t flags)
{
    flags = ntohs(flags);
    uint16_t qr = (flags >> 15) & 0x1;     // QR (Query/Response)
    uint16_t opcode = (flags >> 11) & 0xF; // Opcode (4 bits)
    uint16_t aa = (flags >> 10) & 0x1;     // Authoritative Answer
    uint16_t tc = (flags >> 9) & 0x1;      // Truncated
    uint16_t rd = (flags >> 8) & 0x1;      // Recursion Desired
    uint16_t ra = (flags >> 7) & 0x1;      // Recursion Available
    uint16_t ad = (flags >> 5) & 0x1;      // Authenticated Data (AD)
    uint16_t cd = (flags >> 4) & 0x1;      // Checking Disabled (CD)
    uint16_t rcode = flags & 0xF;          // Response Code (4 bits)

    static char buffer[256];
    sprintf(buffer, "FLAGS: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
            qr, opcode, aa, tc, rd, ra, ad, cd, rcode);
    return buffer;
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
            // Extract the compression domain name from the offset in the message buffer
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

int process_dns_question(char *output_buffer, u_char **payload, u_char *buffer, FILE *domain_file)
{
    // Parse the DNS name from the question section

    char dns_name[256] = {0};
    extract_domain_name((*payload), buffer, dns_name);
    *payload += get_size_of_domain_name(*payload, dns_name); // Adjusted the offset after parsing the domain name

    // Read the type and class
    unsigned short qtype = ntohs(*(unsigned short *)(*payload));
    unsigned short qclass = ntohs(*(unsigned short *)(*payload + 2));
    *payload += 4;

    const char *record_type = dns_type_to_str(qtype);
    if (qclass == 1)
    {
        sprintf(output_buffer + strlen(output_buffer), "%s IN %s\n", dns_name, record_type);
        if (strcmp(record_type, "UNKNOWN") != 0)
        {
            append_domain_if_not_exists(domain_file, dns_name);
            printf("%s", output_buffer);
            return 1; // if 1 then continue to the answer/authotity/additional section
        }
    }
    return 0;
}

void process_dns_records(u_char **payload, u_char *buffer, unsigned short count, FILE *translation_file, FILE *domain_file)
{
    for (unsigned short i = 0; i < count; i++)
    {
        // Parse the DNS name
        char dns_name[256] = {0};

        extract_domain_name((*payload), buffer, dns_name);

        append_domain_if_not_exists(domain_file, dns_name);

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

        // Process based on the type
        switch (rtype)
        {
        case DNS_A:
        {
            // Parse the IPv4 address
            struct in_addr addr;
            memcpy(&addr, *payload, sizeof(addr));
            append_transaction_if_not_exists(translation_file, dns_name, inet_ntoa(addr));
            printf("%s IN A %s\n", dns_name, inet_ntoa(addr));
            break;
        }
        case DNS_NS:
        {
            char ns_name[256] = {0};
            // Parse the NS name
            extract_domain_name(*payload, buffer, ns_name);
            append_domain_if_not_exists(domain_file, ns_name);
            printf("%s IN NS %s\n", dns_name, ns_name);
            break;
        }
        case DNS_CNAME:
        {
            // Parse the CNAME
            char cname[256] = {0};
            extract_domain_name(*payload, buffer, cname);
            append_domain_if_not_exists(domain_file, cname);
            printf("%s IN CNAME %s\n", dns_name, cname);
            break;
        }
        case DNS_SOA:
        {
            char mname[256] = {0}, rname[256] = {0};
            // Parse MNAME
            extract_domain_name(*payload, buffer, mname);

            *payload += get_size_of_domain_name(*payload, mname);

            // Parse RNAME
            extract_domain_name(*payload, buffer, rname);

            *payload += get_size_of_domain_name(*payload, rname);

            // Read the rest of the fields
            unsigned int serial = ntohl(*(unsigned int *)(*payload));
            unsigned int refresh = ntohl(*(unsigned int *)(*payload + 4));
            unsigned int retry = ntohl(*(unsigned int *)(*payload + 8));
            unsigned int expire = ntohl(*(unsigned int *)(*payload + 12));
            unsigned int minimum = ntohl(*(unsigned int *)(*payload + 16));

            append_domain_if_not_exists(domain_file, mname);
            append_domain_if_not_exists(domain_file, rname);

            printf("%s IN SOA %s %s %u %u %u %u %u\n", dns_name, mname, rname, serial, refresh, retry, expire, minimum);
            break;
        }
        case DNS_MX:
        {
            unsigned short preference = ntohs(*(unsigned short *)(*payload));
            char mx_name[256] = {0};
            extract_domain_name((*payload + 2), buffer, mx_name);
            append_domain_if_not_exists(domain_file, mx_name);
            printf("%s IN MX %u %s\n", dns_name, preference, mx_name);
            break;
        }
        case DNS_AAAA:
        {
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, *payload, addr, sizeof(addr));
            append_transaction_if_not_exists(translation_file, dns_name, addr);
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

            append_domain_if_not_exists(domain_file, srv_name);

            printf("%s IN SRV %u %u %u %s\n", dns_name, priority, weight, port, srv_name);
            break;
        }
        default:
        {
            break;
        }
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
            char time_stamp[1028] = {0};
            sprintf(time_stamp + strlen(time_stamp), "%s ", print_timestamp());
            printf("%s", time_stamp);
            print_ip_address(ip_header);
            printf("(%c %d/%d/%d/%d)\n",
                   (ntohs(dns_header->flags) & 0x8000) ? 'R' : 'Q',
                   ntohs(dns_header->qdcount), ntohs(dns_header->ancount),
                   ntohs(dns_header->nscount), ntohs(dns_header->arcount));
        }
        else
        {
            char output_buffer[1028] = {0};
            sprintf(output_buffer + strlen(output_buffer), "Timestamp: ");
            sprintf(output_buffer + strlen(output_buffer), "%s", print_timestamp());
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
            sprintf(output_buffer + strlen(output_buffer), "\nSrcIP: %s\nDstIP: %s", src_ip, dst_ip);
            sprintf(output_buffer + strlen(output_buffer), "\nSrcPort: UDP/%d\nDstPort: UDP/%d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            sprintf(output_buffer + strlen(output_buffer), "Identifier: 0x%X\n", ntohs(dns_header->id));
            sprintf(output_buffer + strlen(output_buffer), "%s", print_dns_flags(dns_header->flags));

            // Process DNS questions
            sprintf(output_buffer + strlen(output_buffer), "\n[Question Section]\n");
            for (int i = 0; i < ntohs(dns_header->qdcount); i++)
            {
                int question_result = process_dns_question(output_buffer, &payload, buffer, domain_file);
                if (question_result == 0)
                {
                    return;
                }
            }

            // Process DNS answers
            if (ntohs(dns_header->ancount) > 0)
            {
                printf("\n[Answer Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->ancount), translation_file, domain_file);
            }

            // Process Authority records
            if (ntohs(dns_header->nscount) > 0)
            {
                printf("\n[Authority Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->nscount), translation_file, domain_file);
            }
            // Process Additional records
            if (ntohs(dns_header->arcount) > 0)
            {
                printf("\n[Additional Section]\n");
                process_dns_records(&payload, buffer, ntohs(dns_header->arcount), translation_file, domain_file);
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

    if (verbose)
    {
        files[0] = (FILE *)1; // Non-NULL to set verbose mode
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

    // Set a BPF filter for DNS UDP packets , only live packets
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

    pcap_loop(handle, 0, packet_handler, (u_char *)files);

    pcap_close(handle);
}

int main(int argc, char *argv[])
{
    int verbose = 0;
    char *interface = NULL;
    char *pcap_file = NULL;
    int use_pcap_file = 0;
    
    // Flag to check if needed to write to the domain file
    FILE *domain_file = NULL;
    // Flag to check if needed to write to the translation file
    FILE *translation_file = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            interface = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {
            if (interface != NULL)
            {
                fprintf(stderr, "Cannot use both interface and pcap file\n");
                return 1;
            }
            use_pcap_file = 1;
            pcap_file = argv[++i];
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
        {
            domain_file = fopen(argv[++i], "w+");
            if (!domain_file)
            {
                fprintf(stderr, "Error opening domain file\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            translation_file = fopen(argv[++i], "w+");
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
