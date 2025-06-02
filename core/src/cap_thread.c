#include "cap_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h> 
#include <netinet/udp.h>

#include <pcap.h>

#include "common.h"
#include "queue.h"


CapThreadContext *cap_thread_init(pthread_t tid, CapArgs *args, GenericQueue *queues) {
    if (!args || !queues) {
        fprintf(stderr, "Отсутствуют параметры захвата\n");
        return NULL;
    }

    CapThreadContext *opts = calloc(1, sizeof(*opts));
    if (!opts) {
        perror("Ошибка выделения памяти для параметров потока захвата");
        return NULL;
    }

    opts->tid = tid;
    opts->pcap_handle = NULL;
    opts->cap_args = args;
    opts->queues = queues;
    
    // Инициализация очередей
    for(int i = 0; i < THREAD_COUNT; i++) {
        increase_producer_count(&opts->queues[i]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if(opts->cap_args->source_type == CAP_SRC_FILE) {
        opts->pcap_handle = pcap_open_offline(opts->cap_args->source_name, errbuf);
    } else if(opts->cap_args->source_type == CAP_SRC_IFACE) {
        opts->pcap_handle = pcap_open_live(opts->cap_args->source_name, 65535, 1, 1000, errbuf);
        if(opts->cap_args->bpf && opts->pcap_handle) {
            struct bpf_program prog;
            if(pcap_compile(opts->pcap_handle, &prog, opts->cap_args->bpf, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
               pcap_setfilter(opts->pcap_handle, &prog) == -1) {
                fprintf(stderr, "BPF ошибка: %s\n", pcap_geterr(opts->pcap_handle));
            }
            pcap_freecode(&prog);
        }
    }
    if (!opts->pcap_handle) {               
        fprintf(stderr, "Ошибка pcap_open_*: %s\n", errbuf);
        for (int i = 0; i < THREAD_COUNT; i++)
            decrease_producer_count(&opts->queues[i]);
        free(opts);
        return NULL;
    }
    if(opts->cap_args->source_type == CAP_SRC_FILE && !access(opts->cap_args->source_name, F_OK)) {
        fprintf(stdout, "Захват из файла: %s\n", opts->cap_args->source_name);
    } else if(opts->cap_args->source_type == CAP_SRC_IFACE && if_nametoindex(opts->cap_args->source_name)) {
        fprintf(stdout, "Захват с интерфейса: %s\n", opts->cap_args->source_name);
    } 

    return opts;
}

int select_thread_for_packet(const unsigned char *packet, uint32_t caplen);

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    CapThreadContext *opts = (CapThreadContext *)user;

    PacketItem *item = malloc(sizeof(PacketItem) + header->caplen);
    if (item == NULL) {
        fprintf(stderr, "Ошибка при попытке копирования очередного пакета\n");
        return;
    }

    item->header = *header;
    memcpy(item->data, pkt_data, header->caplen);

    int thread_number = select_thread_for_packet(item->data, header->caplen);

    printf("Пакет захвачен в потоке %d, длина: %u\n", thread_number, header->caplen);

    queue_push(&opts->queues[thread_number], item);
}

void *cap_thread(void *args) {
    
    CapThreadContext *opts = (CapThreadContext *)args;
    int status = pcap_loop(opts->pcap_handle, -1, packet_handler, (unsigned char *)opts);    

    if(status == -1) {
        fprintf(stderr, "Ошибка при захвате: %s\n", pcap_geterr(opts->pcap_handle));
    } else {
        fprintf(stdout, "Захват завершён успешно\n");
    }

    for(int i = 0; i < THREAD_COUNT; i++) {
        decrease_producer_count(&opts->queues[i]);
    }
    pcap_close(opts->pcap_handle);
    pthread_exit(NULL);   
}

int select_thread_for_packet(const unsigned char *packet, uint32_t caplen) {
    // Анализируем заголовок Ethernet
    if (caplen < 14) {
        return 0;
    }
    uint16_t ethertype;
    memcpy(&ethertype, packet + 12, sizeof ethertype);
    ethertype = ntohs(ethertype);
    unsigned int offset = 14;

    // VLAN (802.1Q и QinQ)
    if (ethertype == 0x8100 || ethertype == 0x88A8) {
        if (caplen < 18) {
            return 0;
        }
        memcpy(&ethertype, packet + 16, sizeof ethertype);
        ethertype = ntohs(ethertype);
        offset = 18;
        if (ethertype == 0x8100 || ethertype == 0x88A8) {
            if (caplen < 22) {
                return 0;
            }
            memcpy(&ethertype, packet + 20, sizeof ethertype);
            ethertype = ntohs(ethertype);
            offset = 22;
        }
    }

    // IPv4
    if (ethertype == 0x0800 && caplen >= offset + sizeof(struct iphdr)) {
        struct iphdr ip;
        memcpy(&ip, packet + offset, sizeof ip);
        if (ip.ihl < 5) {
            return 0;
        }
        uint32_t ip_hdr_len = ip.ihl * 4;
        if (caplen < offset + ip_hdr_len) {
            return 0;
        }
        uint32_t src_ip = ip.saddr;
        uint32_t dst_ip = ip.daddr;
        uint8_t proto = ip.protocol;
        uint16_t src_port = 0, dst_port = 0;

        if (proto == IPPROTO_TCP && caplen >= offset + ip_hdr_len + sizeof(struct tcphdr)) {
            struct tcphdr tcp;
            memcpy(&tcp, packet + offset + ip_hdr_len, sizeof tcp);
            src_port = ntohs(tcp.source);
            dst_port = ntohs(tcp.dest);
        } else if (proto == IPPROTO_UDP && caplen >= offset + ip_hdr_len + sizeof(struct udphdr)) {
            struct udphdr udp;
            memcpy(&udp, packet + offset + ip_hdr_len, sizeof udp);
            src_port = ntohs(udp.source);
            dst_port = ntohs(udp.dest);
        }

        uint32_t min_ip = src_ip < dst_ip ? src_ip : dst_ip;
        uint32_t max_port = src_port > dst_port ? src_port : dst_port;
        uint64_t key = min_ip;
        key += proto;
        key += max_port;
        int thread = key % THREAD_COUNT;
        return thread;
    }
    // IPv6
    else if (ethertype == 0x86DD && caplen >= offset + sizeof(struct ip6_hdr)) {
        struct ip6_hdr ip6;
        memcpy(&ip6, packet + offset, sizeof ip6);

        uint64_t src_ip6[2] = {0,0}, dst_ip6[2] = {0,0};
        memcpy(src_ip6, &ip6.ip6_src, 16);
        memcpy(dst_ip6, &ip6.ip6_dst, 16);
        uint8_t proto = ip6.ip6_nxt;
        uint16_t src_port = 0, dst_port = 0;
        size_t l4_offset = offset + sizeof(struct ip6_hdr);

        if (proto == IPPROTO_TCP && caplen >= l4_offset + sizeof(struct tcphdr)) {
            struct tcphdr tcp;
            memcpy(&tcp, packet + l4_offset, sizeof tcp);
            src_port = ntohs(tcp.source);
            dst_port = ntohs(tcp.dest);
        } else if (proto == IPPROTO_UDP && caplen >= l4_offset + sizeof(struct udphdr)) {
            struct udphdr udp;
            memcpy(&udp, packet + l4_offset, sizeof udp);
            src_port = ntohs(udp.source);
            dst_port = ntohs(udp.dest);
        }

        int use_src = memcmp(src_ip6, dst_ip6, 16) < 0 ? 1 : 0;
        uint64_t min_addr_sum = use_src ? (src_ip6[0] + src_ip6[1]) : (dst_ip6[0] + dst_ip6[1]);
        uint16_t max_port = src_port > dst_port ? src_port : dst_port;
        uint64_t key = min_addr_sum;
        key += proto;
        key += max_port;
        int thread = key % THREAD_COUNT;
        return thread;
    }
    // Всё остальное — поток 0
    else {
        return 0;
    }
}
