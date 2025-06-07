#include "dpi_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ndpi/ndpi_api.h>

#include "common.h"
#include "queue.h"
#include "cap_thread.h"
#include "metadata_writer_thread.h"
#include "offsets_writer_thread.h"


// Внутренняя структура для узла хеш-таблицы потоков (flows)
typedef struct FlowNode {
    FlowKey key;
    struct ndpi_flow_struct *ndpi_flow;
    struct FlowNode *next;
} FlowNode;

// Функция вычисления хеша по ключу потока (FlowKey)
static inline uint32_t flow_hash(const FlowKey *key) {
    uint64_t hash64 = 0;
    if(key->ip_version == 4) {
        // Для IPv4: суммируем адреса, порты и протокол
        hash64 = key->ip.v4.src_ip;
        hash64 += key->ip.v4.dst_ip;
        hash64 += (uint64_t)key->src_port << 16 | key->dst_port;
        hash64 += key->proto;
    } else if(key->ip_version == 6) {
        // Для IPv6: суммируем части адресов, порты и протокол
        hash64 = key->ip.v6.src_ip[0] ^ key->ip.v6.src_ip[1];
        hash64 ^= key->ip.v6.dst_ip[0] ^ key->ip.v6.dst_ip[1];
        hash64 += ((uint64_t)key->src_port << 16) | key->dst_port;
        hash64 += key->proto;
    }
    // Преобразуем 64-битный хеш в 32-битный индекс
    uint32_t hash32 = (uint32_t)(hash64 ^ (hash64 >> 32));
    return hash32 & (FLOW_HASH_SIZE - 1);
}

// Функция сравнения ключей потоков (для поиска в цепочке хеш-таблицы)
static inline int flow_key_equal(const FlowKey *a, const FlowKey *b) {
    if(a->ip_version != b->ip_version) return 0;
    if(a->src_port != b->src_port || a->dst_port != b->dst_port || a->proto != b->proto) return 0;
    if(a->ip_version == 4) {
        return (a->ip.v4.src_ip == b->ip.v4.src_ip && a->ip.v4.dst_ip == b->ip.v4.dst_ip);
    } else if(a->ip_version == 6) {
        return (a->ip.v6.src_ip[0] == b->ip.v6.src_ip[0] && 
                a->ip.v6.src_ip[1] == b->ip.v6.src_ip[1] &&
                a->ip.v6.dst_ip[0] == b->ip.v6.dst_ip[0] &&
                a->ip.v6.dst_ip[1] == b->ip.v6.dst_ip[1]);
    }
    return 0;
}

// Инициализация nDPI для потока
int dpi_thread_init(int thread_number, DPIThreadContext *dpi_ctx, GenericQueue *packet_queue, GenericQueue *metadata_queue, GenericQueue *offsets_queue) {
    dpi_ctx->thread_number = thread_number;
    dpi_ctx->packet_queue = packet_queue;
    dpi_ctx->metadata_queue = metadata_queue;
    dpi_ctx->offsets_queue = offsets_queue;
    dpi_ctx->ndpi_info = calloc(1, sizeof(NDPI_ThreadInfo));
    if (dpi_ctx->ndpi_info == NULL) {
        fprintf(stderr, "Ошибка выделения памяти под NDPI_ThreadInfo\n");
        return 1;
    }
    dpi_ctx->ndpi_info->ndpi_struct = ndpi_init_detection_module(NULL);
    if(dpi_ctx->ndpi_info->ndpi_struct == NULL) {
        fprintf(stderr, "nDPI: не удалось инициализировать структуру обнаружения\n");
        return 1;
    }
    
    // Включаем распознавание всех поддерживаемых протоколов
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(dpi_ctx->ndpi_info->ndpi_struct, &all);
    // Завершаем инициализацию (загружаем все сигнатуры)
    if(ndpi_finalize_initialization(dpi_ctx->ndpi_info->ndpi_struct) != 0) {
        fprintf(stderr, "nDPI: ошибка finalize_initialization\n");
        return 1;
    }
    // Инициализируем хеш-таблицу потоков (изначально все бакеты пустые)
    memset(dpi_ctx->ndpi_info->flow_table, 0, sizeof(dpi_ctx->ndpi_info->flow_table));

    increase_producer_count(dpi_ctx->metadata_queue);
    increase_producer_count(dpi_ctx->offsets_queue);

    return 0;
}

/// Освобождение ресурсов nDPI для потока (очистка памяти)
void destroy_dpi_context(DPIThreadContext *dpi_ctx) {
    if (dpi_ctx == NULL) {
        return;
    }

    if (dpi_ctx->ndpi_info != NULL) {
        for (int i = 0; i < FLOW_HASH_SIZE; ++i) {
            FlowNode *node = dpi_ctx->ndpi_info->flow_table[i];
            while (node != NULL) {
                FlowNode *next = node->next;
                if (node->ndpi_flow != NULL) {
                    ndpi_flow_free(node->ndpi_flow);
                    node->ndpi_flow = NULL;
                }

                free(node);
                node = next;
            }
            dpi_ctx->ndpi_info->flow_table[i] = NULL;
        }

        if (dpi_ctx->ndpi_info->ndpi_struct != NULL) {
            ndpi_exit_detection_module(dpi_ctx->ndpi_info->ndpi_struct);
            dpi_ctx->ndpi_info->ndpi_struct = NULL;
        }

        free(dpi_ctx->ndpi_info);
        dpi_ctx->ndpi_info = NULL;
    }
    if (dpi_ctx->packet_queue != NULL) {
        queue_destroy(dpi_ctx->packet_queue);
        // dpi_ctx->packet_queue = NULL;
    }
}


void *dpi_thread(void *arg)
{
    DPIThreadContext *dpi_ctx = (DPIThreadContext *)arg;

    for (;;)
    {   
        PacketItem *item = (PacketItem *)queue_pop(dpi_ctx->packet_queue);
        if (item == NULL) {
            break;
        }
        uint16_t ethertype  = 0;
        unsigned int offset = 14;
        if (item->header.caplen >= 14)
            memcpy(&ethertype, item->data + 12, sizeof ethertype);
        ethertype = ntohs(ethertype);

        for (int vlan_layers = 0;
             (ethertype == 0x8100 || ethertype == 0x88A8) && vlan_layers < 2;
             ++vlan_layers)
        {
            if (item->header.caplen < offset + 4)
                break;
            memcpy(&ethertype, item->data + offset + 2, sizeof ethertype);
            ethertype = ntohs(ethertype);
            offset   += 4;
        }

        FlowKey   key;
        memset(&key, 0, sizeof key);
        const u_char *l3_ptr = NULL;
        uint32_t     l3_len  = 0;

        if (ethertype == 0x0800 && item->header.caplen >= offset + sizeof(struct iphdr))
        {
            key.ip_version = 4;

            struct iphdr ip;
            memcpy(&ip, item->data + offset, sizeof ip);

            if (ip.ihl < 5)
            {
                free(item);
                continue;
            }
            uint32_t ip_hdr_len = ip.ihl * 4;
            if (item->header.caplen < offset + ip_hdr_len)
            {
                free(item);
                continue;
            }

            key.ip.v4.src_ip = ip.saddr;
            key.ip.v4.dst_ip = ip.daddr;
            key.proto        = ip.protocol;

            /* --- TCP/UDP порты --- */
            if (key.proto == IPPROTO_TCP &&
                item->header.caplen >= offset + ip_hdr_len + sizeof(struct tcphdr))
            {
                struct tcphdr tcp;
                memcpy(&tcp, item->data + offset + ip_hdr_len, sizeof tcp);
                key.src_port = ntohs(tcp.source);
                key.dst_port = ntohs(tcp.dest);
            }
            else if (key.proto == IPPROTO_UDP &&
                     item->header.caplen >= offset + ip_hdr_len + sizeof(struct udphdr))
            {
                struct udphdr udp;
                memcpy(&udp, item->data + offset + ip_hdr_len, sizeof udp);
                key.src_port = ntohs(udp.source);
                key.dst_port = ntohs(udp.dest);
            }
            else
            {
                key.src_port = key.dst_port = 0;
            }

            l3_ptr = item->data + offset;
            l3_len = item->header.caplen - offset;
        }
        else if (ethertype == 0x86DD &&
                 item->header.caplen >= offset + sizeof(struct ip6_hdr))
        {
            key.ip_version = 6;

            struct ip6_hdr ip6;
            memcpy(&ip6, item->data + offset, sizeof ip6);

            memcpy(key.ip.v6.src_ip, &ip6.ip6_src, 16);
            memcpy(key.ip.v6.dst_ip, &ip6.ip6_dst, 16);
            key.proto = ip6.ip6_nxt;

            if (key.proto == IPPROTO_TCP &&
                item->header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
            {
                struct tcphdr tcp;
                memcpy(&tcp, item->data + offset + sizeof(struct ip6_hdr), sizeof tcp);
                key.src_port = ntohs(tcp.source);
                key.dst_port = ntohs(tcp.dest);
            }
            else if (key.proto == IPPROTO_UDP &&
                     item->header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct udphdr))
            {
                struct udphdr udp;
                memcpy(&udp, item->data + offset + sizeof(struct ip6_hdr), sizeof udp);
                key.src_port = ntohs(udp.source);
                key.dst_port = ntohs(udp.dest);
            }
            else
            {
                key.src_port = key.dst_port = 0;
            }

            l3_ptr = item->data + offset;
            l3_len = item->header.caplen - offset;
        }
        else
        {
            free(item);
            continue;
        }

        uint32_t  index = flow_hash(&key);
        FlowNode *node  = dpi_ctx->ndpi_info->flow_table[index];
        while (node && !flow_key_equal(&node->key, &key))
            node = node->next;

        if (node == NULL)
        {
            node = calloc(1, sizeof *node);
            if (!node)
            {
                fprintf(stderr, "Поток %d: недостаточно памяти (FlowNode)\n",
                        dpi_ctx->thread_number);
                free(item);
                continue;
            }
            node->key       = key;
            node->ndpi_flow = calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
            if (!node->ndpi_flow)
            {
                fprintf(stderr, "Поток %d: недостаточно памяти (ndpi_flow)\n",
                        dpi_ctx->thread_number);
                free(node);
                free(item);
                continue;
            }
            node->next = dpi_ctx->ndpi_info->flow_table[index];
            dpi_ctx->ndpi_info->flow_table[index] = node;
        }

        uint64_t   ts_ms   = (uint64_t)item->header.ts.tv_sec * 1000 +
                             item->header.ts.tv_usec / 1000;
        ndpi_protocol proto =
            ndpi_detection_process_packet(dpi_ctx->ndpi_info->ndpi_struct,
                                          node->ndpi_flow,
                                          (uint8_t *)l3_ptr, l3_len,
                                          ts_ms, NULL);

        const char *proto_name = "Unknown";
        if (ndpi_is_protocol_detected(proto) &&
            (proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
             proto.proto.app_protocol    != NDPI_PROTOCOL_UNKNOWN))
        {
            proto_name = ndpi_get_proto_name(
                dpi_ctx->ndpi_info->ndpi_struct,
                (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
                    ? proto.proto.app_protocol
                    : proto.proto.master_protocol);
        }

        OffsetItem *offs_item = calloc(1, sizeof(OffsetItem));
        if (!offs_item) {
            fprintf(stderr, "Поток %d: недостаточно памяти (OffsetItem)\n",
                    dpi_ctx->thread_number);
            free(item);
            continue;
        }

        MetadataItem *meta = calloc(1, sizeof(MetadataItem));
        if (!meta) {
            fprintf(stderr, "Поток %d: недостаточно памяти (MetadataItem)\n",
                    dpi_ctx->thread_number);
            free(item);
            continue;
        }

        offs_item->timestamp_ms = ts_ms;
        offs_item->packet       = item;
        queue_push(dpi_ctx->offsets_queue, offs_item);

        meta->timestamp_ms  = ts_ms;
        meta->session_id    = index;
        meta->ip_version    = key.ip_version;
        if (key.ip_version == 4)
        {
            meta->ip_src.v4 = *(struct in_addr *)&key.ip.v4.src_ip;
            meta->ip_dst.v4 = *(struct in_addr *)&key.ip.v4.dst_ip;
        }
        else
        {
            memcpy(&meta->ip_src.v6, key.ip.v6.src_ip, 16);
            memcpy(&meta->ip_dst.v6, key.ip.v6.dst_ip, 16);
        }
        meta->src_port = key.src_port;
        meta->dst_port = key.dst_port;
        strncpy(meta->protocol_name, proto_name, sizeof(meta->protocol_name) - 1);           

        queue_push(dpi_ctx->metadata_queue, meta);

    }
    decrease_producer_count(dpi_ctx->metadata_queue);
    decrease_producer_count(dpi_ctx->offsets_queue);
    fprintf(stdout, "Поток анализа №%d завершён успешно\n", ++dpi_ctx->thread_number);
    pthread_exit(NULL);
}