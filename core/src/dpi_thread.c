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
#include "matadata_writer_thread.h"
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
int init_ndpi_detection(NDPI_ThreadInfo *info) {
    // Инициализируем модуль обнаружения (без глобального контекста, NULL)
    info->ndpi_struct = ndpi_init_detection_module(NULL);
    if(info->ndpi_struct == NULL) {
        fprintf(stderr, "nDPI: не удалось инициализировать структуру обнаружения\n");
        return -1;
    }
    // Включаем распознавание всех поддерживаемых протоколов
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(info->ndpi_struct, &all);
    // Завершаем инициализацию (загружаем все сигнатуры)
    if(ndpi_finalize_initialization(info->ndpi_struct) != 0) {
        fprintf(stderr, "nDPI: ошибка finalize_initialization\n");
        return -1;
    }
    // Инициализируем хеш-таблицу потоков (изначально все бакеты пустые)
    memset(info->flow_table, 0, sizeof(info->flow_table));

    return 0;
}

// Освобождение ресурсов nDPI для потока (очистка памяти)
void destroy_dpi_thread_context(DPIThreadContext *dpi_ctx) {
    if (dpi_ctx == NULL) {
        return;
    }

    // Если структура ndpi_info была инициализирована, освобождаем всё внутри неё
    if (dpi_ctx->ndpi_info) {
        for (int i = 0; i < FLOW_HASH_SIZE; ++i) {
            FlowNode *node = dpi_ctx->ndpi_info->flow_table[i];
            while (node) {
                FlowNode *next = node->next;

                if (node->ndpi_flow) {
                    ndpi_flow_free(node->ndpi_flow);   
                    free(node->ndpi_flow); 
                    node->ndpi_flow = NULL;
                }

                free(node);
                node = next;
            }
            dpi_ctx->ndpi_info->flow_table[i] = NULL;
        }

        if (dpi_ctx->ndpi_info->ndpi_struct) {
            ndpi_exit_detection_module(dpi_ctx->ndpi_info->ndpi_struct);
            dpi_ctx->ndpi_info->ndpi_struct = NULL;
        }
        dpi_ctx->ndpi_info = NULL;
    }
    free(dpi_ctx);
}

// Функция обработчика пакетов (потоковая функция)
void *dpi_thread(void *arg) {
    DPIThreadContext *dpi_ctx = (DPIThreadContext*) arg;

    while(1) {
        PacketItem* item = (PacketItem*) queue_pop(dpi_ctx->packet_queue);
        if(item == NULL) {
            break;
        }
        
        // Выполняем анализ пакета с помощью nDPI
        // Вычисляем смещение до L3
        uint16_t ethertype = 0;
        unsigned int offset = 14;
        if(item->header.caplen >= 14) {
            ethertype = ntohs(*(uint16_t*)(item->data + 12));
            if(ethertype == 0x8100 || ethertype == 0x88A8) {
                if(item->header.caplen >= 18) {
                    ethertype = ntohs(*(uint16_t*)(item->data + 16));
                    offset = 18;
                    if(ethertype == 0x8100 || ethertype == 0x88A8) {
                        if(item->header.caplen >= 22) {
                            ethertype = ntohs(*(uint16_t*)(item->data + 20));
                            offset = 22;
                        }
                    }
                }
            }
        }
        // Подготовим структуру ключа потока для поиска/добавления в хеш-таблицу
        FlowKey key;
        memset(&key, 0, sizeof(key));
        // Указатель на начало L3 (IP) данных
        const uint8_t *l3_ptr = NULL;
        uint32_t l3_len = 0;
        if(ethertype == 0x0800 && item->header.caplen >= offset + sizeof(struct iphdr)) {
            // IPv4 пакет
            key.ip_version = 4;
            struct iphdr *ip = (struct iphdr*)(item->data + offset);
            if(ip->ihl < 5) {
                // Пропускаем некорректный IP
                free(item);
                continue;
            }
            uint32_t ip_hdr_len = ip->ihl * 4;
            if(item->header.caplen < offset + ip_hdr_len) {
                free(item);
                continue;
            }
            key.ip.v4.src_ip = ip->saddr;
            key.ip.v4.dst_ip = ip->daddr;
            key.proto = ip->protocol;
            // Задаем порты (для ключа потока тоже симметрично не обязательно, т.к. уникальный поток и так идентифицируется 5-ю составляющими)
            if(ip->protocol == IPPROTO_TCP && item->header.caplen >= offset + ip_hdr_len + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr*)(item->data + offset + ip_hdr_len);
                key.src_port = ntohs(tcp->source);
                key.dst_port = ntohs(tcp->dest);
            } else if(ip->protocol == IPPROTO_UDP && item->header.caplen >= offset + ip_hdr_len + sizeof(struct udphdr)) {
                struct udphdr *udp = (struct udphdr*)(item->data + offset + ip_hdr_len);
                key.src_port = ntohs(udp->source);
                key.dst_port = ntohs(udp->dest);
            } else {
                key.src_port = key.dst_port = 0;
            }
            l3_ptr = item->data + offset;
            l3_len = item->header.caplen - offset;
        } else if(ethertype == 0x86DD && item->header.caplen >= offset + sizeof(struct ip6_hdr)) {
            // IPv6 пакет
            key.ip_version = 6;
            struct ip6_hdr *ip6 = (struct ip6_hdr*)(item->data + offset);
            if(item->header.caplen < offset + sizeof(struct ip6_hdr)) {
                free(item);
                continue;
            }
            // Копируем IPv6 адреса в ключ
            memcpy(key.ip.v6.src_ip, &ip6->ip6_src, 16);
            memcpy(key.ip.v6.dst_ip, &ip6->ip6_dst, 16);
            key.proto = ip6->ip6_nxt;
            // Порты для TCP/UDP (если без расширенных заголовков)
            if(key.proto == IPPROTO_TCP && item->header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                struct tcphdr *tcp = (struct tcphdr*)(item->data + offset + sizeof(struct ip6_hdr));
                key.src_port = ntohs(tcp->source);
                key.dst_port = ntohs(tcp->dest);
            } else if(key.proto == IPPROTO_UDP && item->header.caplen >= offset + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                struct udphdr *udp = (struct udphdr*)(item->data + offset + sizeof(struct ip6_hdr));
                key.src_port = ntohs(udp->source);
                key.dst_port = ntohs(udp->dest);
            } else {
                key.src_port = key.dst_port = 0;
            }
            l3_ptr = item->data + offset;
            l3_len = item->header.caplen - offset;
        } else {
            // Неподдерживаемый L3 (например, ARP или слишком короткий) - пропускаем
            free(item);
            continue;
        }

        // Ищем или создаем flow в хеш-таблице потоков для данного ключа
        uint32_t index = flow_hash(&key);
        FlowNode *node = dpi_ctx->ndpi_info->flow_table[index];
        FlowNode *found = NULL;
        while(node != NULL) {
            if(flow_key_equal(&node->key, &key)) {
                found = node;
                break;
            }
            node = node->next;
        }
        if(found == NULL) {
            // Не найден существующий поток, создаём новый
            FlowNode *new_node = (FlowNode*)malloc(sizeof(FlowNode));
            if(new_node == NULL) {
                fprintf(stderr, "Поток %d: недостаточно памяти для FlowNode\n", dpi_ctx->thread_number);
                free(item);
                continue;
            }
            new_node->key = key;
            new_node->next = dpi_ctx->ndpi_info->flow_table[index];
            // Выделяем память под структуру ndpi_flow_struct
            new_node->ndpi_flow = (struct ndpi_flow_struct*)calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
            if(new_node->ndpi_flow == NULL) {
                fprintf(stderr, "Поток %d: недостаточно памяти для ndpi_flow_struct\n", dpi_ctx->thread_number);
                free(new_node);
                free(item);
                continue;
            }
            // Вставляем новый узел в таблицу
            dpi_ctx->ndpi_info->flow_table[index] = new_node;
            found = new_node;
        }
        // Подготовим информацию о направлении потока для nDPI (необязательно для базового определения)
        struct ndpi_flow_struct *flow = found->ndpi_flow;
        // Время пакета в миллисекундах (на основе метки времени pcap)
        uint64_t time_ms = (uint64_t)item->header.ts.tv_sec * 1000 + item->header.ts.tv_usec / 1000;
        // Запускаем определение протокола для пакета
        ndpi_protocol detected_protocol = ndpi_detection_process_packet(
            dpi_ctx->ndpi_info->ndpi_struct,
            flow,
            (uint8_t*)l3_ptr,
            l3_len,
            time_ms,
            NULL // входная информация о направлении не используется в базовой реализации
        );
        // Проверяем, был ли протокол обнаружен
        const char *proto_name = "Unknown";
        if(ndpi_is_protocol_detected(detected_protocol) && 
           (detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
            // Получаем имя протокола высшего уровня (приложения) или, если неизвестен, имя мастер-протокола
            if(detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
                proto_name = ndpi_get_proto_name(dpi_ctx->ndpi_info->ndpi_struct, detected_protocol.proto.app_protocol);
            } else {
                proto_name = ndpi_get_proto_name(dpi_ctx->ndpi_info->ndpi_struct, detected_protocol.proto.master_protocol);
            }
        }

        

        // Создаем запись для лога
        MetadataItem *metadata_entry = calloc(1, sizeof(*metadata_entry));
        if(!metadata_entry) {
            fprintf(stderr, "Поток %d: недостаточно памяти\n", dpi_ctx->thread_number);
            free(item);
            continue;
        }
        PacketItem *offset_entry = item;
        queue_push(dpi_ctx->offsets_queue, offset_entry);

        metadata_entry->timestamp_ms = time_ms;
        metadata_entry->session_id = index;
        metadata_entry->ip_version = key.ip_version;
        if(metadata_entry->ip_version == 4) {
            metadata_entry->ip_src.v4 = *(struct in_addr*)&key.ip.v4.src_ip;
            metadata_entry->ip_dst.v4 = *(struct in_addr*)&key.ip.v4.dst_ip;
        } else if(metadata_entry->ip_version == 6) {
            // struct in6_addr уже содержит 16 байт, копируем напрямую
            memcpy(&metadata_entry->ip_src.v6, key.ip.v6.src_ip, 16);
            memcpy(&metadata_entry->ip_dst.v6, key.ip.v6.dst_ip, 16);
        } else {
            // На случай непредвиденного
            memset(&metadata_entry->ip_src, 0, sizeof(metadata_entry->ip_src));
            memset(&metadata_entry->ip_dst, 0, sizeof(metadata_entry->ip_dst));
        }
        metadata_entry->src_port = key.src_port;
        metadata_entry->dst_port = key.dst_port;
        // Копируем имя протокола в структуру (оно может быть константой в nDPI, но скопируем для независимости)
        strncpy(metadata_entry->protocol_name, proto_name, sizeof(metadata_entry->protocol_name) - 1);
        metadata_entry->protocol_name[sizeof(metadata_entry->protocol_name) - 1] = '\0';
        // Добавляем запись в список результатов потока
        queue_push(dpi_ctx->metadata_queue, &metadata_entry);
    }

    decrease_producer_count(dpi_ctx->metadata_queue);
    decrease_producer_count(dpi_ctx->offsets_queue);
    return NULL;
}
