#ifndef ELDPI_API_H
#define ELDPI_API_H

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CapSrc;

typedef struct {
    CapSrc source_type;
    char *source_name;
    char *bpf;
    char *date_time;
} CapArgs;

typedef struct CapThreadContext CapThreadContext;

CapThreadContext *start_analysis(CapArgs *args);
void stop_analysis(CapThreadContext *ctx);
void destroy_analysis_ctx(CapThreadContext *ctx);

#endif // ELDPI_API_H