#ifndef ELDPI_API_H
#define ELDPI_API_H

#include "dpi_thread.h"
#include "metadata_writer_thread.h"
#include "offsets_writer_thread.h"

extern char name_pattern[128];

typedef struct CapThreadContext CapThreadContext;

typedef enum { CAP_SRC_FILE = 0, CAP_SRC_IFACE = 1 } CapSrc;

typedef struct {
    CapSrc source_type;
    char *source_name;
    char *bpf;
    char *date_time;
} CapArgs;

typedef struct {
    CapThreadContext *cap_ctx;
    DPIThreadContext *dpi_threads;
    MetadataWriterThreadContext *metadata_writer_ctx;
} Contexts;

Contexts *start_analysis(CapArgs *args);
void stop_analysis(Contexts *ctx);
char* get_data_dir();
void wait_analysis(Contexts *ctx);
void destroy_analysis_context(Contexts *ctx);

#endif // ELDPI_API_H