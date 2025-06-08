#include <stdio.h>
#include <time.h>

#include "eldpi_api.h"


int parse_args(int argc, char **argv, CapArgs *opt, char *date_time) {
    memset(opt, 0, sizeof(*opt));
    opt->source_type = -1;

    for(int i = 1; i < argc; ++i) {
        if(strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if(++i >= argc) { fprintf(stderr, "-f требует аргумент\n"); return -1; }
            opt->source_type = CAP_SRC_FILE;
            opt->source_name = argv[i];
        } else if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if(++i >= argc) { fprintf(stderr, "-i требует аргумент\n"); return -1; }
            opt->source_type = CAP_SRC_IFACE;
            opt->source_name = argv[i];
        } else if(strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bpf") == 0) {
            if(++i >= argc) { fprintf(stderr, "-b требует аргумент\n"); return -1; }
            opt->bpf = argv[i];
        } else {
            fprintf(stderr, "Неизвестный параметр: %s\n", argv[i]);
            return -1;
        }
    }
    if(opt->source_type == -1) {
        fprintf(stderr, "Обязателен -f <pcap> или -i <iface>\n");
        return -1;
    }

    time_t now;
    struct tm *tm_info;
    time(&now);
    tm_info = localtime(&now);
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", tm_info);

    opt->date_time = date_time;

    return 0;
}

int main(int argc, char *argv[]){
    CapArgs *params = calloc(1, sizeof(CapArgs));

    char *date_time = calloc(20, sizeof(char));

    if (parse_args(argc, argv, params, date_time) != 0) {
        free(date_time);
        free(params);
        return 1;
    }
    Contexts *ctx = start_analysis(params);
    if(ctx == NULL) {
        fprintf(stderr, "Ошибка при запуске анализа\n");
        free(date_time);
        free(params);
        return 1;
    }
    if(params->source_type == CAP_SRC_IFACE){
        char input;
        printf("Введите 's' для остановки анализа: ");
        while ((input = getchar()) != 's') {
            if (input != '\n') {
                printf("Неверный ввод. Пожалуйста, введите 's': ");
            }
        }
        stop_analysis(ctx);
    } else wait_analysis(ctx);
    destroy_analysis_context(ctx);
    free(date_time);
    free(params);
    return 0;
}