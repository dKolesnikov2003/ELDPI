#include <stdio.h>

#include "eldpi_api.h"


int main(void){
    printf("Hello, World!\n");
    CapArgs args = {
        .source_type = CAP_SRC_FILE,
        .source_name = "/home/dima/icmp.pcap",
        .bpf = "",
        .date_time = "2023-10-01 12:00:00"
    };
    // CapArgs args = {
    //     .source_type = CAP_SRC_IFACE,
    //     .source_name = "enp3s0",
    //     .bpf = "tcp",
    //     .date_time = "2023-10-01 12:00:00"
    // };
    Contexts *ctx = start_analysis(&args);
    if(ctx == NULL) {
        fprintf(stderr, "Ошибка при запуске анализа\n");
        return 1;
    }
    // char input;
    // printf("Введите 's' для остановки анализа: ");
    // while ((input = getchar()) != 's') {
    //     if (input != '\n') { // Игнорируем перевод строки
    //         printf("Неверный ввод. Пожалуйста, введите 's': ");
    //     }
    // }
    // stop_analysis(ctx);
    wait_analysis(ctx);
    destroy_analysis_context(ctx);

    printf("Hello, World!!\n");
    return 0;
}