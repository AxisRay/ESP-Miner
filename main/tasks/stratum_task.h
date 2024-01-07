#ifndef STRATUM_TASK_H_
#define STRATUM_TASK_H_

typedef struct
{
    uint32_t stratum_difficulty;
} SystemTaskModule;

int stratum_tcp_connect(stratum_socket * socket, char * host_ip, uint16_t port);
int stratum_tls_connect(stratum_socket * socket, char * hostname, uint16_t port, esp_tls_cfg_t * cfg);
void stratum_task(void * pvParameters);

#endif