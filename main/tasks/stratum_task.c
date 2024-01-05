#include "esp_log.h"
// #include "addr_from_stdin.h"
#include "bm1397.h"
#include "connect.h"
#include "global_state.h"
#include "lwip/dns.h"
#include "nvs_config.h"
#include "stratum_task.h"
#include "work_queue.h"
#include <esp_sntp.h>
#include <esp_tls.h>
#include <time.h>

#define PORT CONFIG_STRATUM_PORT
#define STRATUM_URL CONFIG_STRATUM_URL

#define STRATUM_PW CONFIG_STRATUM_PW
#define STRATUM_DIFFICULTY CONFIG_STRATUM_DIFFICULTY

static const char * TAG = "stratum_task";
static ip_addr_t ip_Addr;
static bool bDNSFound = false;

static StratumApiV1Message stratum_api_v1_message = {};

static SystemTaskModule SYSTEM_TASK_MODULE = {.stratum_difficulty = 8192};

void dns_found_cb(const char * name, const ip_addr_t * ipaddr, void * callback_arg)
{
    ip_Addr = *ipaddr;
    bDNSFound = true;
}

void stratum_task(void * pvParameters)
{
    GlobalState * GLOBAL_STATE = (GlobalState *) pvParameters;

    STRATUM_V1_initialize_buffer();
    char host_ip[20];
    int addr_family = 0;
    int ip_protocol = 0;

    char * stratum_url = nvs_config_get_string(NVS_CONFIG_STRATUM_URL, STRATUM_URL);
    uint16_t port = nvs_config_get_u16(NVS_CONFIG_STRATUM_PORT, PORT);

    // check to see if the STRATUM_URL is an ip address already
    if (inet_pton(AF_INET, stratum_url, &ip_Addr) == 1) {
        bDNSFound = true;
    } else {
        // it's a hostname. Lookup the ip address.
        IP_ADDR4(&ip_Addr, 0, 0, 0, 0);
        ESP_LOGI(TAG, "Get IP for URL: %s\n", stratum_url);
        dns_gethostbyname(stratum_url, &ip_Addr, dns_found_cb, NULL);
        while (!bDNSFound)
            ;
    }

    // make IP address string from ip_Addr
    snprintf(host_ip, sizeof(host_ip), "%d.%d.%d.%d", ip4_addr1(&ip_Addr.u_addr.ip4), ip4_addr2(&ip_Addr.u_addr.ip4),
             ip4_addr3(&ip_Addr.u_addr.ip4), ip4_addr4(&ip_Addr.u_addr.ip4));
    ESP_LOGI(TAG, "Connecting to: stratum+tcp://%s:%d (%s)\n", stratum_url, port, host_ip);
    free(stratum_url);

    while (1) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = inet_addr(host_ip);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;
        const char * cacert = "-----BEGIN CERTIFICATE-----\n"
                              "MIIFRTCCAy0CFFFxcvrekK6XbdDPEch5nazNtPM+MA0GCSqGSIb3DQEBCwUAMF8x\n"
                              "CzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
                              "cm5ldCBXaWRnaXRzIFB0eSBMdGQxGDAWBgNVBAMMD2F6dXJlLnJheWNuLnB1YjAe\n"
                              "Fw0yNDAxMDUwOTQ2NThaFw0yNTAxMDQwOTQ2NThaMF8xCzAJBgNVBAYTAkNOMRMw\n"
                              "EQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0\n"
                              "eSBMdGQxGDAWBgNVBAMMD2F6dXJlLnJheWNuLnB1YjCCAiIwDQYJKoZIhvcNAQEB\n"
                              "BQADggIPADCCAgoCggIBAKIGneApDpH/n56qlfbkVmllRV2A/WegX3GcRFgzkK95\n"
                              "/w+ieA/r2b8+VrP2Bo5d+GDRGQlNsT6mbtf++mGpHvsDsC1kW7Nq4DJW4v1GtUU0\n"
                              "4CMubRsI0Pr7tF3MW1ALfHjBrRwhBMaBgFQ75rEWkxT0LDz+ZOPo02kjEApuTEIb\n"
                              "COisy8ffkqO2hxoxks5ADG3AIrVdQthJLtrStegmSgsSSmXyqKstGVv3JTnnhTSn\n"
                              "xf47x33e95uNEIHd8J7Dt+pyGicBIn3T2mdao/u73Xf1BnBcKgmMWlxvfWY/V0gF\n"
                              "tG0rZJE1qJxPEBZ/JPcDozIEWSJeMaGWV4OHfqhXGXGG21OHLfGf1x2TaKC/VgQY\n"
                              "mYPMOwIMASbXeYPMGoAejsdyiS2TUQFa9h8tz6YEF7vpD7qmMwasLGEsIP9YIgi6\n"
                              "KH95xYmrU6LSBW4H1muCiMQ6CDKCigdhsLcdZ2QSwzLymr5nIXk+bukV6o8ZLDBw\n"
                              "w6HtF4HNypDuODMDcXqNL7sz4IFtE3MsY+KJek4dpWX+T+CPloncPC5xQ6VH5cqf\n"
                              "/rIpW3d4kXYtox4/WL2DgIXyKNPlWrjohlHVovvhiJOF0cLZU03hMQSxh8S2l38e\n"
                              "BtA+tls2zfgzSHhBdE/81XzKiv4+6w4z+reFUWUPek8dIeTwk9L/Ea/T0stqFBrl\n"
                              "AgMBAAEwDQYJKoZIhvcNAQELBQADggIBADj/pB4X134HgCFiv6dJVkAk/k+P9+8q\n"
                              "iXOtznt41CfF7n9bQF9Pm5zz6FCIZGbrW5jQXP36CWk0HI1KCKpx5/ay/KU9YSXM\n"
                              "VUukegj7X+y+15HfeUHdVdzPVjYn8jC2FIHQy172AJWXwFH1B4qFpabH0E2EOvDm\n"
                              "xeFNqRBwmBARmPl+U7z0TmHpKHh7M2P777/wvCkEPUU6LSERTudYw7ABduK1KdUr\n"
                              "XqqQbEUQ+aPSwjjgU0mmIZEruk5255SwxAu0zLurLF+Ol1Wig4e+VUgiItgkFi57\n"
                              "1OmI7GBFS64gq7+VZYvxqkbrDMaQpzP8URM71Em/sRuO8SWWPXpiTL25Xy5XssGA\n"
                              "Xfdh+YAWE6R21QCKfFjN7coUJnrVInQrswnaUf4DIjwWcQyARSTsGDLYoG0umJNt\n"
                              "Hzj5j3gbioLqVm0oxD8bXoUlJBT4e1499nFRBHlx+wXEh87lgWK1ia6sMLMqFNM6\n"
                              "luHvPelkXBcRLJX1kBNNWs7LtafyXra2dc6OMr+LEIhdmmXrGwWpvUqJC9AS7aV8\n"
                              "KAfgrrEiwVugtrx+Dij1cA6YivU7a8mI0G6A4f2g3pzWdWKqaLIWqs0PTZlYX46+\n"
                              "8A6X03KucLVy1R/LyC0Gq8GUUSAYgq87Yl0YSJ9L5jAgxSUJFoFyxKix/mA5WY20\n"
                              "JT/36mkeABZF\n"
                              "-----END CERTIFICATE-----"; // Set to your CA certificate if required

        // Create a TLS context
        esp_tls_cfg_t tls_cfg = {
            .cacert_buf = cacert, // Set to your CA certificate if required
            .cacert_bytes =,      // Set to the size of your CA certificate if required
        };
        esp_tls_t * tls = esp_tls_init();
        if (tls == NULL) {
            ESP_LOGE(TAG, "Failed to initialize TLS");
            esp_restart();
            break;
        }
        // Establish a TLS connection
        int ret = esp_tls_conn_new_sync(host_ip, port, AF_INET, &tls_cfg, tls);
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to establish TLS connection: %d", ret);
            esp_tls_cleanup(tls);
            esp_restart();
            break;
        }
        // Use the TLS connection for further communication
        GLOBAL_STATE->sock = esp_tls_get_fd(tls);

        // GLOBAL_STATE->sock = socket(addr_family, SOCK_STREAM, ip_protocol);

        if (GLOBAL_STATE->sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            esp_restart();
            break;
        }
        ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, port);

        // int err = connect(GLOBAL_STATE->sock, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in6));
        // if (err != 0) {
        //     ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
        //     esp_restart();
        //     break;
        // }

        STRATUM_V1_subscribe(GLOBAL_STATE->sock, &GLOBAL_STATE->extranonce_str, &GLOBAL_STATE->extranonce_2_len,
                             GLOBAL_STATE->asic_model);

        STRATUM_V1_configure_version_rolling(GLOBAL_STATE->sock);

        char * username = nvs_config_get_string(NVS_CONFIG_STRATUM_USER, STRATUM_USER);
        STRATUM_V1_authenticate(GLOBAL_STATE->sock, username);
        free(username);

        ESP_LOGI(TAG, "Extranonce: %s", GLOBAL_STATE->extranonce_str);
        ESP_LOGI(TAG, "Extranonce 2 length: %d", GLOBAL_STATE->extranonce_2_len);

        STRATUM_V1_suggest_difficulty(GLOBAL_STATE->sock, STRATUM_DIFFICULTY);

        while (1) {
            char * line = STRATUM_V1_receive_jsonrpc_line(GLOBAL_STATE->sock);
            ESP_LOGI(TAG, "rx: %s", line); // debug incoming stratum messages
            STRATUM_V1_parse(&stratum_api_v1_message, line);
            free(line);

            if (stratum_api_v1_message.method == MINING_NOTIFY) {
                SYSTEM_notify_new_ntime(&GLOBAL_STATE->SYSTEM_MODULE, stratum_api_v1_message.mining_notification->ntime);
                if (stratum_api_v1_message.should_abandon_work &&
                    (GLOBAL_STATE->stratum_queue.count > 0 || GLOBAL_STATE->ASIC_jobs_queue.count > 0)) {
                    ESP_LOGI(TAG, "abandoning work");

                    GLOBAL_STATE->abandon_work = 1;
                    queue_clear(&GLOBAL_STATE->stratum_queue);

                    pthread_mutex_lock(&GLOBAL_STATE->valid_jobs_lock);
                    ASIC_jobs_queue_clear(&GLOBAL_STATE->ASIC_jobs_queue);
                    for (int i = 0; i < 128; i = i + 4) {
                        GLOBAL_STATE->valid_jobs[i] = 0;
                    }
                    pthread_mutex_unlock(&GLOBAL_STATE->valid_jobs_lock);
                }
                if (GLOBAL_STATE->stratum_queue.count == QUEUE_SIZE) {
                    mining_notify * next_notify_json_str = (mining_notify *) queue_dequeue(&GLOBAL_STATE->stratum_queue);
                    STRATUM_V1_free_mining_notify(next_notify_json_str);
                }

                stratum_api_v1_message.mining_notification->difficulty = SYSTEM_TASK_MODULE.stratum_difficulty;
                queue_enqueue(&GLOBAL_STATE->stratum_queue, stratum_api_v1_message.mining_notification);
            } else if (stratum_api_v1_message.method == MINING_SET_DIFFICULTY) {
                if (stratum_api_v1_message.new_difficulty != SYSTEM_TASK_MODULE.stratum_difficulty) {
                    SYSTEM_TASK_MODULE.stratum_difficulty = stratum_api_v1_message.new_difficulty;
                    ESP_LOGI(TAG, "Set stratum difficulty: %ld", SYSTEM_TASK_MODULE.stratum_difficulty);
                }
            } else if (stratum_api_v1_message.method == MINING_SET_VERSION_MASK ||
                       stratum_api_v1_message.method == STRATUM_RESULT_VERSION_MASK) {
                // 1fffe000
                ESP_LOGI(TAG, "Set version mask: %08lx", stratum_api_v1_message.version_mask);
                GLOBAL_STATE->version_mask = stratum_api_v1_message.version_mask;
            } else if (stratum_api_v1_message.method == STRATUM_RESULT) {
                if (stratum_api_v1_message.response_success) {
                    ESP_LOGI(TAG, "message result accepted");
                    SYSTEM_notify_accepted_share(&GLOBAL_STATE->SYSTEM_MODULE);
                } else {
                    ESP_LOGE(TAG, "message result rejected");
                    SYSTEM_notify_rejected_share(&GLOBAL_STATE->SYSTEM_MODULE);
                }
            }
        }

        if (GLOBAL_STATE->sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(GLOBAL_STATE->sock, 0);
            close(GLOBAL_STATE->sock);
        }
    }
    vTaskDelete(NULL);
}
