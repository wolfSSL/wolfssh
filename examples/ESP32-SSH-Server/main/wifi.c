/* wifi.c
 *
 * Copyright (C) 2014-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "wifi.h"

/* The examples use WiFi configuration that you can set via project configuration menu

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/

#define EXAMPLE_ESP_MAXIMUM_RETRY  10

#include "my_config.h"




#ifndef  CONFIG_ESP_WIFI_CHANNEL
    #define CONFIG_ESP_WIFI_CHANNEL 1
#endif

#ifndef  CONFIG_ESP_MAX_STA_CONN
    #define CONFIG_ESP_MAX_STA_CONN 2
#endif

#define EXAMPLE_ESP_WIFI_CHANNEL   CONFIG_ESP_WIFI_CHANNEL
#define EXAMPLE_MAX_STA_CONN       CONFIG_ESP_MAX_STA_CONN


/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event,
 * but we only care about two events:
 *
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "wifi station";

static int s_retry_num = 0;

/* we'll change WiFiEthernetReady in event handler
 *
 * see also bool wifi_ready()
 */
static volatile bool WiFiEthernetReady = 0;

/*
 * WiFi event_handler() Public Domain Sample Code Credit Espressif
 *
 * See https://github.com/espressif/esp-idf/blob/master/examples/wifi/getting_started/station/main/station_example_main.c
 *
 */
void event_handler(void* arg,
                   esp_event_base_t event_base,
                   int32_t event_id,
                   void* event_data) {

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        WiFiEthernetReady = 0;
        esp_wifi_connect();
    }

    else if (event_base == WIFI_EVENT
              &&
            event_id == WIFI_EVENT_STA_DISCONNECTED) {

        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        }

        else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }

        ESP_LOGI(TAG, "connect to the AP fail");
        WiFiEthernetReady = 0;
    }

    else if (event_base == IP_EVENT
               &&
             event_id == IP_EVENT_STA_GOT_IP) {

        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        WiFiEthernetReady = 1;
    }
}

/*
 * WiFi wifi_init_sta() Public Domain Sample Code Credit Espressif
 *
 * See https://github.com/espressif/esp-idf/blob/master/examples/wifi/getting_started/station/main/station_example_main.c
 *
 */
void wifi_init_sta(void) {

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &event_handler,
        NULL,
        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
        IP_EVENT_STA_GOT_IP,
        &event_handler,
        NULL,
        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
        .ssid = EXAMPLE_ESP_WIFI_SSID,
        .password = EXAMPLE_ESP_WIFI_PASS,
        /* Setting a password implies station will connect to all security modes including WEP/WPA.
         * However these modes are deprecated and not advisable to be used. Incase your Access point
         * doesn't support WPA2, these mode can be enabled by commenting below line */
     .threshold.authmode = WIFI_AUTH_WPA2_PSK,

        .pmf_cfg = {
        .capable = true,
        .required = false
    },
    },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG,
            "connected to ap SSID:%s password:%s",
            EXAMPLE_ESP_WIFI_SSID,
            EXAMPLE_ESP_WIFI_PASS);
    }
    else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG,
            "Failed to connect to SSID:%s, password:%s",
            EXAMPLE_ESP_WIFI_SSID,
            EXAMPLE_ESP_WIFI_PASS);
    }
    else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }

    /* The event will not be processed after unregister */
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
                      IP_EVENT,
                      IP_EVENT_STA_GOT_IP,
                      instance_got_ip)
                   );

    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
                      WIFI_EVENT,
                      ESP_EVENT_ANY_ID,
                      instance_any_id)
                   );

    vEventGroupDelete(s_wifi_event_group);
}



/*
 * WiFi wifi_ap_event_handler() Public Domain Sample Code Credit Espressif
 *
 * See https://github.com/espressif/esp-idf/blob/master/examples/wifi/getting_started/softAP/main/softap_example_main.c
 *
 */
static void wifi_ap_event_handler(void* arg,
                                  esp_event_base_t event_base,
                                  int32_t event_id,
                                  void* event_data) {

    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event =
              (wifi_event_ap_staconnected_t*) event_data;

        ESP_LOGI(TAG,
            "station "MACSTR" join, AID=%d",
            MAC2STR(event->mac),
            event->aid);
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event =
              (wifi_event_ap_stadisconnected_t*) event_data;

        ESP_LOGI(TAG,
            "station "MACSTR" leave, AID=%d",
            MAC2STR(event->mac),
            event->aid);
    }

    /* when acting as AP, we're always ready, as we're not awaiting connection or IP addy */
    WiFiEthernetReady = 1;
}


/*
 * WiFi wifi_init_softap() Public Domain Sample Code Credit Espressif
 *
 * See https://github.com/espressif/esp-idf/blob/master/examples/wifi/getting_started/softAP/main/softap_example_main.c
 *
 */
void wifi_init_softap(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &wifi_ap_event_handler,
        NULL,
        NULL));

    wifi_config_t wifi_config = {
        .ap = {
        .ssid = EXAMPLE_ESP_WIFI_AP_SSID,
        .ssid_len = strlen(EXAMPLE_ESP_WIFI_AP_SSID),
        .channel = EXAMPLE_ESP_WIFI_CHANNEL,
        .password = EXAMPLE_ESP_WIFI_AP_PASS,
        .max_connection = EXAMPLE_MAX_STA_CONN,
        .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG,
        "wifi_init_softap finished. SSID:%s password:%s channel:%d",
        EXAMPLE_ESP_WIFI_AP_SSID,
        EXAMPLE_ESP_WIFI_AP_PASS,
        EXAMPLE_ESP_WIFI_CHANNEL);
}

/*
 * return true when above events determined that WiFi is actually ready.
 *
 */
bool wifi_ready()
{
    return WiFiEthernetReady;
}