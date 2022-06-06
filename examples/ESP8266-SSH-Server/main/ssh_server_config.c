#include "ssh_server_config.h"

void ssh_server_config_init()
{
    ESP_LOGI("init", "ssh_server_config_init");
}

//char* ntpServerList[NTP_SERVER_COUNT] = {
//    "pool.ntp.org",
//    "time.nist.gov",
//    "utcnist.colorado.edu"
//};

char* ntpServerList[NTP_SERVER_COUNT] = NTP_SERVER_LIST;

