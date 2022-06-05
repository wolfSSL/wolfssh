#pragma once

#define  USE_MY_PRIVATE_CONFIG

/*
 * we code .gitignore to also exclude my_private_config.h with wifi
 * SSID and passwords, etc. But it needs to be included in this project
 * but we don't know if other's will be on different envrionments...
 *
 * So:
 *
 * Search for non-GitHub repo file called my_private_config.h in one of
 * these locations:
 *
 * Sysprogs: /c/workspace/my_private_config.h
 * Windows:  /workspace/my_private_config.h
 * WSL:      /mnt/c/workspace/my_private_config.h
 * Linux:    ~/my_private_config.h
 *
 * If one of those files is NOT found, then the example from the Espressif
 * make menuconfig will be used.
 *
 * For this file to properly detect various "my_private_config.h" files, this
 * text needs to be in the CMakeLists.txt:

if(EXISTS "/c/workspace/my_private_config.h")
   message(STATUS "found SYSPROGS_MY_PRIVATE_CONFIG")
   add_definitions( -DSYSPROGS_MY_PRIVATE_CONFIG="/c/workspace/my_private_config.h" )
endif()

if(EXISTS "/workspace/my_private_config.h")
   message(STATUS "found WINDOWS_MY_PRIVATE_CONFIG")
   add_definitions( -DWINDOWS_MY_PRIVATE_CONFIG="/workspace/my_private_config.h" )
endif()

if(EXISTS "/mnt/c/workspace/my_private_config.h")
   message(STATUS "found WSL_MY_PRIVATE_CONFIG")
   add_definitions( -DWSL_MY_PRIVATE_CONFIG="/mnt/c/workspace/my_private_config.h" )
endif()

if(EXISTS "(~/my_private_config.h")
   message(STATUS "found LINUX_MY_PRIVATE_CONFIG")
   add_definitions( -DWSL_MY_PRIVATE_CONFIG="~/my_private_config.h" )
endif()

*
*/

#define XSTR(x) STR(x)
#define STR(x) #x

#define EXAMPLE_ESP_WIFI_AP_SSID      "TheBucketHill"
#define EXAMPLE_ESP_WIFI_AP_PASS      "jackorjill"

/* clang intellisense gives a pragma-messages warning
 * but we'll ignore it here. It does however, give a
 * compile-time warning that can be ignored:
 *
 * In file included from ../../../main/wifi.c:32:
 * ../../../main/my_config.h:59:32: warning: unknown option after '#pragma GCC diagnostic' kind [-Wpragmas]
 *  #pragma GCC diagnostic ignored "-W#pragma-messages" *
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-W#pragma-messages"


#if defined(NO_PRIVATE_CONFIG)
    /* reminder that if you put a password here,
     * it might get checked into GitHub!         */
    #define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
    #define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD

#elif defined(SYSPROGS_MY_PRIVATE_CONFIG)
    #pragma message ( "Found SYSPROGS_MY_PRIVATE_CONFIG !" )
    #pragma message ( XSTR(SYSPROGS_MY_PRIVATE_CONFIG) )
    #include SYSPROGS_MY_PRIVATE_CONFIG

#elif defined(WINDOWS_MY_PRIVATE_CONFIG)
    #pragma message ( "Found WINDOWS_MY_PRIVATE_CONFIG !" )
    #pragma message ( XSTR(WINDOWS_MY_PRIVATE_CONFIG) )
    #include WINDOWS_MY_PRIVATE_CONFIG

#elif defined(WSL_MY_PRIVATE_CONFIG)
    #pragma message ( "Found WSL_MY_PRIVATE_CONFIG !" )
    #pragma message ( XSTR(WSL_MY_PRIVATE_CONFIG) )
    #include WSL_MY_PRIVATE_CONFIG

#elif defined(LINUX_MY_PRIVATE_CONFIG)
    #pragma message ( "Found LINUX_MY_PRIVATE_CONFIG !" )
    #pragma message ( XSTR(LINUX_MY_PRIVATE_CONFIG) )
    #include LINUX_MY_PRIVATE_CONFIG

#else
    /* reminder that if you put a password here,
     * it might get checked into GitHub!         */
#warning "Not using my_private_config.h"

#ifndef  CONFIG_EXAMPLE_WIFI_SSID
    #define CONFIG_EXAMPLE_WIFI_SSID "TheBucketHill"
#endif
#ifndef  CONFIG_EXAMPLE_WIFI_PASSWORD
    #define CONFIG_EXAMPLE_WIFI_PASSWORD "jackorjill"
#endif

#ifndef  CONFIG_ESP_WIFI_SSID
    #define CONFIG_ESP_WIFI_SSID "TheBucketHill"
#endif
#ifndef  CONFIG_ESP_WIFI_PASSWORD
    #define CONFIG_ESP_WIFI_PASSWORD "jackorjill"
#endif

#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#endif

/* turn off GCC diagnostic ignored "-W#pragma-messages" from above
*/
#pragma GCC diagnostic pop
