#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* include Microchip configuration first and then make additional changes */
#include "configuration.h"

#include <stddef.h>

/* Turn on filesystem support for SFTP use */
#undef NO_FILESYSTEM

/* wolfSSH configuration macros */
#define WOLFSSL_WOLFSSH
#ifndef NO_FILESYSTEM
    #define WOLFSSH_SFTP
#endif
#define DEFAULT_WINDOW_SZ 16384
#define WOLFSSH_NO_HMAC_SHA2_512

/* do not use dirent with wolfSSL */
#define NO_WOLFSSL_DIR

/* avoid the defualt settings in older wolfssl versions from
 * wolfssl/wolfcryt/settings.h */
#undef MICROCHIP_PIC32

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

/* In older versions of wolfSSL (5.7.6 and older) the strcasecmp and strncasecmp
 * were dependent on the macro MICROCHIP_PIC32. Defining them here overrides
 * that. */
#if (__XC32_VERSION >= 1000) && (__XC32_VERSION < 4000)
   #define XSTRCASECMP(s1,s2) strcasecmp((s1),(s2))
   #define XSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))
#else
   #define XSTRCASECMP(s1,s2) strcmp((s1),(s2))
   #define XSTRNCASECMP(s1,s2,n) strncmp((s1),(s2),(n))
#endif

/* allow signature wrapper api for wolfSSH use */
#undef NO_SIG_WRAPPER

#endif
