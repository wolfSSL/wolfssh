[#ftl]
/**
  ******************************************************************************
  * File Name          : ${name}
  * Description        : This file provides code for the configuration
  *                      of the ${name} instances.
  ******************************************************************************
[@common.optinclude name=mxTmpFolder+"/license.tmp"/][#--include License text --]
  ******************************************************************************
  */
[#assign s = name]
[#assign toto = s?replace(".","_")]
[#assign toto = toto?replace("/","")]
[#assign toto = toto?replace("-","_")]
[#assign inclusion_protection = toto?upper_case]
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __${inclusion_protection}__
#define __${inclusion_protection}__

#ifdef __cplusplus
 extern "C" {
#endif


/* Includes ------------------------------------------------------------------*/
[#if includes??]
[#list includes as include]
#include "${include}"
[/#list]
[/#if]

[#-- SWIPdatas is a list of SWIPconfigModel --]  
[#list SWIPdatas as SWIP]  
[#-- Global variables --]
[#if SWIP.variables??]
	[#list SWIP.variables as variable]
extern ${variable.value} ${variable.name};
	[/#list]
[/#if]

[#-- Global variables --]

[#assign instName = SWIP.ipName]   
[#assign fileName = SWIP.fileName]   
[#assign version = SWIP.version]   

/**
	MiddleWare name : ${instName}
	MiddleWare fileName : ${fileName}
	MiddleWare version : ${version}
*/
[#if SWIP.defines??]
	[#list SWIP.defines as definition]	
/*---------- [#if definition.comments??]${definition.comments}[/#if] -----------*/
#define ${definition.name} #t#t ${definition.value} 
[#if definition.description??]${definition.description} [/#if]
	[/#list]
[/#if]



[/#list]

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFSSH_STM32_CUBEMX
/* #define WOLFSSL_CMSIS_RTOS */
/* #define NO_FILESYSTEM */

/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
/* SCP */
#undef WOLFSSH_SCP
#if defined(WOLFSSH_CONF_SCP) && WOLFSSH_CONF_SCP == 1
	#define WOLFSSH_SCP
#endif

/* SFTP */
#undef WOLFSSH_SFTP
#if !defined(NO_FILESYSTEM) && defined(WOLFSSH_CONF_SFTP) && WOLFSSH_CONF_SFTP == 1
	#define WOLFSSH_SFTP
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLFSSH_CONF_DEBUG) && WOLFSSH_CONF_DEBUG == 1
    #define DEBUG_WOLFSSH
#endif


/* ------------------------------------------------------------------------- */
/* wolfSSH IO */
/* ------------------------------------------------------------------------- */
#if defined(WOLFSSH_CONF_IO) && WOLFSSH_CONF_IO == 2
    #define WOLFSSH_LWIP
#else
    #define WOLFSSH_USER_IO
#endif

/* To be defined for the target Socket API */
#define WSTARTTCP()

#define WOLFSSH_LOG_PRINTF
#define WOLFSSL_LOG_PRINTF
#define fprintf(err, ... ) printf(__VA_ARGS__)
#define WFFLUSH fflush

#define BENCH_EMBEDDED
#define NO_WRITEV
#define NO_DEV_RANDOM
#define USE_CERT_BUFFERS_2048
#define WOLFSSL_USER_CURRTIME
#define SIZEOF_LONG_LONG 8
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_CURRDIR
#define NO_WOLF_C99
#define NO_MULTIBYTE_PRINT


#if !defined(NO_FILESYSTEM)
    #define WOLFSSH_USER_FILESYSTEM
#endif
#define NO_WOLFSSH_DIR


#define XVALIDATEDATE(d, f,t) (0)
#define WOLFSSL_USER_CURRTIME /* for benchmark */

#define WOLFSSL_GENSEED_FORTEST /* Warning: define your own seed gen */

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* #define NO_DH */
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_ED25519

#define WOLFSSH_IGNORE_FILE_WARN

typedef unsigned int size_t;

/* defines for unit tests */
#define NO_UNITTEST_MAIN_DRIVER
#define NO_TESTSUITE_MAIN_DRIVER
#define NO_APITEST_MAIN_DRIVER

#ifdef __cplusplus
}
#endif
#endif /* ${inclusion_protection}_H */

/**
  * @}
  */

/*****END OF FILE****/
