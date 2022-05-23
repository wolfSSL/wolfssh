#!/bin/bash
#
#  Expect the script at /path/to/wolfssh/IDE/Espressif/ESP-IDF/
#
#  Note that over the course of time there are 3 possible config files:
#
#    user_settings.h
#      used with IDE; enable with:
#
#      #define WOLFSSL_USER_SETTINGS
#
#      options.h is excluded with that setting
#
#    options.h
#      used with configure builds
#
#      This is an older file related an issue that's been working forever.
#      There should only be a wolfSSL copy right now. It is generated based on configure.
#
#    config.h
#      This is generated per project. The configure script creates it.
#      The one for wolfSSL is different than the one for wolfSSH
#      There's a #define that is added to the Makefile:
#
#      #define HAVE_CONFIG
#
#  EDITOR NOTE: There's a Linux setup.sh that should identically mirror functionality here.
#               Please try to keep code lines matching between files for easily comparing.
# ******************************************************************************************************
# ******************************************************************************************************
echo;
echo "wolfSSH (Secure Shell) Windows Setup. Version 0.1d"
echo;
echo "This utility will copy a static snapshot of wolfSSH files to the ESP32-IDF component directory."
echo;
echo "You must first have installed wolfSSL component for this SSH component to function properly."
echo;
echo "If you wish to keep your component library fresh with git pull, consider soft link with ln."
echo;
echo    "ln [OPTION]... [-T] TARGET LINK_NAME"
echo;
# ******************************************************************************************************
# ******************************************************************************************************

#  Set REPLICATE_WOLFSSL=true  if a local copy of wolfssl is desired.
#  The default is false: use use wolfssl in the parent directory component.
REPLICATE_WOLFSSL=false

COPYERROR=false
WOLFSSH_FOUND=false
WOLFSSH_FORCE_CONFIG=false

#  if there's a setup.sh, we are probably starting in the right place.
if [ ! -f "./setup_win.bat" ]; then
    echo "Please run this script at /path/to/wolfssh/ide/Espressif/ESP-IDF/"
   exit 1
fi

#  if there's also a default wolfssh_espressif_semaphore.md, we are very likely starting in the right place."
if [ ! -f "./wolfssh_espressif_semaphore.md" ]; then
    echo Please run this script at /path/to/wolfssh/ide/Espressif/ESP-IDF/
    exit 1
fi

#  see if there was a parameter passed for a specific EDP-IDF directory
#  this may be different than the standard ESP-IDF environment (e.g. VisualGDB)
if [ "$1" == "" ]; then
    if [ "${IDF_PATH}" == "" ]; then
        echo;
        echo "ERROR: Specify your ESP-IDF path as a parameter or run from ESP-IDF prompt with IDF_PATH environment variable."
        echo;
        echo "For example: ./setup.sh ~/workspace/esp-idf/v4.4"
        echo;
        exit 1
    fi

    #  There's no parameter, check if ${IDF_PATH} non-blank
    if [ -d "${IDF_PATH}" ]; then
        echo "Using IDF_PATH: ${IDF_PATH}"
        echo;
    else
        echo ERROR: IDF_PATH=${IDF_PATH} does not exist!
        echo;
        exit 1
    fi
else
    if [ ! -d "$1" ]; then
        echo "ERROR: optional directory was specified, but not found: $1"
        exit 1
    fi

    IDF_PATH=$1
    echo "Set specified IDF_PATH: ${IDF_PATH}"
fi

#  if no IDF_PATH is found, we don't know what to do. Go exit with error.
if [ "${IDF_PATH}" == "" ]; then
  echo "Please launch the script from ESP-IDF command prompt,"
  echo "or set your desired IDF_PATH environment variable,"
  echo "or pass a parameter to your directory, such as for VisualGDB with ESP-IDF 4.4:"
  echo;
  echo "  ./setup.sh /mnt/c/SysGCC/esp32/esp-idf/v4.4"
  echo;
  echo "The wolfssl components can also be installed in project directory:"
  echo;
  echo "  ./setup.sh /mnt/c/workspace/wolfssh/examples/ESP32-SSH-Server"
  echo;
  exit 1
fi

echo;
echo "Using IDF_PATH: ${IDF_PATH}"

#  Here we go!
# setup some path variables
echo;

SCRIPTDIR=$(pwd)
BASEDIR=${SCRIPTDIR}/../../..

#  SSH
WOLFSSH_ESPIDFDIR=$BASEDIR/ide/Espressif/ESP-IDF

WOLFSSHLIB_TRG_DIR=${IDF_PATH}/components/wolfssh
WOLFSSHEXP_TRG_DIR=${IDF_PATH}/examples/protocols

#  SSL
WOLFSSLLIB_TRG_DIR=${IDF_PATH}/components/wolfssl

echo "Using SCRIPTDIR          = ${SCRIPTDIR}"
echo "Using BASEDIR            = ${BASEDIR}"

if [ -d "$WOLFSSLLIB_TRG_DIR" ]; then
    echo Using WOLFSSLLIB_TRG_DIR = $WOLFSSLLIB_TRG_DIR
    echo;
else
    echo ERROR: this wolfSSH component depends on the wolfSSL component being installed first.
    echo;
    echo Directory "$WOLFSSLLIB_TRG_DIR" not found.
    echo;
    echo See https://github.com/wolfSSL/wolfssl for more info
    echo;
    exit 1
fi

if [ -d  "${WOLFSSHLIB_TRG_DIR}" ]; then
    echo "Found exisintg ${WOLFSSHLIB_TRG_DIR}"
    WOLFSSH_FOUND=true
else
    mkdir  "${WOLFSSHLIB_TRG_DIR}"
fi

echo "Using WOLFSSH_ESPIDFDIR  = ${WOLFSSH_ESPIDFDIR}"
echo "Using WOLFSSHLIB_TRG_DIR = ${WOLFSSHLIB_TRG_DIR}"
echo "Using WOLFSSHEXP_TRG_DIR = ${WOLFSSHEXP_TRG_DIR}"

echo;
echo Equivalalent wolfSSH destination path:
echo $(cd "$WOLFSSH_ESPIDFDIR"; pwd)

echo;
echo Equivalalent wolfSSL source directory paths:


echo $(cd "$WOLFSSLLIB_TRG_DIR"; pwd)

echo;
echo Equivalalent wolfSSH source directory paths:

echo $(cd "$BASEDIR"; pwd)
echo $(cd "$WOLFSSHLIB_TRG_DIR"; pwd)
echo $(cd "$WOLFSSHEXP_TRG_DIR"; pwd)

# set TIME and DATE environment variables
TIME="$(date +%T)";DATE="$(date +%a) $(date +%x)"

#  set the FileStamp variable to the current date:  YYMMYY_HHMMSS
#  the simplest method, to use existing TIME ad DATE variables:
#  date = Thu 09/17/15  (note 2 digit year in Linux, 4 digits in Windows)
#  time = 11:13:15.47
#         012345678901234567890
#
#  There is no leading zero for single digit hours (e.g. 9:00am), so we need to manually include the zero
#
if   [ "${TIME:0:1}" == " " ]; then FileStamp=${DATE:10:2}${DATE:7:2}${DATE:4:2}_0${TIME:1:1}${TIME:3:2}${TIME:6:2}; fi

#  otherwise, if a space not found before the digit, it is a 2 digit hour, so no extract zero is needed
if [ ! "${TIME:0:1}" == " " ]; then FileStamp=${DATE:10:2}${DATE:7:2}${DATE:4:2}_${TIME:0:2}${TIME:3:2}${TIME:6:2}; fi

#  Backup existing config settings
if [ -f "${WOLFSSHLIB_TRG_DIR}/include/config.h" ]; then
  echo;
  echo "Saving: $WOLFSSHLIB_TRG_DIR/include/config.h"
  echo "    to: $SCRIPTDIR/config_h_/${FileStamp}.bak"
  cp           "${WOLFSSHLIB_TRG_DIR}"/include/config.h      "${SCRIPTDIR}"/config_h_${FileStamp}.bak
  echo;
fi

#  Backup existing user_settings
if [ -f "${WOLFSSHLIB_TRG_DIR}"/include/user_settings.h ]; then
  echo;
  echo "Saving: ${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
  echo "    to: ${SCRIPTDIR}/user_settings_h_${FileStamp}.bak"
  cp   "${WOLFSSHLIB_TRG_DIR}"/include/user_settings.h       "${SCRIPTDIR}"/user_settings_h_${FileStamp}.bak
  echo;
fi

#*******************************************************************************************************
#* check if there's already an existing ${WOLFSSHLIB_TRG_DIR} and confirm removal
#*******************************************************************************************************
PURGE_COPY=
PURGE=false
if [ ${WOLFSSH_FOUND} == true ]; then
    echo;
    echo "WARNING: Existing files found in $WOLFSSHLIB_TRG_DIR"
    echo;

    until [ "${PURGE_COPY^}" == "Y" ] || [ "${PURGE_COPY^}" == "N" ]; do
      read -n1 -p "Delete files and proceed with install in $WOLFSSHLIB_TRG_DIR (Y/N) " PURGE_COPY
      PURGE_COPY=${PURGE_COPY^};
      echo;
    done


    echo "Ready to copy files into ${IDF_PATH}"

#*******************************************************************************************************
#* NO DELETE (this is not a goto label)
#*******************************************************************************************************
    # prompt for purge
    if [ ! "${PURGE_COPY}" == "Y" ]; then
        echo;
        REFRESH_COPY=
        until [ "${REFRESH_COPY^}" == "Y" ] || [ "${REFRESH_COPY^}" == "N" ]; do
          read -n1 -p "Refresh files ${WOLFSSHLIB_TRG_DIR}   (there will be a prompt to keep or overwrite config) (Y/N) " REFRESH_COPY
          REFRESH_COPY=${REFRESH_COPY^}
          echo;
        done

    else
        echo;
        read -n1 -p "Press any key to continue"
    fi
fi

#*******************************************************************************************************
#*  PURGE
#*******************************************************************************************************
#* purge existing directory

if [ "${PURGE_COPY}" == "Y" ]; then
    if [ -d "${WOLFSSHLIB_TRG_DIR}" ]; then
        echo;
        echo Removing "${WOLFSSHLIB_TRG_DIR}"
        rm "${WOLFSSHLIB_TRG_DIR}" -R

        if [ -d "${WOLFSSHLIB_TRG_DIR}" ]; then
            COPYERROR=true
            echo;
            echo "WARNING: Failed to remove ${WOLFSSHLIB_TRG_DIR}"
            echo;
            echo "Check permissions, open files, read-only attributes, etc."
            echo;
        fi
        echo;
    else
        echo;
        echo Prior ${WOLFSSHLIB_TRG_DIR} not found, installing fresh.
        echo;
    fi
fi # not purge

#*******************************************************************************************************
#*REFRESH
#*******************************************************************************************************
if [ ! -d "${WOLFSSHLIB_TRG_DIR}"           ]; then       mkdir      "${WOLFSSHLIB_TRG_DIR}"          ; fi
if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfssh/  ]; then       mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfssh/ ; fi
if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/include/  ]; then       mkdir      "${WOLFSSHLIB_TRG_DIR}"/include/ ; fi
if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/src/      ]; then       mkdir      "${WOLFSSHLIB_TRG_DIR}"/src/     ; fi
if [ ! -d "${WOLFSSHEXP_TRG_DIR}"           ]; then       mkdir      "${WOLFSSHEXP_TRG_DIR}"          ; fi

#*******************************************************************************************************
#* optionally copy wolfssl here (the default is to use the parent directory shared component)
#*******************************************************************************************************
if [ "${REPLICATE_WOLFSSL}" == "true" ]; then
   #  note we copy wolfcrypt from wolfssl component
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/                    ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/                    ; fi
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/benchmark/          ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/benchmark/          ; fi
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/                ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/                ; fi
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/           ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/           ; fi
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/Atmel/     ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/Atmel/     ; fi
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/Espressif/ ]; then   mkdir      "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/port/Espressif/ ; fi
fi

echo;
echo "Copying files to ${WOLFSSHLIB_TRG_DIR}/src/"
cp "${BASEDIR}"/src/*.c                                                   "${WOLFSSHLIB_TRG_DIR}"/src/
if [ $? != 0 ]; then COPYERROR=true; fi

#*******************************************************************************************************
#* optionally copy wolfssl here (the default is to use the parent directory shared component)
#*******************************************************************************************************
if [ "${REPLICATE_WOLFSSL}" == "true" ]; then
   echo "Copying port/Atmel files to ${WOLFSSHLIB_TRG_DIR}/src/port/Atmel"
   cp "${BASEDIR}"/src/port/Atmel/*.c                                      "${WOLFSSHLIB_TRG_DIR}"/src/port/Atmel
   if [ $? != 0 ]; then COPYERROR=true; fi

   echo "Copying port/Espressif files to ${WOLFSSHLIB_TRG_DIR}/src/port/Espressif"
   cp "${BASEDIR}"/src/port/Espressif/*.c                                  "${WOLFSSHLIB_TRG_DIR}"/src/port/Espressif
   if [ $? != 0 ]; then COPYERROR=true; fi

   echo "Copying wolfSSL component src/*.c files to ${WOLFSSHLIB_TRG_DIR}/wolfcrypt/src"
   cp "${WOLFSSLLIB_TRG_DIR}"/wolfcrypt/src/*.c                            "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/ -R
   if [ $? != 0 ]; then COPYERROR=true; fi

   echo "Copying src/*.i files to ${WOLFSSHLIB_TRG_DIR}/wolfcrypt/src"
   cp "${WOLFSSLLIB_TRG_DIR}"/wolfcrypt/src/*.i                            "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/src/ -R
   if [ $? != 0 ]; then COPYERROR=true; fi

   echo "Copying files to ${WOLFSSHLIB_TRG_DIR}/wolfcrypt/benchmark/"
   cp "${WOLFSSLLIB_TRG_DIR}"/wolfcrypt/benchmark/*                        "${WOLFSSHLIB_TRG_DIR}"/wolfcrypt/benchmark/ -R
   if [ $? != 0 ]; then COPYERROR=true; fi
fi

echo "Copying files to ${WOLFSSHLIB_TRG_DIR}/wolfssh/"
cp "${BASEDIR}"/wolfssh/*.h                                                "${WOLFSSHLIB_TRG_DIR}"/wolfssh/
if [ $? != 0 ]; then COPYERROR=true; fi

#*******************************************************************************************************
#* optionally copy wolfssl here (the default is to use the parent directory shared component)
#*******************************************************************************************************
if [ "${REPLICATE_WOLFSSL}" == "true" ]; then
   echo;
   echo "Replicating  ${WOLFSSLLIB_TRG_DIR}/wolfssl/  to  ${WOLFSSHLIB_TRG_DIR}/wolfssl/"
   if [ ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfssl/ ]; then  mkdir   "${WOLFSSHLIB_TRG_DIR}"/wolfssl/           ; fi
   if p ! -d "${WOLFSSHLIB_TRG_DIR}"/wolfssl/ ]; then  mkdir   "${WOLFSSHLIB_TRG_DIR}"/wolfssl/wolfcrypt/ ; fi

   cp  "${WOLFSSLLIB_TRG_DIR}"/wolfssl/*                       "${WOLFSSHLIB_TRG_DIR}"/wolfssl/
   cp  "${WOLFSSLLIB_TRG_DIR}"/wolfssl/wolfcrypt/*             "${WOLFSSHLIB_TRG_DIR}"/wolfssl/wolfcrypt/
fi

#*******************************************************************************************************
#* config file
#*******************************************************************************************************
echo;
echo "Copying config file to ${WOLFSSHLIB_TRG_DIR}/include/"
echo;

#* Check if operator wants to keep prior config.h
if [ -f "./config_h_${FileStamp}.bak" ]; then
    echo;
    echo "Found prior config.h in  ${SCRIPTDIR}/config_h_${FileStamp}.bak"
    echo;
    ls "config_h_${FileStamp}.bak" -al
    echo;

    CHOICE_COPY=
    until [ "${CHOICE_COPY}" == "Y" ] || [ "${CHOICE_COPY}" == "N" ]; do
      read -n1 -p "Use prior config.h  in  ${WOLFSSHLIB_TRG_DIR}/include/ (Y/N) " CHOICE_COPY
      CHOICE_COPY=${CHOICE_COPY^}
      echo;
    done


    if [ "${CHOICE_COPY}" == "Y" ]; then
        # create a placeholder file
        echo "/* new config */" >                                      "${WOLFSSHLIB_TRG_DIR}/include/config.h"

        cp "config_h_${FileStamp}.bak"                                 "${WOLFSSHLIB_TRG_DIR}/include/config.h"
        if [ $? != 0 ]; then COPYERROR=true; fi
    fi

else
    # a config_h_${FileStamp}.bak file does not exist
    echo;
    echo "Prior config.h not found. (and one is not desired; it should be in wolfssl)"
    echo;

    if [ "${WOLFSSH_FORCE_CONFIG}" == "true" ]; then
        echo "/* new config.h  */" >                                       "${WOLFSSHLIB_TRG_DIR}/include/config.h"

        if [ -f "${WOLFSSH_ESPIDFDIR}/dummy_config_h." ]; then
            echo "Using default file dummy_config_h for ssh component in  \"${WOLFSSHLIB_TRG_DIR}/include/config.h\" "
            cp "${WOLFSSH_ESPIDFDIR}"/dummy_config_h.                      "${WOLFSSHLIB_TRG_DIR}"/include/config.h
            if [ $? != 0 ]; then COPYERROR=true; fi
        else
            echo;
            echo "WARNING: Prior config.h not found and dummy_config_h default available. Using placeholder."
        fi
    fi
fi

#*******************************************************************************************************
#NO_CONFIG_RESTORE
#*******************************************************************************************************
#* Check if operator wants to keep prior user_settings.h
if [ -f "user_settings_h_${FileStamp}.bak" ]; then
    echo;
    echo;
    echo "Found prior user_settings.h in  ${SCRIPTDIR}/user_settings_h_${FileStamp}.bak"
    echo;
    ls "user_settings_h_${FileStamp}.bak" -al
    echo;


    CHOICE_COPY=
    until [ "${CHOICE_COPY}" == "Y" ] || [ "${CHOICE_COPY}" == "N" ]; do
      read -n1 -p "Use prior user_settings.h  in  ${WOLFSSHLIB_TRG_DIR}/include/ (Y/N) " CHOICE_COPY
      CHOICE_COPY=${CHOICE_COPY^}
      echo;
    done


    if [ "${CHOICE_COPY}" == "Y" ]; then
        cp "user_settings_h_${FileStamp}.bak"    "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
        if [ $? != 0 ]; then COPYERROR=true; fi

        #* TODO do we really need to replicate the user_settings.h here for wolfSSH?
        if [ -f "${WOLFSSHLIB_TRG_DIR}/wolfssl/include/user_settings.h" ]; then
          cp "user_settings_h_${FileStamp}.bak"    "${WOLFSSHLIB_TRG_DIR}/wolfssl/include/user_settings.h"
          if [ $? != 0 ]; then COPYERROR=true; fi
        fi
        CHOICE_COPY=
    fi
else
    #* user_settings_h_${FileStamp}.bak not found
    echo;
    echo;
    #* TODO do we really need to replicate the user_settings.h here? It does seem the compiler wants one.
    echo "Prior user_settings.h not found in user_settings_h_${FileStamp}.bak"
    echo /* new user_settings file */ >                     "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"

    if [ -f "${WOLFSSLLIB_TRG_DIR}/include/user_settings.h" ]; then
        echo "Using file: ${WOLFSSLLIB_TRG_DIR}/include/user_settings.h"
        cp "${WOLFSSLLIB_TRG_DIR}/include/user_settings.h"  "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
    else
        echo;
        echo "WARNING: No ${WOLFSSLLIB_TRG_DIR}/include/user_settings.h file found"
        echo;
        echo "Created placeholder. Edit ${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
    fi
    echo;
fi

#*******************************************************************************************************
#NO_USER_SETTINGS_RESTORE
#*******************************************************************************************************

echo;
echo Copying libs/CMakeLists.txt to ${WOLFSSHLIB_TRG_DIR}/
cp "${WOLFSSH_ESPIDFDIR}/libs/CMakeLists.txt"                "${WOLFSSHLIB_TRG_DIR}/"
if [ $? != 0 ]; then COPYERROR=true; fi

echo Copying libs/component.mk to ${WOLFSSHLIB_TRG_DIR}/
cp "${WOLFSSH_ESPIDFDIR}/libs/component.mk"                  "${WOLFSSHLIB_TRG_DIR}/"
if [ $? != 0 ]; then COPYERROR=true; fi

#* TODO determine what happened to ssl x509_str.c (we get a compile error when this is missing):
if [ ! -f "${WOLFSSHLIB_TRG_DIR}/src/x509_str.c" ]; then
    echo "/* x509_str placeholder */"  > "${WOLFSSHLIB_TRG_DIR}/src/x509_str.c"
    echo "Created  placeholder for file   ${WOLFSSHLIB_TRG_DIR}/src/x509_str.c"
fi

#* TODO determine what happened to ssh x509_str.c (we get a compile error when this is missing):
if [ ! -f "${WOLFSSLLIB_TRG_DIR}/src/x509_str.c" ]; then
    echo "/* x509_str placeholder */"  > "${WOLFSSLLIB_TRG_DIR}/src/x509_str.c"
    echo "Created placeholder for file    ${WOLFSSLLIB_TRG_DIR}/src/x509_str.c"
fi

#*******************************************************************************************************
#* check if there's a wolfssl/options.h
#*******************************************************************************************************
echo Checking for ${WOLFSSLLIB_TRG_DIR}/wolfssl/options.h
if [ -f "${WOLFSSLLIB_TRG_DIR}/wolfssl/options.h" ]; then
    echo;
    echo "WARNING: options.h found in ${WOLFSSLLIB_TRG_DIR}/wolfssl/"
    echo;
    echo "Consider using a project user_settings.h and #define WOLFSSL_USER_SETTINGS"
else
    echo "Confirmed no options.h file; will expect user_settings.h"
fi



#* error during copy encountered
#*******************************************************************************************************
if [ "${COPYERROR}" == "true" ]; then
#*******************************************************************************************************
    echo;
    echo "Error during copy."
    echo;
    echo "Please ensure none of the target files are flagged as read-only, open, etc."
    exit 1
fi

#
# space placeholder for side-by-side, line-by-line Linux script comparison
#
#
#
#
#
#
#
#
#
#
#
#* Success
#*******************************************************************************************************
# DONE
#*******************************************************************************************************
echo;
echo;
echo "See Component files for wolfSSL in ${WOLFSSHLIB_TRG_DIR}"
echo;
echo "See additional examples at  https://github.com/wolfSSL/wolfssl-examples"
echo;
echo "REMINDER: Ensure any wolfSSL #include definitions occur BEFORE include files in your source code."
echo;
if [ "${COPYERROR}" == "true" ]; then
    echo;
    echo "WARNING: Copy completed with errors! Check for files in use, permissions, symbolic links, etc."
    echo;
fi

echo "Configuration files found:"
# ssl
find "${WOLFSSLLIB_TRG_DIR}" -name config.h
find "${WOLFSSLLIB_TRG_DIR}" -name options.h
find "${WOLFSSLLIB_TRG_DIR}" -name user_settings.h
# ssh
find "${WOLFSSHLIB_TRG_DIR}" -name config.h
find "${WOLFSSHLIB_TRG_DIR}" -name options.h
find "${WOLFSSHLIB_TRG_DIR}" -name user_settings.h
echo;

#* Remind of backup files
if [ -f "${SCRIPTDIR}/config_h_${FileStamp}.bak" ]; then
    echo;
    echo "Your prior config.h file was saved to:    ${SCRIPTDIR}/config_h_${FileStamp}.bak"
fi

if [ -f "${SCRIPTDIR}/user_settings_h_${FileStamp}.bak" ]; then
    echo "Your prior user_settings.h was saved to:  ${SCRIPTDIR}/user_settings_h_${FileStamp}.bak"
    echo;
fi

# Check to ensure we have a valid Expressif chip defined

if [ -f "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h" ]; then
    FOUND_ESP=false
    echo "Looking for Espressif WOLFSSL_ESPWROOM32, WOLFSSL_ESPWROOM32SE, or WOLFSSL_ESP8266"
    echo;

    cat "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h" | grep "#define WOLFSSL_ESPWROOM32"
    if [ $? == 0 ]; then FOUND_ESP=true; fi

    cat "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h" | grep "#define WOLFSSL_ESPWROOM32SE"
    if [ $? == 0 ]; then FOUND_ESP=true; fi

    cat "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h" | grep "#define WOLFSSL_ESP8266"
    if [ $? == 0 ]; then FOUND_ESP=true; fi

    if [ "${FOUND_ESP}" == "N" ]; then
        echo "WARNING: did not find an Espressif define in ${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
    fi
else 
    echo;
    echo WARNING: File not found: "${WOLFSSHLIB_TRG_DIR}/include/user_settings.h"
fi

echo;
echo "Review config file in  \"${WOLFSSHLIB_TRG_DIR}/include/user_settings.h\" before compiling."
echo;

echo "setup.sh for wolfSSH (Secure Shell) ESP-IDF component install completed."
