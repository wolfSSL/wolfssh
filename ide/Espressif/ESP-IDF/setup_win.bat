@echo off
::
:: Expect the script at /path/to/wolfssh/IDE/Espressif/ESP-IDF/
::
:: Note that over the course of time there are 3 possible config files:
::
::   user_settings.h
::     used with IDE; enable with:
::
::     #define WOLFSSL_USER_SETTINGS
::
::     options.h is excluded with that setting
::
::   options.h
::     used with configure builds
:: 
::     This is an older file related an issue that’s been working forever.
::     There should only be a wolfSSL copy right now. It is generated based on configure.
::
::   config.h 
::     This is generated per project. The configure script creates it.
::     The one for wolfSSL is different than the one for wolfSSH
::     There’s a #define that is added to the Makefile:
::
::     #define HAVE_CONFIG
::
:: EDITOR NOTE: There's a Linux setup.sh that should identically mirror functionality here.
::              Please try to keep code lines matching between files for easily comparing.
::******************************************************************************************************
::******************************************************************************************************
echo;
echo wolfSSH (Secure Shell) Windows Setup. Version 0.1d
echo;
echo This utility will copy a static snapshot of wolfSSH files to the ESP32-IDF component directory.
echo;
echo You must first have installed wolfSSL component for this SSH component to function properly.
echo;
echo If you wish to keep your component library fresh with git pull, consider hard link with mklink.
echo;
echo    "mklink [[/d] | [/h] | [/j]] <link> <target>"
echo;
::******************************************************************************************************
::******************************************************************************************************

:: Set REPLICATE_WOLFSSL=true  if a local copy of wolfssl is desired. 
:: The default is false: use use wolfssl in the parent directory component.
SET REPLICATE_WOLFSSL=false

SET COPYERROR=false
SET WOLFSSH_FOUND=false
SET WOLFSSH_FORCE_CONFIG=false

:: if there's a setup.sh, we are probably starting in the right place.
if NOT EXIST "setup.sh" (
  echo Please run this script at /path/to/wolfssh/IDE/Espressif/ESP-IDF/
  goto :ERR
)

:: if there's also a default wolfssh_espressif_semaphore.md, we are very likely starting in the right place.
if NOT EXIST "wolfssh_espressif_semaphore.md" (
  echo Please run this script at /path/to/wolfssh/IDE/Espressif/ESP-IDF/
  goto :ERR
)

:: see if there was a parameter passed for a specific EDP-IDF directory
:: this may be different than the standard ESP-IDF environment (e.g. VisualGDB)
if "%~1" == "" (
    if "%IDF_PATH%" == "" (
        echo;
        echo ERROR: Specify your ESP-IDF path as a parameter or run from ESP-IDF prompt with IDF_PATH environment variable.
        echo;
        echo For example: setup_win.bat C:\SysGCC\esp32\esp-idf\v4.4
        echo;
        goto :ERR
    )

    REM There's no parameter, check if %IDF_PATH% non-blank 
    if exist "%IDF_PATH%" (
        echo Using IDF_PATH: %IDF_PATH%
        echo;
    ) else (
        echo ERROR: IDF_PATH=%IDF_PATH% does not exist!
        echo;
        goto :ERR
    )
) else (
    if not exist "%~1" (
        echo ERROR: optional directory was specified, but not found: %~1
        goto :ERR
    )

    SET "IDF_PATH=%~1"
    echo Set specified IDF_PATH.
)

:: if no IDF_PATH is found, we don't know what to do. Go exit with error.
if "%IDF_PATH%" == "" (
  echo Please launch the script from ESP-IDF command prompt,
  echo or set your desired IDF_PATH environment variable,
  echo or pass a parameter to your directory, such as for VisualGDB with ESP-IDF 4.4:
  echo;
  echo   .\setup_win.bat C:\SysGCC\esp32\esp-idf\v4.4
  echo;
  echo The wolfssl components can also be installed in project directory:
  echo;
  echo   .\setup_win.bat C:\workspace\wolfssh\examples\ESP32-SSH-Server
  echo;
  goto :ERR
)

echo;
echo Using IDF_PATH: %IDF_PATH%

:: Here we go!
:: setup some path variables
echo;

set SCRIPTDIR=%CD%
set BASEDIR=%SCRIPTDIR%\..\..\..

:: SSH
set WOLFSSH_ESPIDFDIR=%BASEDIR%\IDE\Espressif\ESP-IDF

set WOLFSSHLIB_TRG_DIR=%IDF_PATH%\components\wolfssh
set WOLFSSHEXP_TRG_DIR=%IDF_PATH%\examples\protocols

:: SSL
set WOLFSSLLIB_TRG_DIR=%IDF_PATH%\components\wolfssl

echo Using SCRIPTDIR          = %SCRIPTDIR%
echo Using BASEDIR            = %BASEDIR%

if exist "%WOLFSSLLIB_TRG_DIR%" (
    echo Using WOLFSSLLIB_TRG_DIR = %WOLFSSLLIB_TRG_DIR%
    echo;
) else (
    echo ERROR: this wolfSSH component depends on the wolfSSL component being installed first.
    echo;
    echo Directory "%WOLFSSLLIB_TRG_DIR%" not found.
    echo;
    echo See https://github.com/wolfSSL/wolfssl for more info
    echo;
    goto :ERR
)

if exist "%WOLFSSHLIB_TRG_DIR%" (
    echo Found exisintg %WOLFSSHLIB_TRG_DIR%
    SET WOLFSSH_FOUND=true
) else (
    mkdir  "%WOLFSSHLIB_TRG_DIR%"
)

echo Using WOLFSSH_ESPIDFDIR  = %WOLFSSH_ESPIDFDIR%
echo Using WOLFSSHLIB_TRG_DIR = %WOLFSSHLIB_TRG_DIR%
echo Using WOLFSSHEXP_TRG_DIR = %WOLFSSHEXP_TRG_DIR%

echo;
echo Equivalalent wolfSSH destination path:
dir "%WOLFSSH_ESPIDFDIR%\*.xyzzy" 2> nul | findstr  \

echo;
echo Equivalalent wolfSSL source directory paths:
:: show the path of the equivalent  %VALUE% (search for files that don't exist, supress error, and look for string with "\")

dir "%WOLFSSLLIB_TRG_DIR%\*.xyzzy" 2> nul | findstr  \

echo;
echo Equivalalent wolfSSH source directory paths:

dir "%BASEDIR%\*.xyzzy" 2> nul | findstr  \
dir "%WOLFSSHLIB_TRG_DIR%\*.xyzzy" 2> nul | findstr  \
dir "%WOLFSSHEXP_TRG_DIR%\*.xyzzy" 2> nul | findstr  \

:: DOS already has current DATE and TIME environment variables
::

:: set the FileStamp variable to the current date:  YYMMYY_HHMMSS
:: the simplest method, to use existing TIME ad DATE variables:
:: date = Thu 09/17/2015
:: time = 11:13:15.47
::        012345678901234567890
::
:: There is no leading zero for single digit hours (e.g. 9:00am), so we need to manually include the zero
::                                                                      here  |
if     "%TIME:~0,1%" == " "  set FileStamp=%DATE:~12,2%%DATE:~7,2%%DATE:~4,2%_0%TIME:~1,1%%TIME:~3,2%%TIME:~6,2%

:: otherwise, if a space not found before the digit, it is a 2 digit hour, so no extract zero is needed
if NOT "%TIME:~0,1%" == " "  set FileStamp=%DATE:~12,2%%DATE:~7,2%%DATE:~4,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%

:: Backup existing ssh config settings file
if exist "%WOLFSSHLIB_TRG_DIR%\include\config.h" (
  echo;
  echo Saving: %WOLFSSHLIB_TRG_DIR%\include\config.h
  echo     to: %SCRIPTDIR%\config_h_%FileStamp%.bak
  copy         %WOLFSSHLIB_TRG_DIR%\include\config.h      %SCRIPTDIR%\config_h_%FileStamp%.bak
  echo;
)

:: Backup existing ssh user_settings file
if exist "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" (
  echo;
  echo Saving: %WOLFSSHLIB_TRG_DIR%\include\user_settings.h
  echo     to: %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
  copy         %WOLFSSHLIB_TRG_DIR%\include\user_settings.h      %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
  echo;
)

::******************************************************************************************************
:: check if there's already an existing %WOLFSSHLIB_TRG_DIR% and confirm removal
::******************************************************************************************************
:: clear any error level that will be used in choice command
call;
if exist "%WOLFSSHLIB_TRG_DIR%" (
    echo;
    echo WARNING: Existing files found in %WOLFSSHLIB_TRG_DIR%
    echo;

    REM clear any prior errorlevel
    call;
    choice /c YN /m "Delete files and proceed with install in %WOLFSSHLIB_TRG_DIR%  "
    if ERRORLEVEL 2 GOTO :NODELETE
    GOTO :PURGE

    echo;
    echo Ready to copy files into %IDF_PATH%

::******************************************************************************************************
:NODELETE
::******************************************************************************************************
    REM clear any prior errorlevel
    echo;
    call;
    choice /c YN /m "Refresh files %WOLFSSHLIB_TRG_DIR%   (there will be a prompt to keep or overwrite config)  "
    if ERRORLEVEL 2 GOTO :NOCOPY
::
::
:: space placeholder for side-by-side, line-by-line Linux script comparison
::
::
    GOTO :REFRESH
) else (
    echo;
    pause
)

::******************************************************************************************************
:PURGE
::******************************************************************************************************
:: purge existing directory

if exist "%WOLFSSHLIB_TRG_DIR%" (
    echo;
    echo Removing "%WOLFSSHLIB_TRG_DIR%"
    rmdir "%WOLFSSHLIB_TRG_DIR%" /S /Q
    if exist "%WOLFSSHLIB_TRG_DIR%" (
        SET COPYERROR=true
        echo;
        echo WARNING: Failed to remove %WOLFSSHLIB_TRG_DIR%
        echo;
        echo Check permissions, open files, read-only attributes, etc.
        echo;
    )

    
    echo;
) else (
    echo;
    echo Prior %WOLFSSHLIB_TRG_DIR% not found, installing fresh.
    echo;
)


::******************************************************************************************************
:REFRESH
::******************************************************************************************************
if not exist "%WOLFSSHLIB_TRG_DIR%"                 mkdir      "%WOLFSSHLIB_TRG_DIR%"
if not exist "%WOLFSSHLIB_TRG_DIR%\wolfssh"         mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfssh\"
if not exist "%WOLFSSHLIB_TRG_DIR%\include"         mkdir      "%WOLFSSHLIB_TRG_DIR%\include\"
if not exist "%WOLFSSHLIB_TRG_DIR%\src"             mkdir      "%WOLFSSHLIB_TRG_DIR%\src\"
if not exist "%WOLFSSHEXP_TRG_DIR%"                 mkdir      "%WOLFSSHEXP_TRG_DIR%"

::******************************************************************************************************
:: optionally copy wolfssl here (the default is to use the parent directory shared component)
::******************************************************************************************************
if "%REPLICATE_WOLFSSL%" == "true" (
   REM note we copy wolfcrypt from wolfssl component
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\"                      mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\"
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\"            mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\"
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\"                  mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\"
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\"             mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\"
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\Atmel\"       mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\Atmel\"
   if not exist "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\Espressif\"   mkdir      "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\port\Espressif\"
)

echo;
echo Copying files to %WOLFSSHLIB_TRG_DIR%\src\
xcopy "%BASEDIR%\src\*.c"                                                 "%WOLFSSHLIB_TRG_DIR%\src\"                              /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

::******************************************************************************************************
:: optionally copy wolfssl here (the default is to use the parent directory shared component)
::******************************************************************************************************
if "%REPLICATE_WOLFSSL%" == "true" (
   echo Copying port/Atmel files to %WOLFSSHLIB_TRG_DIR%\src\port\Atmel 
   xcopy "%BASEDIR%\src\port\Atmel\*.c "                                     "%WOLFSSHLIB_TRG_DIR%\src\port\Atmel"                    /Q /Y
   if %errorlevel% NEQ 0 SET COPYERROR=true

   echo Copying port/Espressif files to %WOLFSSHLIB_TRG_DIR%\src\port\Espressif 
   xcopy "%BASEDIR%\src\port\Espressif\*.c"                                  "%WOLFSSHLIB_TRG_DIR%\src\port\Espressif"                /Q /Y
   if %errorlevel% NEQ 0 SET COPYERROR=true

   echo Copying wolfSSL component src\*.c files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src
   xcopy "%WOLFSSLLIB_TRG_DIR%\wolfcrypt\src\*.c"                            "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\"              /S /E /Q /Y
   if %errorlevel% NEQ 0 SET COPYERROR=true

   echo Copying src\*.i files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src
   xcopy "%WOLFSSLLIB_TRG_DIR%\wolfcrypt\src\*.i"                            "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\"              /S /E /Q /Y
   if %errorlevel% NEQ 0 SET COPYERROR=true

   echo Copying files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\
   xcopy "%WOLFSSLLIB_TRG_DIR%\wolfcrypt\benchmark"                          "%WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\"        /S /E /Q /Y
   if %errorlevel% NEQ 0 SET COPYERROR=true
)

echo Copying files to %WOLFSSHLIB_TRG_DIR%\wolfssh\
xcopy "%BASEDIR%\wolfssh\*.h"                                                "%WOLFSSHLIB_TRG_DIR%\wolfssh\"                     /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

::******************************************************************************************************
:: optionally copy wolfssl here (the default is to use the parent directory shared component)
::******************************************************************************************************
if "%REPLICATE_WOLFSSL%" == "true" (
   echo;
   echo Replicating  %WOLFSSLLIB_TRG_DIR%\wolfssl\  to  %WOLFSSHLIB_TRG_DIR%\wolfssl\
   if not EXIST "%WOLFSSHLIB_TRG_DIR%\wolfssl\"   mkdir   "%WOLFSSHLIB_TRG_DIR%\wolfssl\"
   if not EXIST "%WOLFSSHLIB_TRG_DIR%\wolfssl\"   mkdir   "%WOLFSSHLIB_TRG_DIR%\wolfssl\wolfcrypt\"

   xcopy  "%WOLFSSLLIB_TRG_DIR%\wolfssl\*.*"              "%WOLFSSHLIB_TRG_DIR%\wolfssl\"
   xcopy  "%WOLFSSLLIB_TRG_DIR%\wolfssl\wolfcrypt\*.*"    "%WOLFSSHLIB_TRG_DIR%\wolfssl\wolfcrypt\"
)

::******************************************************************************************************
:: config file
::******************************************************************************************************
echo;
echo Copying config files to %WOLFSSHLIB_TRG_DIR%\include\
echo;

:: Check if operator wants to keep prior config.h
if EXIST config_h_%FileStamp%.bak (
    echo;
    echo Found prior config.h in  "%SCRIPTDIR%\config_h_%FileStamp%.bak"
    echo;
    dir "config_h_%FileStamp%.bak" | findstr config_h_%FileStamp%.bak
    echo;

    REM clear any prior errorlevel
    call;
    choice /c YN /m "Use prior config.h  in  %WOLFSSHLIB_TRG_DIR%\include\ "
    if ERRORLEVEL 2 GOTO :NO_CONFIG_RESTORE

    REM
    REM this is just a placeholder for side-by-side code alignment with setup.sh
    REM

    echo /* new config */                                          > "%WOLFSSHLIB_TRG_DIR%\include\config.h"
    call;
    xcopy "config_h_%FileStamp%.bak"                                 "%WOLFSSHLIB_TRG_DIR%\include\config.h" /Y
    
    
    if %errorlevel% NEQ 0 SET COPYERROR=true

) else (
    REM a config_h_%FileStamp%.bak file does not exist
    echo;
    echo Prior config.h not found. (and one is not desired; it should be in wolfssl)
    echo;

    if "%WOLFSSH_FORCE_CONFIG%" == "true" (
        echo /* new config  */ >                                         "%WOLFSSHLIB_TRG_DIR%\include\config.h"
        call;
        if exist "%WOLFSSH_ESPIDFDIR%\dummy_config_h." (
            echo Using default file dummy_config_h for ssh component in  "%WOLFSSHLIB_TRG_DIR%\include\config.h" 
            xcopy "%WOLFSSH_ESPIDFDIR%\dummy_config_h."                  "%WOLFSSHLIB_TRG_DIR%\include\config.h"  /F /Y
            if "%ERRORLEVEL%" NEQ "0" SET COPYERROR=true
        ) else (
            echo;
            echo WARNING: Prior config.h not found and dummy_config_h default available. Using placeholder.
        )
    )
)

::******************************************************************************************************
:NO_CONFIG_RESTORE
::******************************************************************************************************
:: Check if operator wants to keep prior user_settings.h
if EXIST "user_settings_h_%FileStamp%.bak" (
    echo;
    echo Found prior user_settings.h in  %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
    echo;
    dir user_settings_h_%FileStamp%.bak | findstr user_settings_h_%FileStamp%.bak
    echo;

    REM clear any prior errorlevel
    call;
    choice /c YN /m "Use prior user_settings.h  in  %WOLFSSHLIB_TRG_DIR%\include\ "
    if ERRORLEVEL 2 GOTO :NO_USER_SETTINGS_RESTORE

    REM Create a placeholder file so we don't get prompted for file or directory with xcopy
    echo /* new config  */ >                                         "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h"
    REM

    echo;
    call;
    xcopy "user_settings_h_%FileStamp%.bak"                          "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" /Y
    if %errorlevel% NEQ 0 SET COPYERROR=true

    REM TODO do we really need to replicate the user_settings.h here for wolfSSH?
    if EXIST "${WOLFSSHLIB_TRG_DIR}/wolfssl/include/user_settings.h"  (
        xcopy "user_settings_h_%FileStamp%.bak"                      "%WOLFSSHLIB_TRG_DIR%\wolfssl\include\user_settings.h" /Y
        if %errorlevel% NEQ 0 SET COPYERROR=true
    )
    REM space placeholder for side-by-side, line-by-line Linux script comparison
    REM
) else (
    REM user_settings_h_%FileStamp%.bak not found
    echo;
    echo;
    REM TODO do we really need to replicate the user_settings.h here? It does seem the compiler wants one.
    echo Prior user_settings.h not found.  
    echo /* new file */ >                      "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h"

    if exist "%WOLFSSLLIB_TRG_DIR%\include\user_settings.h" (
        echo Using file: "%WOLFSSLLIB_TRG_DIR%\include\user_settings.h"
        xcopy "%WOLFSSLLIB_TRG_DIR%\include\user_settings.h"  "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h"  /Y
    ) else (
        echo;
        echo WARNING: No %WOLFSSLLIB_TRG_DIR%\include\user_settings.h file found
        echo;
        echo Created placeholder. Edit %WOLFSSHLIB_TRG_DIR%\include\user_settings.h
    )
    echo;
)

::******************************************************************************************************
:NO_USER_SETTINGS_RESTORE
::******************************************************************************************************

echo;
echo Copying libs\CMakeLists.txt to %WOLFSSHLIB_TRG_DIR%\
xcopy "%WOLFSSH_ESPIDFDIR%\libs\CMakeLists.txt"                "%WOLFSSHLIB_TRG_DIR%\"                             /F
if %errorlevel% NEQ 0 GOTO :COPYERR

echo Copying libs\component.mk to %WOLFSSHLIB_TRG_DIR%\
xcopy "%WOLFSSH_ESPIDFDIR%\libs\component.mk"                  "%WOLFSSHLIB_TRG_DIR%\"                             /F
if %errorlevel% NEQ 0 GOTO :COPYERR

:: TODO determine what happened to ssl x509_str.c (we get a compile error when this is missing):
if not exist "%WOLFSSHLIB_TRG_DIR%\src\x509_str.c" (
    echo /* placeholder */    > "%WOLFSSHLIB_TRG_DIR%\src\x509_str.c"
    echo Created  placeholder   "%WOLFSSHLIB_TRG_DIR%\src\x509_str.c"
)

:: TODO determine what happened to ssh x509_str.c (we get a compile error when this is missing):
if not exist "%WOLFSSLLIB_TRG_DIR%\src\x509_str.c" (
    echo /* placeholder */    > "%WOLFSSLLIB_TRG_DIR%\src\x509_str.c"
    echo Created placeholder    "%WOLFSSLLIB_TRG_DIR%\src\x509_str.c"
)

::******************************************************************************************************
:: check if there's a wolfssl/options.h
::******************************************************************************************************
echo Checking for %WOLFSSLLIB_TRG_DIR%\wolfssl\options.h
if exist "%WOLFSSLLIB_TRG_DIR%\wolfssl\options.h" (
    echo;
    echo WARNING: options.h found in "%WOLFSSLLIB_TRG_DIR%\wolfssl\"
    echo;
    echo Consider using a project user_settings.h and #define WOLFSSL_USER_SETTINGS
) else (
    echo Confirmed no options.h file; will expect user_settings.h
)

goto :DONE

:: error during copy encountered
::******************************************************************************************************
:COPYERR
::******************************************************************************************************
echo;
echo Error during copy.
echo;
echo Please ensure none of the target files are flagged as read-only, open, etc.
goto :ERR

:: abort at user request
::******************************************************************************************************
:NOCOPY
::******************************************************************************************************
echo;
echo Setup did not copy any files.
goto :ERR

:: ERROR
::******************************************************************************************************
:ERR
::******************************************************************************************************
exit /B 1

:: Success
::******************************************************************************************************
:DONE
::******************************************************************************************************
echo;
echo;
echo See Component files for wolfSSH in %WOLFSSHLIB_TRG_DIR%
echo;
echo See additional examples at https://github.com/wolfSSL/wolfssh/tree/master/examples
echo;
echo REMINDER: Ensure any wolfSSL #include definitions occur BEFORE include files in your source code.
echo;
if "%COPYERROR%" == "true" (
    echo;
    echo WARNING: Copy completed with errors! Check for files in use, permissions, symbolic links, etc.
    echo;
)

echo Configuration files found:
:: ssl
where /R %WOLFSSLLIB_TRG_DIR%\ config.h         2> nul
where /R %WOLFSSLLIB_TRG_DIR%\ options.h        2> nul
where /R %WOLFSSLLIB_TRG_DIR%\ user_settings.h  2> nul
:: ssh
where /R %WOLFSSHLIB_TRG_DIR%\ config.h         2> nul
where /R %WOLFSSHLIB_TRG_DIR%\ options.h        2> nul
where /R %WOLFSSHLIB_TRG_DIR%\ user_settings.h  2> nul


:: Remind of backup files
if exist %SCRIPTDIR%\config_h_%FileStamp%.bak (
    echo;
    echo Your prior config.h file was saved to:    %SCRIPTDIR%\config_h_%FileStamp%.bak
)

if exist %SCRIPTDIR%\user_settings_h_%FileStamp%.bak (
    echo Your prior user_settings.h was saved to:  %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
    echo;
)

:: Check to ensure we have a valid Expressif chip defined

if EXIST "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" (
    SET FOUND_ESP=false
    echo Looking for Espressif WOLFSSL_ESPWROOM32, WOLFSSL_ESPWROOM32SE, or WOLFSSL_ESP8266 in user_settings.h
    echo;

    type "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" | findstr /C:"#define WOLFSSL_ESPWROOM32"   2> nul
    if "%ERRORLEVEL%" == "0" (SET FOUND_ESP=true)

    type "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" | findstr /C:"#define WOLFSSL_ESPWROOM32SE" 2> nul
    if "%ERRORLEVEL%" == "0" (SET FOUND_ESP=true)

    type "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" | findstr /C:"#define WOLFSSL_ESP8266"      2> nul
    if "%ERRORLEVEL%" == "0" (SET FOUND_ESP=true)

    if "%FOUND_ESP%" == "false" (echo WARNING: did not find an Espressif define in "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" )
    REM
    REM 
) else (
    echo;
    echo WARNING: File not found: "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h"
)

echo;
echo Review config file in  "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" before compiling.
echo;

echo setup_win.bat for wolfSSH (Secure Shell) ESP-IDF component install completed.
