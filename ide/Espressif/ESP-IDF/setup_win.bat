@echo off
REM Expect the script at /path/to/wolfssh/IDE/Espressif/ESP-IDF/

::******************************************************************************************************
::******************************************************************************************************
echo;
echo wolfSSH (Secure Shell) Windows Setup. Version 0.1b
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
SET COPYERROR=false
pause

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
if "%1" == "" (
    if exist "%IDF_PATH%" (
        echo Using IDF_PATH: %IDF_PATH%
    ) 
) else (
    if not exist "%1" (
        echo "ERROR: optional directory was specified, but not found: %1"
        goto :ERR
    )

    SET IDF_PATH=%1
    echo Using specified IDF_PATH: %IDF_PATH%
)

:: if no IDF_PATH is found, we don't know what to do. Go exit with error.
if "%IDF_PATH%" == "" (
  echo Please launch the script from ESP-IDF command prompt,
  echo or set your desired IDF_PATH environment variable,
  echo or pass a parameter to your directory, such as for VisualGDB with ESP-IDF 4.4:
  echo;
  echo   .\setup_win.bat C:\SysGCC\esp32\esp-idf\v4.4
  echo;
  goto :ERR
)

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

if exist %WOLFSSLLIB_TRG_DIR% (
    echo Using WOLFSSLLIB_TRG_DIR = %WOLFSSLLIB_TRG_DIR%
    echo;
) else (
    echo ERROR: this wolfSSH component depends on the wolfSSL component.
    echo;
    echo See https://github.com/wolfSSL/wolfssl for more info
    echo;
    goto :ERR
)

echo Using WOLFSSH_ESPIDFDIR  = %WOLFSSH_ESPIDFDIR%
echo Using WOLFSSHLIB_TRG_DIR = %WOLFSSHLIB_TRG_DIR%
echo Using WOLFSSHEXP_TRG_DIR = %WOLFSSHEXP_TRG_DIR%



echo;
echo Equivalalent destination path:
dir %WOLFSSH_ESPIDFDIR%\*.xyzzy 2> nul | findstr  \

echo;
echo Equivalalent wolfSSL source directory paths:
:: show the path of the equivalent  %VALUE% (search for files that don't exist, supress error, and look for string with "\")

dir %WOLFSSLLIB_TRG_DIR%\*.xyzzy 2> nul | findstr  \

echo;
echo Equivalalent wolfSSH source directory paths:

dir %BASEDIR%\*.xyzzy 2> nul | findstr  \
dir %WOLFSSHLIB_TRG_DIR%\*.xyzzy 2> nul | findstr  \
dir %WOLFSSHEXP_TRG_DIR%\*.xyzzy 2> nul | findstr  \

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

:: Backup existing user settings
if exist %WOLFSSHLIB_TRG_DIR%\include\config.h (
  echo;
  echo Saving: %WOLFSSHLIB_TRG_DIR%\include\config.h
  echo     to: %SCRIPTDIR%\config_h_%FileStamp%.bak
  copy         %WOLFSSHLIB_TRG_DIR%\include\config.h      %SCRIPTDIR%\config_h_%FileStamp%.bak
  echo;
)

:: if exist %WOLFSSH_ESPIDFDIR%\user_settings.h (
::   echo Saving: %WOLFSSHLIB_TRG_DIR%\include\user_settings.h
::   echo     to: %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
::  copy         %WOLFSSHLIB_TRG_DIR%\include\user_settings.h      %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
::  echo;
:: )


::******************************************************************************************************
:: check if there's already an existing %WOLFSSHLIB_TRG_DIR% and confirm removal
::******************************************************************************************************
if exist %WOLFSSHLIB_TRG_DIR% (
    echo;
    echo WARNING: Existing files found in %WOLFSSHLIB_TRG_DIR%
    echo;

    :: clear any prior errorlevel
    call;
    choice /c YN /m "Delete files and proceed with install in %WOLFSSHLIB_TRG_DIR%  "
    if errorlevel 2 GOTO :NODELETE
    GOTO :PURGE


    echo;
    echo Ready to copy files into %IDF_PATH%


::******************************************************************************************************
:NODELETE
::******************************************************************************************************
  :: clear any prior errorlevel
    echo;
    call;
    choice /c YN /m "Refresh files %WOLFSSHLIB_TRG_DIR%   (there will be a prompt to keep or overwrite config)  "
    if errorlevel 2 GOTO :NOCOPY
    GOTO :REFRESH
)


::******************************************************************************************************
:PURGE
::******************************************************************************************************
:: purge existing directory

if exist %WOLFSSHLIB_TRG_DIR% (
    echo;
    echo Removing %WOLFSSHLIB_TRG_DIR%
    rmdir %WOLFSSHLIB_TRG_DIR% /S /Q
    if exist %WOLFSSHLIB_TRG_DIR% (
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
if not exist %WOLFSSHLIB_TRG_DIR%                 mkdir      %WOLFSSHLIB_TRG_DIR%
if not exist %WOLFSSHLIB_TRG_DIR%\include         mkdir      %WOLFSSHLIB_TRG_DIR%\include\
if not exist %WOLFSSHLIB_TRG_DIR%\src             mkdir      %WOLFSSHLIB_TRG_DIR%\src\
:: note we copy wolfcrypt from wolfssl component
if not exist %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src   mkdir      %WOLFSSHLIB_TRG_DIR%\wolfcrypt\
if not exist %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src   mkdir      %WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\
if not exist %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src   mkdir      %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\
if not exist %WOLFSSHLIB_TRG_DIR%\wolfssh         mkdir      %WOLFSSHLIB_TRG_DIR%\wolfssh\


rem copying ... files in src/ into $WOLFSSHLIB_TRG_DIR%/src
echo;
echo Copying files to %WOLFSSHLIB_TRG_DIR%\src\
xcopy %BASEDIR%\src\*.c                                      %WOLFSSHLIB_TRG_DIR%\src\                        /S /E /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

echo;
echo Copying wolfSSL component src\*.c files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src
xcopy %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src\*.c                            %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\              /S /E /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

echo;
echo Copying src\*.i files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src
xcopy %WOLFSSLLIB_TRG_DIR%\wolfcrypt\src\*.i                            %WOLFSSHLIB_TRG_DIR%\wolfcrypt\src\              /S /E /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

echo;
echo Copying files to %WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\
xcopy %WOLFSSLLIB_TRG_DIR%\wolfcrypt\benchmark                          %WOLFSSHLIB_TRG_DIR%\wolfcrypt\benchmark\        /S /E /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

echo;
echo Copying files to %WOLFSSHLIB_TRG_DIR%\wolfssh\
xcopy %BASEDIR%\wolfssh\*.h                                  %WOLFSSHLIB_TRG_DIR%\wolfssh\                    /S /E /Q /Y
if %errorlevel% NEQ 0 SET COPYERROR=true

:: TODO do we really need to replicate the entire wolfssl directory here?
echo;
echo Replicating  %WOLFSSLLIB_TRG_DIR%\wolfssl\  to  %WOLFSSHLIB_TRG_DIR%\wolfssl\
if not EXIST %WOLFSSHLIB_TRG_DIR%\wolfssl\   mkdir   %WOLFSSHLIB_TRG_DIR%\wolfssl\
xcopy  %WOLFSSLLIB_TRG_DIR%\wolfssl\*.*              %WOLFSSHLIB_TRG_DIR%\wolfssl\ /s /e

::******************************************************************************************************
:: user_settings and config defaults
::******************************************************************************************************
echo;
echo Copying user config files to %WOLFSSHLIB_TRG_DIR%\include\
echo;



:: Check if operator wants to keep prior config.h
if EXIST config_h_%FileStamp%.bak (
    echo;
    echo Found prior config.h in  %SCRIPTDIR%\config_h_%FileStamp%.bak
    echo;
    dir config_h_%FileStamp%.bak | findstr config_h_%FileStamp%.bak
    echo;

    :: clear any prior errorlevel
    call;
    choice /c YN /m "Use prior config.h  in  %WOLFSSHLIB_TRG_DIR%\include\ "
    if errorlevel 2 GOTO :NO_CONFIG_RESTORE

    echo new config                                            >  %WOLFSSHLIB_TRG_DIR%\include\config.h
    call;
    xcopy config_h_%FileStamp%.bak                                %WOLFSSHLIB_TRG_DIR%\include\config.h /Y
    if %errorlevel% NEQ 0 SET COPYERROR=true

) else (
    echo;
    echo Prior config.h not found. Using default file.
    echo;

    echo new config                                            > %WOLFSSHLIB_TRG_DIR%\include\config.h
    call;
    xcopy  %WOLFSSH_ESPIDFDIR%\dummy_config_h.                   %WOLFSSHLIB_TRG_DIR%\include\config.h             /F /Y
    if %errorlevel% NEQ 0 SET COPYERROR=true
)
::******************************************************************************************************
:NO_CONFIG_RESTORE
::******************************************************************************************************

:: Check if operator wants to keep prior config.h
if EXIST user_settings_h_%FileStamp%.bak (
    echo;
    echo Found prior user_settings.h in  %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
    echo;
    dir user_settings_h_%FileStamp%.bak | findstr user_settings_h_%FileStamp%.bak
    echo;

    :: clear any prior errorlevel
    call;
    choice /c YN /m "Use prior user_settings.h  in  %WOLFSSHLIB_TRG_DIR%\include\ "
    if errorlevel 2 GOTO :NO_USER_SETTINGS_RESTORE

    echo;
    call;
    xcopy user_settings_h_%FileStamp%.bak    %WOLFSSHLIB_TRG_DIR%\include\user_settings.h /Y
    if %errorlevel% NEQ 0 SET COPYERROR=true

    :: TODO do we really need to replicate the user_settings.h here?
    xcopy user_settings_h_%FileStamp%.bak    %WOLFSSHLIB_TRG_DIR%\wolfssl\include\user_settings.h /Y
    if %errorlevel% NEQ 0 SET COPYERROR=true
) else (
    echo;
    :: TODO do we really need to replicate the user_settings.h here?
    echo Prior user_settings.h not found.  Using file:  %WOLFSSLLIB_TRG_DIR%\include\user_settings.h
    echo new file >                                     %WOLFSSHLIB_TRG_DIR%\include\user_settings.h
    xcopy %WOLFSSLLIB_TRG_DIR%\include\user_settings.h  %WOLFSSHLIB_TRG_DIR%\include\user_settings.h  /Y

    echo;
)

::******************************************************************************************************
:NO_USER_SETTINGS_RESTORE
::******************************************************************************************************


echo;
echo Copying CMakeLists.txt to %WOLFSSHLIB_TRG_DIR%\
xcopy %WOLFSSH_ESPIDFDIR%\libs\CMakeLists.txt                %WOLFSSHLIB_TRG_DIR%\                             /F
if %errorlevel% NEQ 0 GOTO :COPYERR

echo;
echo Copying component.mk to %WOLFSSHLIB_TRG_DIR%\
xcopy %WOLFSSH_ESPIDFDIR%\libs\component.mk                  %WOLFSSHLIB_TRG_DIR%\                             /F
if %errorlevel% NEQ 0 GOTO :COPYERR

:: TODO determine what happened to ssl x509_str.c (we get a compile error when this is missing):
if not exist %WOLFSSHLIB_TRG_DIR%\src\x509_str.c (
    echo;
    echo # > %WOLFSSHLIB_TRG_DIR%\src\x509_str.c
    echo Copied  placeholder %WOLFSSHLIB_TRG_DIR%\src\x509_str.c
)
:: echo C:/Users/gojimmypi/Desktop/esp-idf/components/wolfssl/src/x509_str.c
:: echo %WOLFSSHLIB_TRG_DIR%\src\x509_str.c

:: TODO determine what happened to ssh x509_str.c (we get a compile error when this is missing):
if not exist %WOLFSSLLIB_TRG_DIR%\src\x509_str.c (
    echo;
    echo # > %WOLFSSLLIB_TRG_DIR%\src\x509_str.c
    echo Created placeholder %WOLFSSLLIB_TRG_DIR%\src\x509_str.c
)
:: echo C:/Users/gojimmypi/Desktop/esp-idf/components/wolfssl/src/x509_str.c
:: echo %WOLFSSLLIB_TRG_DIR%\src\x509_str.c
goto :DONE

:: error during copy encountered
::******************************************************************************************************
:COPYERR
::******************************************************************************************************
echo;
echo Error during copy.
echo
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
echo Edit config file in  "%WOLFSSHLIB_TRG_DIR%\include\user_settings.h" before trying to compile.
echo;
echo See Component files for wolfSSL in %WOLFSSHLIB_TRG_DIR%
echo;
echo See additional examples at  https://github.com/wolfSSL/wolfssl-examples
echo;
echo REMINDER: Ensure any wolfSSL #include definitions occur BEFORE include files in your source code.
echo;
if "%COPYERROR%" == "true" (
    echo;
    echo WARNING: Copy completed with errors! Check for files in use, permissions, symbolic links, etc.
    echo;
)

:: Remind of backup files
if exist %SCRIPTDIR%\config_h_%FileStamp%.bak (
    echo;
    echo Your prior config.h file was saved to:    %SCRIPTDIR%\config_h_%FileStamp%.bak
)

if exist %SCRIPTDIR%\user_settings_h_%FileStamp%.bak (
    echo Your prior user_settings.h was saved to:  %SCRIPTDIR%\user_settings_h_%FileStamp%.bak
    echo;
)
echo;
echo setup_win.bat for wolfSSH (Secure Shell) ESP-IDF component install completed.
