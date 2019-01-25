/* port.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
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


/*
 * The port module wraps standard C library functions with macros to
 * cover portablility issues when building in environments that rename
 * those functions. This module also provides local versions of some
 * standard C library functions that are missing on some platforms.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif


#include <wolfssh/port.h>
#ifndef USE_WINDOWS_API
    #include <stdio.h>
#endif


#ifndef NO_FILESYSTEM
int wfopen(WFILE** f, const char* filename, const char* mode)
{
#ifdef USE_WINDOWS_API
    return fopen_s(f, filename, mode) != 0;
#elif defined(WOLFSSL_NUCLEUS)
    int m = WOLFSSH_O_CREAT;

    if (WSTRSTR(mode, "r") && WSTRSTR(mode, "w")) {
        m |= WOLFSSH_O_RDWR;
    }
    else {
        if (WSTRSTR(mode, "r")) {
            m |= WOLFSSH_O_RDONLY;
        }
        if (WSTRSTR(mode, "w")) {
            m |= WOLFSSH_O_WRONLY;
        }
    }

    if (filename != NULL && f != NULL) {
        if ((**f = WOPEN(filename, m, 0)) < 0) {
            return **f;
        }

        /* fopen defaults to normal */
        if (NU_Set_Attributes(filename, 0) != NU_SUCCESS) {
            WCLOSE(**f);
            return 1;
        }
        return 0;
    }
    else {
        return 1;
    }
#else
    if (f != NULL) {
        *f = fopen(filename, mode);
        return *f == NULL;
    }
    return 1;
#endif
}

#if 0
#if defined(USE_WINDOWS_API) && (defined(WOLFSSH_SFTP) || \
    defined(WOLFSSH_SCP)) && !defined(NO_WOLFSSH_SERVER)
int wPwrite(WFD fd, unsigned char* buf, unsigned int sz, long ofst)
{
    OVERLAPPED offset;
    DWORD bytesWritten;
    int ret;

    WMEMSET(&offset, 0, sizeof(OVERLAPPED));
    offset.Offset = (DWORD)(ofst & 0xFFFFFFFF);
    offset.OffsetHigh = (DWORD)((ofst & 0xFFFFFFFF00000000) >> 32);
    if (WriteFile((HANDLE)_get_osfhandle(fd), buf, sz, &bytesWritten, &offset) == 0)
        ret = -1;
    else
        ret = (int)bytesWritten;

    return ret;
}


int wPread(WFD fd, unsigned char* buf, unsigned int sz, long ofst)
{
    OVERLAPPED offset;
    DWORD bytesRead;
    int ret;

    WMEMSET(&offset, 0, sizeof(OVERLAPPED));
    offset.Offset = (DWORD)(ofst & 0xFFFFFFFF);
    offset.OffsetHigh = (DWORD)((ofst & 0xFFFFFFFF00000000) >> 32);
    if (ReadFile((HANDLE)_get_osfhandle(fd), buf, sz, &bytesRead, &offset) == 0) {
        if (GetLastError() == ERROR_HANDLE_EOF) {
            ret = 0; /* return 0 for end of file */
        }
        else {
            ret = -1;
        }
    }
    else
        ret = (int)bytesRead;

    return ret;
}

#endif /* USE_WINDOWS_API */
#endif
#endif /* !NO_FILESYSTEM */


#ifdef USE_WINDOWS_API

void* WS_CreateFileA(const char* fileName, unsigned long desiredAccess,
        unsigned long shareMode, unsigned long creationDisposition,
        unsigned long flags, void* heap)
{
    HANDLE fileHandle;
    wchar_t* unicodeFileName;
    size_t unicodeFileNameSz = 0;
    size_t returnSz = 0;
    size_t fileNameSz = 0;
    errno_t error;

    fileNameSz = WSTRLEN(fileName);
    error = mbstowcs_s(&unicodeFileNameSz, NULL, 0, fileName, 0);
    if (error)
        return INVALID_HANDLE_VALUE;

    unicodeFileName = (wchar_t*)WMALLOC(unicodeFileNameSz, heap, 0);
    if (unicodeFileName == NULL)
        return INVALID_HANDLE_VALUE;

    error = mbstowcs_s(&returnSz, unicodeFileName, unicodeFileNameSz,
        fileName, fileNameSz);

    if (!error)
        fileHandle = CreateFileW(unicodeFileName, desiredAccess, shareMode,
                NULL, creationDisposition, flags, NULL);

    WFREE(unicodeFileName, heap, 0);

    return (void*)(error ? INVALID_HANDLE_VALUE : fileHandle);
}

void* WS_FindFirstFileA(const char* fileName,
        char* realFileName, size_t realFileNameSz, int* isDir, void* heap)
{
    HANDLE findHandle;
    WIN32_FIND_DATAW findFileData;
    wchar_t* unicodeFileName;
    size_t unicodeFileNameSz = 0;
    size_t returnSz = 0;
    size_t fileNameSz = 0;
    errno_t error;

    fileNameSz = WSTRLEN(fileName);
    error = mbstowcs_s(&unicodeFileNameSz, NULL, 0, fileName, 0);
    if (error)
        return INVALID_HANDLE_VALUE;

    unicodeFileName = (wchar_t*)WMALLOC(unicodeFileNameSz, heap, 0);
    if (unicodeFileName == NULL)
        return INVALID_HANDLE_VALUE;

    error = mbstowcs_s(&returnSz, unicodeFileName, unicodeFileNameSz,
        fileName, fileNameSz);

    if (!error)
        findHandle = FindFirstFileW(unicodeFileName, &findFileData);

    WFREE(unicodeFileName, heap, 0);

    error = wcstombs_s(NULL, realFileName, realFileNameSz,
        findFileData.cFileName, realFileNameSz);

    if (isDir != NULL) {
        *isDir =
            (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    return (void*)findHandle;
}


int WS_FindNextFileA(void* findHandle,
        char* realFileName, size_t realFileNameSz)
{
    BOOL success;
    WIN32_FIND_DATAW findFileData;
    errno_t error;

    success = FindNextFileW((HANDLE)findHandle, &findFileData);

    if (success) {
        error = wcstombs_s(NULL, realFileName, realFileNameSz,
            findFileData.cFileName, realFileNameSz);
    }

    return (success != 0) && (error == 0);
}


int WS_GetFileAttributesExA(const char* fileName, void* fileInfo, void* heap)
{
    BOOL success = 0;
    wchar_t* unicodeFileName;
    size_t unicodeFileNameSz = 0;
    size_t returnSz = 0;
    size_t fileNameSz = 0;
    errno_t error;

    fileNameSz = WSTRLEN(fileName);
    error = mbstowcs_s(&unicodeFileNameSz, NULL, 0, fileName, 0);
    if (error != 0)
        return 0;

    unicodeFileName = (wchar_t*)WMALLOC(unicodeFileNameSz, heap, 0);
    if (unicodeFileName == NULL)
        return 0;

    error = mbstowcs_s(&returnSz, unicodeFileName, unicodeFileNameSz,
        fileName, fileNameSz);

    if (error == 0) {
        success = GetFileAttributesExW(unicodeFileName,
                GetFileExInfoStandard, fileInfo);
    }

    WFREE(unicodeFileName, heap, 0);

    return success != 0;
}

#endif /* USE_WINDOWS_API */


#ifndef WSTRING_USER

char* wstrnstr(const char* s1, const char* s2, unsigned int n)
{
    unsigned int s2_len = (unsigned int)WSTRLEN(s2);

    if (s2_len == 0)
        return (char*)s1;

    while (n >= s2_len && s1[0]) {
        if (s1[0] == s2[0])
            if (WMEMCMP(s1, s2, s2_len) == 0)
                return (char*)s1;
        s1++;
        n--;
    }

    return NULL;
}


/* Returns s1 if successful. Returns NULL if unsuccessful.
 * Copies the characters string s2 onto the end of s1. n is the size of the
 * buffer s1 is stored in. Returns NULL if s2 is too large to fit onto the
 * end of s1 including a null terminator. */
char* wstrncat(char* s1, const char* s2, size_t n)
{
    size_t freeSpace = n - strlen(s1) - 1;

    if (freeSpace >= strlen(s2)) {
        #ifndef USE_WINDOWS_API
            strncat(s1, s2, freeSpace);
        #else
            strncat_s(s1, n, s2, freeSpace);
        #endif
        return s1;
    }

    return NULL;
}

#endif /* WSTRING_USER */
