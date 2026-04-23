/* Match auth.c's feature-test macros so crypt() is declared and so the
 * pre-existing CleanupWildcardTest code keeps seeing DT_DIR. Must come
 * before any system header is pulled in. */
#ifdef __linux__
    #ifndef _XOPEN_SOURCE
        #define _XOPEN_SOURCE
    #endif
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif
#endif

#include <stdarg.h>
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
    #include <unistd.h>
#endif
#ifdef HAVE_CRYPT_H
    #include <crypt.h>
#endif

#include <wolfssh/ssh.h>
#include <configuration.h>
#include <auth.h>

#ifndef WOLFSSH_DEFAULT_LOG_WIDTH
    #define WOLFSSH_DEFAULT_LOG_WIDTH 120
#endif

#undef FMTCHECK
#ifdef __GNUC__
    #define FMTCHECK __attribute__((format(printf,1,2)))
#else
    #define FMTCHECK
#endif /* __GNUC__ */


void Log(const char *const, ...) FMTCHECK;
void Log(const char *const fmt, ...)
{
    va_list vlist;
    char    msgStr[WOLFSSH_DEFAULT_LOG_WIDTH];

    va_start(vlist, fmt);
    WVSNPRINTF(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);
}

static void CleanupWildcardTest(void)
{
    WDIR dir;
    struct dirent* d;
    char filepath[MAX_PATH*2]; /* d_name is max_path long */
    size_t prefixLen;
    size_t maxNameLen;

    prefixLen  = WSTRLEN("./sshd_config.d/");
    maxNameLen = sizeof(filepath) - prefixLen - 1; /* -1 for null terminator */
    if (!WOPENDIR(NULL, NULL, &dir, "./sshd_config.d/")) {
        while ((d = WREADDIR(NULL, &dir)) != NULL) {
        #if defined(__QNX__) || defined(__QNXNTO__)
            struct stat s;

            lstat(d->d_name, &s);
            if (!S_ISDIR(s.st_mode))
        #else
            if (d->d_type != DT_DIR)
        #endif
            {
                WSNPRINTF(filepath, sizeof filepath, "%.*s%.*s",
                        (int)prefixLen, "./sshd_config.d/",
                        (int)maxNameLen, d->d_name);
                WREMOVE(0, filepath);
            }
        }
        WCLOSEDIR(NULL, &dir);
        WRMDIR(0, "./sshd_config.d/");
    }
}

static int SetupWildcardTest(void)
{
    WFILE* f;
    const byte fileIds[] = { 0, 1, 50, 59, 99 };
    word32 fileIdsSz = (word32)(sizeof(fileIds) / sizeof(byte));
    word32 i;
    int ret;
    char filepath[MAX_PATH];

    ret = WMKDIR(0, "./sshd_config.d/", 0755);

    if (ret == 0) {
        for (i = 0; i < fileIdsSz; i++) {
            if (fileIds[i] != 0) {
                WSNPRINTF(filepath, sizeof filepath, "%s%02u-test.conf",
                        "./sshd_config.d/", fileIds[i]);
            }
            else {
                WSNPRINTF(filepath, sizeof filepath, "%stest.bad",
                        "./sshd_config.d/");
            }

            WFOPEN(NULL, &f, filepath, "w");
            if (f) {
                word32 sz, wr;
                char contents[20];
                WSNPRINTF(contents, sizeof contents, "LoginGraceTime %02u",
                        fileIds[i]);
                sz = (word32)WSTRLEN(contents);
                wr = (word32)WFWRITE(NULL, contents, sizeof(char), sz, f);
                WFCLOSE(NULL, f);
                if (sz != wr) {
                    Log("Couldn't write the contents of file %s\n", filepath);
                    ret = WS_FATAL_ERROR;
                    break;
                }
            }
            else {
                Log("Couldn't create the file %s\n", filepath);
                ret = WS_FATAL_ERROR;
                break;
            }
        }
    }
    else {
        Log("Couldn't make the test config directory\n");
        ret = WS_FATAL_ERROR;
    }

    return ret;
}

typedef int (*TEST_FUNC)(void);
typedef struct {
    const char *name;
    TEST_FUNC func;
} TEST_CASE;

#define TEST_DECL(func) { #func, func }

#define TEST_CASE_CNT (int)(sizeof(testCases) / sizeof(*testCases))

static void TestSetup(const TEST_CASE* tc)
{
    Log("Running %s.\n", tc->name);
}

static void TestCleanup(void)
{
}

static int RunTest(const TEST_CASE* tc)
{
    int ret;

    TestSetup(tc);

    ret = tc->func();
    if (ret != 0) {
        fprintf(stderr, "%s FAILED (ret=%d).\n", tc->name, ret);
    }
    else {
        fprintf(stderr, "%s PASSED.\n", tc->name);
    }

    TestCleanup();

    return ret;
}

typedef struct {
    const char* desc;
    const char* line;
    int shouldFail;
} CONFIG_LINE_VECTOR;

static int test_ConfigDefaults(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_MEMORY_E;

    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetGraceTime(conf) != 120)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPort(conf) != 22)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(conf) == 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(conf);
    return ret;
}

static int test_ParseConfigLine(void)
{
    int ret = WS_SUCCESS;
    int i;
    WOLFSSHD_CONFIG* conf;

    static CONFIG_LINE_VECTOR vectors[] = {
        /* Port tests. */
        {"Valid port", "Port 22", 0},
        {"Port too big", "Port 65536", 1},
        {"Negative port", "Port -99", 1},
        {"Port 0", "Port 0", 1},
        {"Port NaN", "Port wolfsshd", 1},
        {"Port no value", "Port \n", 1},

        /* Whitespace tests. */
        {"Extra leading whitespace", "Port   22", 0},
        {"Extra trailing whitespace", "Port 22   \n", 0},

        /* Privilege separation tests. */
        {"Privilege separation yes", "UsePrivilegeSeparation yes", 0},
        {"Privilege separation no", "UsePrivilegeSeparation no", 0},
        {"Privilege separation sandbox", "UsePrivilegeSeparation sandbox", 0},
        {"Privilege separation invalid", "UsePrivilegeSeparation wolfsshd", 1},

        /* Login grace time tests. */
        {"Valid login grace time seconds", "LoginGraceTime 60", 0},
        {"Valid login grace time minutes", "LoginGraceTime 1m", 0},
        {"Valid login grace time hours", "LoginGraceTime 1h", 0},
        {"Invalid login grace time", "LoginGraceTime wolfsshd", 1},

        /* Permit empty password tests. */
        {"Permit empty password no", "PermitEmptyPasswords no", 0},
        {"Permit empty password yes", "PermitEmptyPasswords yes", 0},
        {"Permit empty password invalid", "PermitEmptyPasswords wolfsshd", 1},

        /* Password auth tests. */
        {"Password auth no", "PasswordAuthentication no", 0},
        {"Password auth yes", "PasswordAuthentication yes", 0},
        {"Password auth invalid", "PasswordAuthentication wolfsshd", 1},

        /* Include files tests. */
        {"Include file bad", "Include sshd_config.d/test.bad", 1},
        {"Include file exists", "Include sshd_config.d/01-test.conf", 0},
        {"Include file DNE", "Include sshd_config.d/test-dne.conf", 1},
        {"Include wildcard exists", "Include sshd_config.d/*.conf", 0},
        {"Include wildcard NDE", "Include sshd_config.d/*.dne", 0},
    };
    const int numVectors = (int)(sizeof(vectors) / sizeof(*vectors));

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        for (i = 0; i < numVectors; ++i) {
            Log("    Testing scenario: %s.", vectors[i].desc);

            ret = ParseConfigLine(&conf, vectors[i].line,
                                  (int)WSTRLEN(vectors[i].line));

            if ((ret == WS_SUCCESS && !vectors[i].shouldFail) ||
                (ret != WS_SUCCESS && vectors[i].shouldFail)) {
                Log(" PASSED.\n");
                ret = WS_SUCCESS;
            }
            else {
                Log(" FAILED.\n");
                ret = WS_FATAL_ERROR;
                break;
            }
        }
        wolfSSHD_ConfigFree(conf);
    }

    return ret;
}

static int test_ConfigCopy(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

    /* string fields via ParseConfigLine */
#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s))
    if (ret == WS_SUCCESS) ret = PCL("Banner /etc/issue");
    if (ret == WS_SUCCESS) ret = PCL("ChrootDirectory /var/chroot");
    if (ret == WS_SUCCESS) ret = PCL("HostKey /etc/ssh/ssh_host_key");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/restricted");
    if (ret == WS_SUCCESS) ret = PCL("PidFile /var/run/sshd.pid");

    /* string fields via public setters */
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetHostCertFile(head, "/etc/ssh/host_cert.pub");
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetUserCAKeysFile(head, "/etc/ssh/ca.pub");
    /* AuthorizedKeysFile must go through PCL so authKeysFileSet flag is set */
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedKeysFile .ssh/authorized_keys");

    /* scalar fields */
    if (ret == WS_SUCCESS) ret = PCL("Port 2222");
    if (ret == WS_SUCCESS) ret = PCL("LoginGraceTime 30");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords yes");
    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin yes");
    if (ret == WS_SUCCESS) ret = PCL("UsePrivilegeSeparation sandbox");

    /* trigger ConfigCopy via Match; conf advances to the new node */
    if (ret == WS_SUCCESS) ret = PCL("Match User testuser");
#undef PCL

    /* retrieve match node from the list head */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "testuser", NULL, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }

    /* verify string fields were copied */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetBanner(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetBanner(match), "/etc/issue") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetChroot(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetChroot(match), "/var/chroot") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetHostKeyFile(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetHostKeyFile(match),
                    "/etc/ssh/ssh_host_key") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetHostCertFile(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetHostCertFile(match),
                    "/etc/ssh/host_cert.pub") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetUserCAKeysFile(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetUserCAKeysFile(match),
                    "/etc/ssh/ca.pub") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFile(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetAuthKeysFile(match),
                    ".ssh/authorized_keys") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetForcedCmd(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetForcedCmd(match),
                    "/bin/restricted") != 0)
            ret = WS_FATAL_ERROR;
    }

    /* verify authKeysFileSet flag was copied */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(match) == 0)
            ret = WS_FATAL_ERROR;
    }

    /* verify scalar fields were copied */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPort(match) != 2222)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetGraceTime(match) != 30)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) == 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPermitEmptyPw(match) == 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPermitRoot(match) == 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPrivilegeSeparation(match) != WOLFSSHD_PRIV_SANDBOX)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* Verifies ConfigFree releases all string fields - most useful under ASan. */
static int test_ConfigFree(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s))
    if (ret == WS_SUCCESS) ret = PCL("Banner /etc/issue");
    if (ret == WS_SUCCESS) ret = PCL("ChrootDirectory /var/chroot");
    if (ret == WS_SUCCESS) ret = PCL("HostKey /etc/ssh/ssh_host_key");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/restricted");
    if (ret == WS_SUCCESS) ret = PCL("PidFile /var/run/sshd.pid");
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetHostCertFile(head, "/etc/ssh/host_cert.pub");
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetUserCAKeysFile(head, "/etc/ssh/ca.pub");
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetAuthKeysFile(head, ".ssh/authorized_keys");

    /* Match User - allocates usrAppliesTo on the copied node */
    if (ret == WS_SUCCESS) ret = PCL("Match User alice");

    /* Match Group - allocates groupAppliesTo on the next copied node */
    if (ret == WS_SUCCESS) ret = PCL("Match Group staff");
#undef PCL

    /* Free must not crash and must release every allocation */
    wolfSSHD_ConfigFree(head);
    return ret;
}

#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
/* Negative-path coverage for CheckPasswordHashUnix so mutation of the
 * ConstantCompare clause (the only substantive check once crypt() has
 * produced its fixed-length output) does not survive the test suite. */
static int test_CheckPasswordHashUnix(void)
{
    int ret = WS_SUCCESS;
    const char* correct = "wolfssh-test-pass";
    const char* wrong   = "wolfssh-test-wrong";
    /* SHA-512 crypt salt; portable across glibc-based crypt() impls. */
    const char* salt = "$6$wolfsshtestsalt$";
    char stored[128];
    char* hash;
    int rc;

    hash = crypt(correct, salt);
    if (hash == NULL || hash[0] == '*' || WSTRLEN(hash) == 0) {
        Log("    crypt() unavailable or refused salt, skipping.\n");
        return WS_SUCCESS;
    }
    if (WSTRLEN(hash) >= sizeof(stored)) {
        return WS_FATAL_ERROR;
    }
    WMEMCPY(stored, hash, WSTRLEN(hash) + 1);

    Log("    Testing scenario: correct password authenticates.");
    rc = CheckPasswordHashUnix(correct, stored);
    if (rc == WSSHD_AUTH_SUCCESS) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: wrong password is rejected.");
        rc = CheckPasswordHashUnix(wrong, stored);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* WOLFSSH_HAVE_LIBCRYPT || WOLFSSH_HAVE_LIBLOGIN */

const TEST_CASE testCases[] = {
    TEST_DECL(test_ConfigDefaults),
    TEST_DECL(test_ParseConfigLine),
    TEST_DECL(test_ConfigCopy),
    TEST_DECL(test_ConfigFree),
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
    TEST_DECL(test_CheckPasswordHashUnix),
#endif
};

int main(int argc, char** argv)
{
    int i;
    int ret = WS_SUCCESS;

    (void)argc;
    (void)argv;

    CleanupWildcardTest();
    ret = SetupWildcardTest();

    if (ret == 0) {
        for (i = 0; i < TEST_CASE_CNT; ++i) {
            ret = RunTest(&testCases[i]);
            if (ret != WS_SUCCESS) {
                break;
            }
        }
    }

    CleanupWildcardTest();

    return ret;
}
