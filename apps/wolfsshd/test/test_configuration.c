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
#include <wolfssl/wolfcrypt/coding.h>
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


void Log(const char *const fmt, ...) FMTCHECK;
void Log(const char *const fmt, ...)
{
    va_list vlist;

    va_start(vlist, fmt);
    vfprintf(stderr, fmt, vlist);
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
        {"Bare multiplier m (no digit)", "LoginGraceTime m", 1},
        {"Bare multiplier h (no digit)", "LoginGraceTime h", 1},

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
                                  (int)WSTRLEN(vectors[i].line), 0);

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
#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
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

/* Verifies that a Match block override of the auth-relevant settings is the
 * value returned by wolfSSHD_GetUserConf, and that it differs from the global
 * node. RequestAuthentication and DoCheckUser resolve the per-user config via
 * wolfSSHD_AuthGetUserConf (a wrapper around wolfSSHD_GetUserConf) before
 * consulting PwAuth, PermitEmptyPw, PermitRootLogin and AuthKeysFileSet, so
 * this locks in that resolution: a regression that reverts to the global node
 * would be caught here.
 *
 * Coverage note: the new fail-closed branches in DoCheckUser and
 * RequestAuthentication (rejecting auth when wolfSSHD_AuthGetUserConf returns
 * NULL, and the Match-aware PermitRootLogin check) are not exercised directly.
 * Those paths require a populated WOLFSSHD_AUTH context (opaque to this test)
 * plus real system users, group lookups, callbacks, and privilege raising, so
 * they are validated here only at the config-resolution layer they depend on.
 * The auth-boundary enforcement itself (a tightened Match node is honored, and
 * a NULL per-user config rejects rather than falls through to the global node)
 * is covered by manual/integration testing of wolfsshd against an sshd_config
 * containing a Match block that disables password auth and PermitRootLogin. */
static int test_GetUserConfMatchOverride(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;
    WOLFSSHD_CONFIG* other;

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    /* permissive global settings */
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords yes");
    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin yes");

    /* Match block tightens the auth settings for testuser. Lines after the
     * Match keyword apply to the newly created per-user node, leaving the
     * global head node unchanged. */
    if (ret == WS_SUCCESS) ret = PCL("Match User testuser");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords no");
    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin no");
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedKeysFile .ssh/match_keys");
#undef PCL

    /* the global head node must keep the permissive values */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 1 ||
            wolfSSHD_ConfigGetPermitEmptyPw(head) != 1 ||
            wolfSSHD_ConfigGetPermitRoot(head) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* resolving testuser must return the per-user node, not the global head */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "testuser", NULL, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }

    /* the resolved node must carry the tightened (overridden) values, i.e. the
     * ones RequestAuthentication and DoCheckUser will now enforce */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) != 0 ||
            wolfSSHD_ConfigGetPermitEmptyPw(match) != 0 ||
            wolfSSHD_ConfigGetPermitRoot(match) != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(match) == 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFile(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetAuthKeysFile(match),
                    ".ssh/match_keys") != 0)
            ret = WS_FATAL_ERROR;
    }

    /* a user with no Match block must fall back to the permissive global head,
     * confirming the default behavior is unchanged for non-Match users */
    if (ret == WS_SUCCESS) {
        other = wolfSSHD_GetUserConf(head, "otheruser", NULL, NULL, NULL,
                                     NULL, NULL, NULL);
        if (other != head)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* Bounded recursion through Include directives: a self-including config
 * must fail with WS_BAD_ARGUMENT once the depth limit is hit, and the
 * config object must remain usable so a subsequent load of a normal
 * config on the same WOLFSSHD_CONFIG still succeeds. */
static int test_IncludeRecursionBound(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf = NULL;
    WFILE* f = NULL;
    const char* loopPath = "./include_loop.conf";
    const char* normalPath = "./include_normal.conf";
    const char* loopContents = "Include ./include_loop.conf\n";
    const char* normalContents = "Port 22\n";
    word32 sz, wr;

    WFOPEN(NULL, &f, loopPath, "w");
    if (f == NULL) {
        Log("    Could not create %s.\n", loopPath);
        return WS_FATAL_ERROR;
    }
    sz = (word32)WSTRLEN(loopContents);
    wr = (word32)WFWRITE(NULL, loopContents, sizeof(char), sz, f);
    WFCLOSE(NULL, f);
    if (sz != wr) {
        WREMOVE(0, loopPath);
        return WS_FATAL_ERROR;
    }

    WFOPEN(NULL, &f, normalPath, "w");
    if (f == NULL) {
        WREMOVE(0, loopPath);
        Log("    Could not create %s.\n", normalPath);
        return WS_FATAL_ERROR;
    }
    sz = (word32)WSTRLEN(normalContents);
    wr = (word32)WFWRITE(NULL, normalContents, sizeof(char), sz, f);
    WFCLOSE(NULL, f);
    if (sz != wr) {
        WREMOVE(0, loopPath);
        WREMOVE(0, normalPath);
        return WS_FATAL_ERROR;
    }

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: self-include hits depth bound.");
        if (wolfSSHD_ConfigLoad(conf, loopPath) == WS_BAD_ARGUMENT) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: config reusable after failed include.");
        if (wolfSSHD_ConfigLoad(conf, normalPath) == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    wolfSSHD_ConfigFree(conf);
    WREMOVE(0, loopPath);
    WREMOVE(0, normalPath);
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

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
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

#ifdef WOLFSSL_BASE64_ENCODE
/* Build a mutable "ssh-rsa <base64(key)>" line; WSTRTOK mutates in place. */
static int BuildAuthKeysLine(const byte* key, word32 keySz,
                             char* lineOut, word32 lineOutSz)
{
    static const char prefix[] = "ssh-rsa ";
    word32 prefixLen = (word32)(sizeof(prefix) - 1);
    word32 b64Sz;

    if (lineOutSz <= prefixLen) {
        return WS_BUFFER_E;
    }
    WMEMCPY(lineOut, prefix, prefixLen);
    b64Sz = lineOutSz - prefixLen;
    if (Base64_Encode_NoNl(key, keySz, (byte*)lineOut + prefixLen, &b64Sz)
            != 0) {
        return WS_FATAL_ERROR;
    }
    /* Base64_Encode_NoNl does not null-terminate; do it ourselves. */
    if (prefixLen + b64Sz >= lineOutSz) {
        return WS_BUFFER_E;
    }
    lineOut[prefixLen + b64Sz] = '\0';
    return WS_SUCCESS;
}

/* Negative-path coverage for CheckAuthKeysLine so mutation of the
 * ConstantCompare clause (the only substantive bytewise check after the
 * length comparison) does not survive the test suite. */
static int test_CheckAuthKeysLine(void)
{
    int ret = WS_SUCCESS;
    /* Three equal-length payloads. keyB differs from keyA throughout;
     * keyALastByte differs from keyA only in the final byte -- this is the
     * case that kills a "delete the ConstantCompare" mutation, since the
     * length comparison alone would accept it. */
    static const char keyAStr[] = "wolfssh-auth-key-test-A-AAAAAAA";
    static const char keyBStr[] = "wolfssh-auth-key-test-B-BBBBBBB";
    const byte* keyA = (const byte*)keyAStr;
    const byte* keyB = (const byte*)keyBStr;
    const word32 keySz = (word32)(sizeof(keyAStr) - 1);
    byte keyALastByte[sizeof(keyAStr) - 1];
    char line[256];
    char lineCopy[256];
    int rc;

    WMEMCPY(keyALastByte, keyA, keySz);
    keyALastByte[keySz - 1] ^= 0x01;

    ret = BuildAuthKeysLine(keyA, keySz, line, sizeof(line));
    if (ret != WS_SUCCESS) {
        return ret;
    }

    Log("    Testing scenario: matching key authenticates.");
    WMEMCPY(lineCopy, line, WSTRLEN(line) + 1);
    rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy),
                           keyA, keySz);
    if (rc == WSSHD_AUTH_SUCCESS) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED (rc=%d).\n", rc);
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: different same-length key is rejected.");
        WMEMCPY(lineCopy, line, WSTRLEN(line) + 1);
        rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy),
                               keyB, keySz);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: same-length key differing in last byte is "
            "rejected.");
        WMEMCPY(lineCopy, line, WSTRLEN(line) + 1);
        rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy),
                               keyALastByte, keySz);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* WOLFSSL_BASE64_ENCODE */

#ifndef _WIN32
static WGID_T s_setregid_arg0, s_setregid_arg1;
static WUID_T s_setreuid_arg0, s_setreuid_arg1;
static int    s_setregid_ret;
static int    s_setreuid_ret;
static int    s_setregid_called;
static int    s_setreuid_called;

static int stub_setregid(WGID_T rgid, WGID_T egid)
{
    s_setregid_called = 1;
    s_setregid_arg0   = rgid;
    s_setregid_arg1   = egid;
    return s_setregid_ret;
}

static int stub_setreuid(WUID_T ruid, WUID_T euid)
{
    s_setreuid_called = 1;
    s_setreuid_arg0   = ruid;
    s_setreuid_arg1   = euid;
    return s_setreuid_ret;
}

static void InstallPrivDropStubs(int regidRet, int reuidRet,
    int (**savedRegid)(WGID_T, WGID_T),
    int (**savedReuid)(WUID_T, WUID_T))
{
    *savedRegid       = wsshd_setregid_cb;
    *savedReuid       = wsshd_setreuid_cb;
    wsshd_setregid_cb = stub_setregid;
    wsshd_setreuid_cb = stub_setreuid;
    s_setregid_ret    = regidRet;
    s_setreuid_ret    = reuidRet;
    s_setregid_called = 0;
    s_setreuid_called = 0;
    s_setregid_arg0   = s_setregid_arg1 = 0;
    s_setreuid_arg0   = s_setreuid_arg1 = 0;
}

static int test_AuthReducePermissionsUser_ok(void)
{
    int    ret     = WS_SUCCESS;
    WUID_T testUid = 1001;
    WGID_T testGid = 1002;
    int (*savedRegid)(WGID_T, WGID_T);
    int (*savedReuid)(WUID_T, WUID_T);

    InstallPrivDropStubs(0, 0, &savedRegid, &savedReuid);

    if (wolfSSHD_AuthReducePermissionsUser(NULL, testUid, testGid)
            != WS_SUCCESS)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setregid_called)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS
            && (s_setregid_arg0 != testGid || s_setregid_arg1 != testGid))
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setreuid_called)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS
            && (s_setreuid_arg0 != testUid || s_setreuid_arg1 != testUid))
        ret = WS_FATAL_ERROR;

    wsshd_setregid_cb = savedRegid;
    wsshd_setreuid_cb = savedReuid;
    return ret;
}

static int test_AuthReducePermissionsUser_gid_fail(void)
{
    int ret = WS_SUCCESS;
    int (*savedRegid)(WGID_T, WGID_T);
    int (*savedReuid)(WUID_T, WUID_T);

    InstallPrivDropStubs(-1, 0, &savedRegid, &savedReuid);

    if (wolfSSHD_AuthReducePermissionsUser(NULL, 1001, 1002)
            != WS_FATAL_ERROR)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setregid_called)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && s_setreuid_called)
        ret = WS_FATAL_ERROR;

    wsshd_setregid_cb = savedRegid;
    wsshd_setreuid_cb = savedReuid;
    return ret;
}

static int test_AuthReducePermissionsUser_uid_fail(void)
{
    int ret = WS_SUCCESS;
    int (*savedRegid)(WGID_T, WGID_T);
    int (*savedReuid)(WUID_T, WUID_T);

    InstallPrivDropStubs(0, -1, &savedRegid, &savedReuid);

    if (wolfSSHD_AuthReducePermissionsUser(NULL, 1001, 1002)
            != WS_FATAL_ERROR)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setreuid_called)
        ret = WS_FATAL_ERROR;

    wsshd_setregid_cb = savedRegid;
    wsshd_setreuid_cb = savedReuid;
    return ret;
}
#endif /* !_WIN32 */

/* Locks in the NULL-safe comparison used by RequestAuthentication to fail
 * closed when a Match block's TrustedUserCAKeys differs from the global one.
 * Covers all four permutations: both NULL (equal), exactly one NULL (differ),
 * equal strings (equal), and differing strings (differ). */
static int test_CAKeysFileDiffers(void)
{
    int ret = WS_SUCCESS;
    static const char caA[] = "/etc/ssh/ca_a.pem";
    static const char caB[] = "/etc/ssh/ca_b.pem";
    static const char caADup[] = "/etc/ssh/ca_a.pem";

    Log("    Testing scenario: both NULL compares equal.");
    if (CAKeysFileDiffers(NULL, NULL) != 0) {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: NULL vs non-NULL compares different.");
        if (CAKeysFileDiffers(NULL, caA) != 1 ||
            CAKeysFileDiffers(caA, NULL) != 1) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: equal strings compare equal.");
        if (CAKeysFileDiffers(caA, caADup) != 0) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: differing strings compare different.");
        if (CAKeysFileDiffers(caA, caB) != 1) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    return ret;
}

const TEST_CASE testCases[] = {
    TEST_DECL(test_ConfigDefaults),
    TEST_DECL(test_ParseConfigLine),
    TEST_DECL(test_ConfigCopy),
    TEST_DECL(test_GetUserConfMatchOverride),
    TEST_DECL(test_CAKeysFileDiffers),
    TEST_DECL(test_IncludeRecursionBound),
    TEST_DECL(test_ConfigFree),
#ifdef WOLFSSL_BASE64_ENCODE
    TEST_DECL(test_CheckAuthKeysLine),
#endif
#ifndef _WIN32
    TEST_DECL(test_AuthReducePermissionsUser_ok),
    TEST_DECL(test_AuthReducePermissionsUser_gid_fail),
    TEST_DECL(test_AuthReducePermissionsUser_uid_fail),
#endif
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
