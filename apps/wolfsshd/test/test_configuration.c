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
#ifndef _WIN32
    #include <unistd.h>
    #include <pwd.h>
#endif
#if !defined(_WIN32) && !(defined(__OSX__) || defined(__APPLE__))
    #include <shadow.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <configuration.h>
#include <auth.h>

#ifndef _WIN32
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/resource.h>
    #include <signal.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <grp.h>
#endif

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
                (void)WREMOVE(NULL, filepath);
            }
        }
        (void)WCLOSEDIR(NULL, &dir);
        (void)WRMDIR(NULL, "./sshd_config.d/");
    }
}

static int SetupWildcardTest(void)
{
    WFILE* f = WBADFILE;
    const byte fileIds[] = { 0, 1, 50, 59, 99 };
    word32 fileIdsSz = (word32)(sizeof(fileIds) / sizeof(byte));
    word32 i;
    int ret;
    char filepath[MAX_PATH];

    ret = WMKDIR(NULL, "./sshd_config.d/", 0755);

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

            if (WFOPEN(NULL, &f, filepath, "w") == 0 && f != WBADFILE) {
                word32 sz, wr;
                int cl;
                char contents[20];
                WSNPRINTF(contents, sizeof contents, "LoginGraceTime %02u",
                        fileIds[i]);
                sz = (word32)WSTRLEN(contents);
                wr = (word32)WFWRITE(NULL, contents, sizeof(char), sz, f);
                cl = WFCLOSE(NULL, f);
                f = WBADFILE;
                /* both can fail from one I/O error, so report the
                 * write first, it is the more specific message */
                if (sz != wr) {
                    Log("Couldn't write the contents of file %s\n", filepath);
                    ret = WS_FATAL_ERROR;
                    break;
                }
                if (cl != 0) {
                    Log("Couldn't close the file %s\n", filepath);
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
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPubKeyAuth(conf) == 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        /* StrictModes defaults to on */
        if (wolfSSHD_ConfigGetStrictModes(conf) != 1)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(conf);
    return ret;
}

/* Pins PermitRootLogin prohibit-password/without-password parsing. */
static int test_PermitRootProhibitPassword(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_MEMORY_E;

    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin prohibit-password");
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPermitRoot(conf) !=
                WOLFSSHD_PERMIT_ROOT_PROHIBIT_PW)
            ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin without-password");
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPermitRoot(conf) !=
                WOLFSSHD_PERMIT_ROOT_PROHIBIT_PW)
            ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin forced-commands-only");
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPermitRoot(conf) !=
                WOLFSSHD_PERMIT_ROOT_FORCED_CMD)
            ret = WS_FATAL_ERROR;
    }
#undef PCL

    if (conf != NULL)
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
        {"Tab delimiter", "Port\t22", 0},
        {"Trailing tabs", "Port 22\t\t\n", 0},

        /* The option matcher requires whitespace (or end of line) after the
         * matched name, so an unknown name that extends a real one must not
         * prefix-match it. Ignore-unknown builds accept such lines with a
         * warning, so only assert rejection where it is observable. */
    #ifndef WOLFSSH_IGNORE_UNKNOWN_CONFIG
        {"Unknown extension of Port", "PortFoo 22", 1},
        {"Unknown extension of HostKey", "HostKeyFoo /tmp/x", 1},
        {"Unknown extension of HostKeyStore", "HostKeyStoreX MY", 1},
        {"Unknown extension of TrustedUserCAStore",
            "wolfSSH_TrustedUserCAStoreX yes", 1},
    #endif
        /* A known keyword in Keyword=value form is a hard error on every
         * build; ignoring it would silently drop the directive. */
        {"Keyword=value form is rejected", "Port=22", 1},

        /* The two store-trust toggles follow the same yes/no/invalid
         * convention as every other boolean option. Note: on builds without
         * WOLFSSH_CERTS support these still parse; only SetupCTX rejects
         * them, so parse success is the right expectation everywhere. */
        {"System CA yes", "wolfSSH_TrustedSystemCAKeys yes", 0},
        {"System CA no", "wolfSSH_TrustedSystemCAKeys no", 0},
        {"System CA invalid", "wolfSSH_TrustedSystemCAKeys wolfsshd", 1},
        {"User CA store yes", "wolfSSH_TrustedUserCAStore yes", 0},
        {"User CA store no", "wolfSSH_TrustedUserCAStore no", 0},
        {"User CA store invalid", "wolfSSH_TrustedUserCAStore wolfsshd", 1},

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
        {"Valid login grace time zero", "LoginGraceTime 0", 0},
        {"Valid login grace time zero minutes", "LoginGraceTime 0m", 0},
        {"Valid login grace time zero hours", "LoginGraceTime 0h", 0},
        {"Invalid zero padded login grace time", "LoginGraceTime 00", 1},

        /* Permit empty password tests. */
        {"Permit empty password no", "PermitEmptyPasswords no", 0},
        {"Permit empty password yes", "PermitEmptyPasswords yes", 0},
        {"Permit empty password invalid", "PermitEmptyPasswords wolfsshd", 1},

        /* Password auth tests. */
        {"Password auth no", "PasswordAuthentication no", 0},
        {"Password auth yes", "PasswordAuthentication yes", 0},
        {"Password auth invalid", "PasswordAuthentication wolfsshd", 1},

        /* Public key auth tests. */
        {"Pubkey auth no", "PubkeyAuthentication no", 0},
        {"Pubkey auth yes", "PubkeyAuthentication yes", 0},
        {"Pubkey auth invalid", "PubkeyAuthentication wolfsshd", 1},

        /* Permit root login tests. */
        {"Permit root login no", "PermitRootLogin no", 0},
        {"Permit root login yes", "PermitRootLogin yes", 0},
        {"Permit root login prohibit-password",
            "PermitRootLogin prohibit-password", 0},
        {"Permit root login without-password",
            "PermitRootLogin without-password", 0},
        {"Permit root login forced-commands-only",
            "PermitRootLogin forced-commands-only", 0},
        {"Permit root login invalid", "PermitRootLogin wolfsshd", 1},

        /* StrictModes tests. */
        {"Strict modes no", "StrictModes no", 0},
        {"Strict modes yes", "StrictModes yes", 0},
        {"Strict modes invalid", "StrictModes wolfsshd", 1},

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
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedUPNDomains corp.example");

    /* string fields via public setters */
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetHostCertFile(head, "/etc/ssh/host_cert.pub");
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetUserCAKeysFile(head, "/etc/ssh/ca.pub");
    /* AuthorizedKeysFile via PCL to also exercise the config-parse path; the
     * authKeysFileSet flag is set either way and must survive the copy */
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedKeysFile .ssh/authorized_keys");

    /* scalar fields */
    if (ret == WS_SUCCESS) ret = PCL("Port 2222");
    if (ret == WS_SUCCESS) ret = PCL("LoginGraceTime 30");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
    /* set to the non-default value so a dropped copy (which would leave the
     * wolfSSHD_ConfigNew default of 1) is caught */
    if (ret == WS_SUCCESS) ret = PCL("PubkeyAuthentication no");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords yes");
    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin yes");
    if (ret == WS_SUCCESS) ret = PCL("UsePrivilegeSeparation sandbox");
    /* set to non-default (default is on) so a dropped copy is detected */
    if (ret == WS_SUCCESS) ret = PCL("StrictModes no");

    /* CA trust flags, non-default so a dropped copy is detected */
    if (ret == WS_SUCCESS) ret = PCL("wolfSSH_TrustedSystemCAKeys yes");
    if (ret == WS_SUCCESS) ret = PCL("wolfSSH_TrustedUserCAStore yes");

#ifdef WOLFSSHD_WIN_STORE_CONFIG
    if (ret == WS_SUCCESS) ret = PCL("HostKeyStore MY");
    if (ret == WS_SUCCESS) ret = PCL("HostKeyStoreSubject wolfSSH Host");
    if (ret == WS_SUCCESS) ret = PCL("HostKeyStoreFlags 0x1000");
    if (ret == WS_SUCCESS) ret = PCL("wolfSSH_WinUserStores MY,Root");
    if (ret == WS_SUCCESS) ret = PCL("wolfSSH_WinUserDwFlags 0x1");
    if (ret == WS_SUCCESS) ret = PCL("wolfSSH_WinUserPvPara subjectName");
#endif

    /* trigger ConfigCopy via Match; conf advances to the new node */
    if (ret == WS_SUCCESS) ret = PCL("Match User testuser");
#undef PCL

    /* retrieve match node from the list head */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "testuser", NULL, 0, NULL, NULL,
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
    /* pubKeyAuth was set to the non-default 'no' (0) on the head, so the copy
     * must carry 0; a dropped copy would surface as the default 1 here */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPubKeyAuth(match) != 0)
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
    if (ret == WS_SUCCESS) {
        /* source set StrictModes off; the copy must carry it over */
        if (wolfSSHD_ConfigGetStrictModes(match) != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthorizedUPNDomains(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetAuthorizedUPNDomains(match),
                    "corp.example") != 0)
            ret = WS_FATAL_ERROR;
    }

    /* CA trust flags must survive the copy */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetSystemCA(match) != 1)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetUserCAStore(match) != 1)
            ret = WS_FATAL_ERROR;
    }

#ifdef WOLFSSHD_WIN_STORE_CONFIG
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetHostKeyStore(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetHostKeyStore(match), "MY") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetHostKeyStoreSubject(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetHostKeyStoreSubject(match),
                    "wolfSSH Host") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetHostKeyStoreFlags(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetHostKeyStoreFlags(match),
                    "0x1000") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetWinUserStores(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetWinUserStores(match), "MY,Root") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetWinUserDwFlags(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetWinUserDwFlags(match), "0x1") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetWinUserPvPara(match) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetWinUserPvPara(match),
                    "subjectName") != 0)
            ret = WS_FATAL_ERROR;
    }
#endif /* WOLFSSHD_WIN_STORE_CONFIG */

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* Verifies a Match block override is returned by wolfSSHD_GetUserConf and
 * differs from the global node; RequestAuthentication/DoCheckUser depend on
 * this resolution for PwAuth, PermitEmptyPw, PermitRootLogin, and
 * AuthKeysFileSet.
 *
 * Not covered here: the fail-closed NULL-config branches and the Match-aware
 * PermitRootLogin modes (prohibit-password, forced-commands-only) need a
 * real WOLFSSHD_AUTH context and system users, so they're covered instead by
 * sshd_permitroot_test.sh, sshd_permitroot_prohibit_password.sh, and
 * sshd_permitroot_forced_cmd.sh. */
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
    if (ret == WS_SUCCESS) ret = PCL("PubkeyAuthentication no");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords no");
    if (ret == WS_SUCCESS) ret = PCL("PermitRootLogin no");
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedKeysFile .ssh/match_keys");
#undef PCL

    /* the global head node must keep the permissive values (pubKeyAuth keeps
     * its default of 1, proving the Match override did not leak to the head) */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 1 ||
            wolfSSHD_ConfigGetPubKeyAuth(head) != 1 ||
            wolfSSHD_ConfigGetPermitEmptyPw(head) != 1 ||
            wolfSSHD_ConfigGetPermitRoot(head) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* resolving testuser must return the per-user node, not the global head */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "testuser", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }

    /* the resolved node must carry the tightened (overridden) values, i.e. the
     * ones RequestAuthentication and DoCheckUser will now enforce */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) != 0 ||
            wolfSSHD_ConfigGetPubKeyAuth(match) != 0 ||
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
        other = wolfSSHD_GetUserConf(head, "otheruser", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (other != head)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* Only the User and Group Match selectors are implemented. A Match block keyed
 * on any other selector (Address, Host, LocalAddress, LocalPort, RDomain) would
 * otherwise be accepted but never apply, a fail-open misconfiguration. Verify
 * that User/Group are accepted while the unsupported selectors are rejected. */
static int test_MatchUnsupportedSelector(void)
{
    int ret = WS_SUCCESS;
    int i;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;

    static CONFIG_LINE_VECTOR vectors[] = {
        /* supported selectors */
        {"Match User", "Match User testuser", 0},
        {"Match Group", "Match Group testgroup", 0},

        /* combined supported selectors must be accepted, in either order */
        {"Match User+Group", "Match User alice Group dev", 0},
        {"Match Group+User", "Match Group dev User alice", 0},

        /* unsupported selectors must be rejected, not silently ignored */
        {"Match Address", "Match Address 10.0.0.0/8", 1},
        {"Match Host", "Match Host example.com", 1},
        {"Match LocalAddress", "Match LocalAddress 192.168.1.1", 1},
        {"Match LocalPort", "Match LocalPort 22", 1},
        {"Match RDomain", "Match RDomain vrf-external", 1},

        /* no-selector forms must also be rejected, not silently accepted */
        {"Match all", "Match all", 1},
        {"Bare Match", "Match", 1},

        /* supported selector with no argument: passes the selector check but
         * fails while parsing the (missing) name, exercising the cleanup of
         * the already allocated config node */
        {"Match User no arg", "Match User", 1},

        /* mixed supported+unsupported selectors must be rejected; the
         * unsupported part must not be silently dropped */
        {"Mixed User+Address", "Match User alice Address 10.0.0.0/8", 1},
        {"Mixed Group+Host", "Match Group dev Host example.com", 1},
    };
    const int numVectors = (int)(sizeof(vectors) / sizeof(*vectors));

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL) {
        ret = WS_MEMORY_E;
    }
    conf = head;

    if (ret == WS_SUCCESS) {
        for (i = 0; i < numVectors; ++i) {
            int rc;

            Log("    Testing scenario: %s.", vectors[i].desc);

            rc = ParseConfigLine(&conf, vectors[i].line,
                                 (int)WSTRLEN(vectors[i].line), 0);

            if ((rc == WS_SUCCESS && !vectors[i].shouldFail) ||
                (rc != WS_SUCCESS && vectors[i].shouldFail)) {
                Log(" PASSED.\n");
            }
            else {
                Log(" FAILED.\n");
                ret = WS_FATAL_ERROR;
                break;
            }
        }
        wolfSSHD_ConfigFree(head);
    }
    return ret;
}

/* A combined 'Match User X Group Y' directive is a conjunction: it applies only
 * to a user who satisfies BOTH selectors, matching OpenSSH semantics. This
 * locks in that wolfSSHD_GetUserConf does not return such a block for a user
 * who satisfies only one selector (the policy-bypass case), while single
 * selector 'Match User' and 'Match Group' blocks keep applying on their one
 * selector alone. */
static int test_GetUserConfMatchGroupAnd(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* combined;
    WOLFSSHD_CONFIG* userOnly;
    WOLFSSHD_CONFIG* groupOnly;
    WOLFSSHD_CONFIG* match;
    const char* grps[1];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    /* restrictive global default: SFTP only for everyone */
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand internal-sftp");

    /* combined block relaxes the restriction, but only for a user who is both
     * 'alice' AND in group 'admins' */
    if (ret == WS_SUCCESS) ret = PCL("Match User alice Group admins");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/sh");
    if (ret == WS_SUCCESS) combined = conf;

    /* single selector blocks must keep matching on their one selector */
    if (ret == WS_SUCCESS) ret = PCL("Match User bob");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/bob");
    if (ret == WS_SUCCESS) userOnly = conf;

    if (ret == WS_SUCCESS) ret = PCL("Match Group staff");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/staff");
    if (ret == WS_SUCCESS) groupOnly = conf;
#undef PCL

    /* alice in admins satisfies both selectors -> gets the combined block */
    if (ret == WS_SUCCESS) {
        grps[0] = "admins";
        match = wolfSSHD_GetUserConf(head, "alice", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != combined)
            ret = WS_FATAL_ERROR;
    }

    /* alice in a different group satisfies only the user selector -> must NOT
     * get the combined block; falls back to the restrictive global head */
    if (ret == WS_SUCCESS) {
        grps[0] = "users";
        match = wolfSSHD_GetUserConf(head, "alice", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    /* carol in admins satisfies only the group selector -> must NOT get the
     * combined block; falls back to the restrictive global head */
    if (ret == WS_SUCCESS) {
        grps[0] = "admins";
        match = wolfSSHD_GetUserConf(head, "carol", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    /* alice with no resolved group must NOT get the combined block: an empty
     * group set cannot satisfy the group selector, so it fails closed to the
     * global head. This is the WIN32 / failed group-lookup path where
     * wolfSSHD_AuthGetUserConf passes an empty group list. */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "alice", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    /* single selector 'Match User bob' still applies on the user alone */
    if (ret == WS_SUCCESS) {
        grps[0] = "anygroup";
        match = wolfSSHD_GetUserConf(head, "bob", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != userOnly)
            ret = WS_FATAL_ERROR;
    }

    /* single selector 'Match Group staff' still applies on the group alone */
    if (ret == WS_SUCCESS) {
        grps[0] = "staff";
        match = wolfSSHD_GetUserConf(head, "anyuser", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != groupOnly)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* A 'Match Group' directive must match on any of the user's groups, primary or
 * supplementary, the way OpenSSH evaluates it. The matcher receives the full
 * group set as a list, so a group named only in a secondary slot still selects
 * the block. The combined 'Match User X Group Y' conjunction must likewise be
 * satisfiable when the group is a secondary one. */
static int test_GetUserConfMatchSecondaryGroup(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* blockWS;
    WOLFSSHD_CONFIG* blockComb;
    WOLFSSHD_CONFIG* match;
    const char* grps[3];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    /* restrictive global default */
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand internal-sftp");

    /* single group selector */
    if (ret == WS_SUCCESS) ret = PCL("Match Group wireshark");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/ws");
    if (ret == WS_SUCCESS) blockWS = conf;

    /* combined user AND group selector */
    if (ret == WS_SUCCESS) ret = PCL("Match User john Group admins");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/adm");
    if (ret == WS_SUCCESS) blockComb = conf;
#undef PCL

    /* wireshark present only in a secondary slot must still select the block */
    if (ret == WS_SUCCESS) {
        grps[0] = "alice";
        grps[1] = "staff";
        grps[2] = "wireshark";
        match = wolfSSHD_GetUserConf(head, "alice", grps, 3, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != blockWS)
            ret = WS_FATAL_ERROR;
    }

    /* combined block satisfied with the group in a secondary slot */
    if (ret == WS_SUCCESS) {
        grps[0] = "john";
        grps[1] = "admins";
        match = wolfSSHD_GetUserConf(head, "john", grps, 2, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != blockComb)
            ret = WS_FATAL_ERROR;
    }

    /* combined block: user matches but group absent -> falls back to head */
    if (ret == WS_SUCCESS) {
        grps[0] = "john";
        grps[1] = "users";
        match = wolfSSHD_GetUserConf(head, "john", grps, 2, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    /* combined block: group matches but user differs -> falls back to head */
    if (ret == WS_SUCCESS) {
        grps[0] = "bob";
        grps[1] = "admins";
        match = wolfSSHD_GetUserConf(head, "bob", grps, 2, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    /* user in none of the selector groups -> falls back to head */
    if (ret == WS_SUCCESS) {
        grps[0] = "carol";
        match = wolfSSHD_GetUserConf(head, "carol", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != head)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* A Match directive whose user name contains the substring "Group" (e.g.
 * "GroupAdmin") must not yield a spurious group applies-to value. The parser is
 * a positional tokenizer, so "Match User GroupAdmin" sets only the user
 * applies-to: a lookup by the real user name resolves to the Match node, while
 * a lookup by the ghost group token ("Admin") must fall back to the global
 * head. This prevents an unrelated OS account whose primary group equals the
 * ghost token from inheriting the Match block's auth overrides. */
static int test_GetUserConfMatchSubstring(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;
    WOLFSSHD_CONFIG* ghost;
    const char* grps[1];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");

    /* user name embeds the "Group" keyword as a substring */
    if (ret == WS_SUCCESS) ret = PCL("Match User GroupAdmin");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
#undef PCL

    /* lookup by the real user name must resolve to the Match node */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "GroupAdmin", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* lookup by the ghost group token ("Admin") must NOT match; it falls back
     * to the permissive-denied global head */
    if (ret == WS_SUCCESS) {
        grps[0] = "Admin";
        ghost = wolfSSHD_GetUserConf(head, NULL, grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (ghost != head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* Symmetric counterpart to test_GetUserConfMatchSubstring: a Match directive
 * whose group name contains the substring "User" (e.g. "UserStaff") must not
 * yield a spurious user applies-to value. "Match Group UserStaff" sets only the
 * group applies-to: a lookup by the real group name resolves to the Match node,
 * while a lookup by the ghost user token ("Staff") must fall back to the global
 * head. This locks in the "User" keyword direction of the positional parser. */
static int test_GetUserConfMatchSubstringGroup(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;
    WOLFSSHD_CONFIG* ghost;
    const char* grps[1];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");

    /* group name embeds the "User" keyword as a substring */
    if (ret == WS_SUCCESS) ret = PCL("Match Group UserStaff");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
#undef PCL

    /* lookup by the real group name must resolve to the Match node */
    if (ret == WS_SUCCESS) {
        grps[0] = "UserStaff";
        match = wolfSSHD_GetUserConf(head, NULL, grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* lookup by the ghost user token ("Staff") must NOT match; it falls back
     * to the permissive-denied global head */
    if (ret == WS_SUCCESS) {
        ghost = wolfSSHD_GetUserConf(head, "Staff", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (ghost != head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* A principal named exactly like the opposite keyword must be handled by token
 * position, not by the embedded keyword. "Match User Group" names a user whose
 * name happens to be "Group": it must set usrAppliesTo="Group" and leave
 * groupAppliesTo unset. The positional parser consumes the token after the
 * "User" keyword as the name and never re-examines it as a keyword, so the
 * "Group" token here is treated as the user name, not the Group keyword. A
 * lookup by user "Group" must resolve to the Match node, while a lookup by
 * group "Group" must fall back to the head. This locks the behavior against a
 * refactor that would treat a name token spelling a keyword as a keyword. */
static int test_GetUserConfMatchLiteralKeywordName(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;
    WOLFSSHD_CONFIG* ghost;
    const char* grps[1];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");

    /* user literally named "Group" (the opposite keyword) at end of line */
    if (ret == WS_SUCCESS) ret = PCL("Match User Group");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
#undef PCL

    /* lookup by the user name "Group" must resolve to the Match node */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "Group", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(match) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* the user name must NOT have leaked into groupAppliesTo: a lookup by group
     * "Group" must fall back to the permissive-denied global head */
    if (ret == WS_SUCCESS) {
        grps[0] = "Group";
        ghost = wolfSSHD_GetUserConf(head, NULL, grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (ghost != head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* A Match directive whose keyword has no following name (e.g. a bare
 * "Match User") is a configuration error and must fail closed: ParseConfigLine
 * returns an error rather than silently loading a dead node that would discard
 * the admin's subsequent settings. The global head must be left untouched. */
static int test_GetUserConfMatchBareKeyword(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");

    /* bare keyword with no name must be rejected */
    if (ret == WS_SUCCESS) {
        rc = PCL("Match User");
        if (rc == WS_SUCCESS)
            ret = WS_FATAL_ERROR;
    }
#undef PCL

    /* the rejected directive must not have altered the global head */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* A keyword repeated on one Match line ("Match User a User b") replaces the
 * earlier name: the parser frees the first usrAppliesTo ("a") before storing
 * the second ("b"). The final value must be "b", so a lookup by user "b"
 * resolves to the Match node while a lookup by the replaced name "a" falls back
 * to the global head. This exercises the free-then-reallocate path (run under
 * ASan to catch a leak or double-free regression). */
static int test_GetUserConfMatchRepeatedKeyword(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* match;
    WOLFSSHD_CONFIG* old;

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication no");

    /* same keyword twice; the second name must replace the first */
    if (ret == WS_SUCCESS) ret = PCL("Match User a User b");
    if (ret == WS_SUCCESS) ret = PCL("PasswordAuthentication yes");
#undef PCL

    /* lookup by the replacement name "b" must resolve to the Match node */
    if (ret == WS_SUCCESS) {
        match = wolfSSHD_GetUserConf(head, "b", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match == NULL || match == head ||
            wolfSSHD_ConfigGetPwAuth(match) != 1)
            ret = WS_FATAL_ERROR;
    }

    /* lookup by the replaced name "a" must NOT match; it falls back to head */
    if (ret == WS_SUCCESS) {
        old = wolfSSHD_GetUserConf(head, "a", NULL, 0, NULL, NULL,
                                   NULL, NULL, NULL);
        if (old != head)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetPwAuth(head) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}

/* writes 'contents' to the file 'path', creating or truncating it.
 * Returns WS_SUCCESS on success. */
static int WriteConfigFile(const char* path, const char* contents)
{
    WFILE* f = WBADFILE;
    word32 sz, wr;
    int ret = WS_SUCCESS;
    int cl;

    if (WFOPEN(NULL, &f, path, "w") != 0 || f == WBADFILE) {
        Log("    Could not create %s.\n", path);
        return WS_FATAL_ERROR;
    }

    sz = (word32)WSTRLEN(contents);
    wr = (word32)WFWRITE(NULL, contents, sizeof(char), sz, f);
    cl = WFCLOSE(NULL, f);

    /* both can fail from one I/O error, report the write first */
    if (sz != wr) {
        Log("    Could not write %s.\n", path);
        ret = WS_FATAL_ERROR;
    }
    else if (cl != 0) {
        Log("    Could not close %s.\n", path);
        ret = WS_FATAL_ERROR;
    }

    return ret;
}


/* Bounded recursion through Include directives: a self-including config
 * must fail with WS_BAD_ARGUMENT once the depth limit is hit, and the
 * config object must remain usable so a subsequent load of a normal
 * config on the same WOLFSSHD_CONFIG still succeeds. */
static int test_IncludeRecursionBound(void)
{
    int ret;
    WOLFSSHD_CONFIG* conf = NULL;
    const char* loopPath = "./include_loop.conf";
    const char* normalPath = "./include_normal.conf";
    const char* loopContents = "Include ./include_loop.conf\n";
    const char* normalContents = "Port 22\n";

    ret = WriteConfigFile(loopPath, loopContents);
    if (ret == WS_SUCCESS) {
        ret = WriteConfigFile(normalPath, normalContents);
    }
    if (ret != WS_SUCCESS) {
        (void)WREMOVE(NULL, loopPath);
        (void)WREMOVE(NULL, normalPath);
        return ret;
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
    (void)WREMOVE(NULL, loopPath);
    (void)WREMOVE(NULL, normalPath);
    return ret;
}

/* Each Match block is built from the global config, not from the Match block
 * before it. A user selected by a later block must not pick up settings that
 * an earlier, non-matching block changed. */
static int test_GetUserConfMatchNoInherit(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* aliceConf = NULL;
    WOLFSSHD_CONFIG* staffConf = NULL;
    WOLFSSHD_CONFIG* match = NULL;
    const char* cmd;
    const char* grps[1];

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL)
        ret = WS_MEMORY_E;
    conf = head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/global");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords yes");

    /* alice's block overrides several of the global settings */
    if (ret == WS_SUCCESS) ret = PCL("Match User alice");
    if (ret == WS_SUCCESS) ret = PCL("ForceCommand /bin/alice");
    if (ret == WS_SUCCESS) ret = PCL("AuthorizedKeysFile .ssh/alice_keys");
    if (ret == WS_SUCCESS) ret = PCL("PermitEmptyPasswords no");
    if (ret == WS_SUCCESS) aliceConf = conf;

    /* the staff block sets one option, everything else must resolve to the
     * global value rather than to alice's */
    if (ret == WS_SUCCESS) ret = PCL("Match Group staff");
    if (ret == WS_SUCCESS) ret = PCL("PubkeyAuthentication no");
    if (ret == WS_SUCCESS) staffConf = conf;
#undef PCL

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: staff user does not inherit alice.");
        grps[0] = "staff";
        match = wolfSSHD_GetUserConf(head, "bob", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != staffConf)
            ret = WS_FATAL_ERROR;

        if (ret == WS_SUCCESS) {
            cmd = wolfSSHD_ConfigGetForcedCmd(match);
            if (cmd == NULL || XSTRCMP(cmd, "/bin/global") != 0)
                ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                wolfSSHD_ConfigGetAuthKeysFileSet(match) != 0) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                wolfSSHD_ConfigGetPermitEmptyPw(match) != 1) {
            ret = WS_FATAL_ERROR;
        }
        /* the staff block's own override still applies */
        if (ret == WS_SUCCESS && wolfSSHD_ConfigGetPubKeyAuth(match) != 0) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: alice keeps her own overrides.");
        grps[0] = "users";
        match = wolfSSHD_GetUserConf(head, "alice", grps, 1, NULL, NULL,
                                     NULL, NULL, NULL);
        if (match != aliceConf)
            ret = WS_FATAL_ERROR;

        if (ret == WS_SUCCESS) {
            cmd = wolfSSHD_ConfigGetForcedCmd(match);
            if (cmd == NULL || XSTRCMP(cmd, "/bin/alice") != 0)
                ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                wolfSSHD_ConfigGetAuthKeysFileSet(match) != 1) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                wolfSSHD_ConfigGetPermitEmptyPw(match) != 0) {
            ret = WS_FATAL_ERROR;
        }
        /* alice is not in staff, so she keeps the global pubkey setting */
        if (ret == WS_SUCCESS && wolfSSHD_ConfigGetPubKeyAuth(match) != 1) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
        }
    }

    wolfSSHD_ConfigFree(head);
    return ret;
}


/* A Match block inside an Include'd file must survive a later Match block in
 * the including file, and the include must not export its Match scope: a
 * directive after the Include belongs to the global config, the way OpenSSH
 * resets Match scope at the end of an included file. */
static int test_ConfigIncludeMatchChain(void)
{
    int ret;
    WOLFSSHD_CONFIG* head = NULL;
    WOLFSSHD_CONFIG* match;
    const char* cmd;
    const char* incPath = "./include_match.conf";
    const char* topPath = "./include_match_top.conf";
    const char* incContents =
        "Match User alice\n"
        "ForceCommand /bin/alice\n";
    const char* topContents =
        "ForceCommand /bin/global\n"
        "Include ./include_match.conf\n"
        "PermitEmptyPasswords yes\n"
        "Match User bob\n"
        "ForceCommand /bin/bob\n";

    ret = WriteConfigFile(incPath, incContents);
    if (ret == WS_SUCCESS) {
        ret = WriteConfigFile(topPath, topContents);
    }
    if (ret != WS_SUCCESS) {
        (void)WREMOVE(NULL, incPath);
        (void)WREMOVE(NULL, topPath);
        return ret;
    }

    head = wolfSSHD_ConfigNew(NULL);
    if (head == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSHD_ConfigLoad(head, topPath);
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: included Match block still applies.");
        match = wolfSSHD_GetUserConf(head, "alice", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        cmd = wolfSSHD_ConfigGetForcedCmd(match);
        if (match == head || cmd == NULL ||
                XSTRCMP(cmd, "/bin/alice") != 0) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: outer Match block still applies.");
        match = wolfSSHD_GetUserConf(head, "bob", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        cmd = wolfSSHD_ConfigGetForcedCmd(match);
        if (match == head || cmd == NULL || XSTRCMP(cmd, "/bin/bob") != 0) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: unmatched user gets the global config.");
        match = wolfSSHD_GetUserConf(head, "carol", NULL, 0, NULL, NULL,
                                     NULL, NULL, NULL);
        cmd = wolfSSHD_ConfigGetForcedCmd(match);
        if (match != head || cmd == NULL ||
                XSTRCMP(cmd, "/bin/global") != 0) {
            ret = WS_FATAL_ERROR;
        }
        /* the include ends inside a Match block, so this proves the directive
         * after it was not swallowed by that block */
        if (ret == WS_SUCCESS &&
                wolfSSHD_ConfigGetPermitEmptyPw(match) != 1) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
        }
    }

    wolfSSHD_ConfigFree(head);
    (void)WREMOVE(NULL, incPath);
    (void)WREMOVE(NULL, topPath);
    return ret;
}


/* The public wolfSSHD_ConfigSetAuthKeysFile setter must mark the authorized
 * keys file as explicitly configured, otherwise certificate public-key logins
 * skip the authorized-keys check and rely on CA validation alone. */
static int test_ConfigSetAuthKeysFile(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_MEMORY_E;

    /* fresh config has no explicit authorized keys file */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(conf) != 0)
            ret = WS_FATAL_ERROR;
    }

    /* configuring a file through the public setter must set the flag */
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetAuthKeysFile(conf, ".ssh/authorized_keys");
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(conf) == 0)
            ret = WS_FATAL_ERROR;
    }

    /* a failed update must leave the existing configuration intact: an
     * all-whitespace file makes CreateString fail, and both the previously
     * configured file and the flag must be untouched, not half cleared */
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigSetAuthKeysFile(conf, " ") == WS_SUCCESS)
            ret = WS_FATAL_ERROR; /* the bad value should have been rejected */
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFile(conf) == NULL ||
            XSTRCMP(wolfSSHD_ConfigGetAuthKeysFile(conf),
                    ".ssh/authorized_keys") != 0)
            ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(conf) == 0)
            ret = WS_FATAL_ERROR;
    }

    /* removing the file must clear the flag again */
    if (ret == WS_SUCCESS)
        ret = wolfSSHD_ConfigSetAuthKeysFile(conf, NULL);
    if (ret == WS_SUCCESS) {
        if (wolfSSHD_ConfigGetAuthKeysFileSet(conf) != 0)
            ret = WS_FATAL_ERROR;
    }

    wolfSSHD_ConfigFree(conf);
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
/* Negative-path coverage for CheckPasswordHashUnix to prevent mutation of
 * the ConstantCompare clause.
 *
 * fakeHashMD5/fakeHashDES fallback is not covered because glibc crypt()
 * returns "*0" rather than NULL, making the branch unreachable here. */
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
    /* Skip if crypt() did not honor the $6$ SHA-512 request. macOS/Darwin and
     * some BSD libc only implement legacy DES, which ignores the modular salt,
     * truncates the password to 8 bytes, and returns a valid-looking 13-char
     * hash that begins "$6l..." (no second '$'). A real $6$ hash begins with
     * "$6$<salt>$", so the prefix check cleanly distinguishes them. */
    if (hash == NULL || hash[0] == '*' || WSTRLEN(hash) == 0 ||
            WSTRNCMP(hash, "$6$", 3) != 0) {
        Log("    crypt() did not honor $6$ SHA-512, skipping.\n");
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

    if (ret == WS_SUCCESS) {
        char empty[1];

        empty[0] = '\0';

        Log("    Empty password + empty stored: ");
        rc = CheckPasswordHashUnix(empty, empty);
        if (rc == WSSHD_AUTH_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        char empty[1];

        empty[0] = '\0';

        Log("    Empty password vs real hash: ");
        rc = CheckPasswordHashUnix(empty, stored);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        char emptyStored[1];

        emptyStored[0] = '\0';

        /* A hardened libxcrypt may reject the degenerate salt outright
         * (crypt() returns NULL -> WS_FATAL_ERROR) rather than proceeding
         * to a mismatched comparison (WSSHD_AUTH_FAILURE); either is a
         * correct "not authenticated" outcome. */
        Log("    Non-empty password vs empty stored: ");
        rc = CheckPasswordHashUnix(correct, emptyStored);
        if (rc == WSSHD_AUTH_FAILURE || rc == WS_FATAL_ERROR) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        char locked[] = "*";

        /* Same NULL-tolerant reasoning as the empty-salt case above. */
        Log("    Locked account (stored[0] == '*'): ");
        rc = CheckPasswordHashUnix(correct, locked);
        if (rc == WSSHD_AUTH_FAILURE || rc == WS_FATAL_ERROR) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        char lockedWithSalt[130];

        /* A locked account starting with '!' exercises salt-reuse instead of
         * fake hash fallback. It must fail auth even with a correct password. */
        lockedWithSalt[0] = '!';
        WMEMCPY(lockedWithSalt + 1, stored, WSTRLEN(stored) + 1);

        Log("    Locked account with reusable '!' salt: ");
        rc = CheckPasswordHashUnix(correct, lockedWithSalt);
        if (rc == WSSHD_AUTH_FAILURE || rc == WS_FATAL_ERROR) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }


    return ret;
}

static int test_DefaultUserAuth_OOBRead(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    char* passwordHeap;
    word32 passwordSz = 16;
    int rc;
    /* Privilege separation off so RequestAuthentication's unconditional
     * wolfSSHD_AuthReducePermissions() -> exit(1) on failure never fires:
     * SetDefaultUserID then uses this process's own uid/gid, making the
     * permission drop a no-op regardless of whether an 'sshd' account
     * exists on the test machine. */
    static const char line[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    if (ParseConfigLine(&conf, line, (int)WSTRLEN(line), 0) != WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        Log("    Skipping test: wolfSSHD_AuthCreateUser failed (likely missing 'sshd' user).\n");
        return WS_SUCCESS;
    }

    passwordHeap = (char*)WMALLOC(passwordSz, NULL, DYNTYPE_STRING);
    if (passwordHeap != NULL) {
        WMEMSET(passwordHeap, 'A', passwordSz);

        WMEMSET(&authData, 0, sizeof(authData));
        authData.type = WOLFSSH_USERAUTH_PASSWORD;
        authData.username = (const byte*)"nonexistent_test_user_xyz";
        authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);
        authData.sf.password.password = (const byte*)passwordHeap;
        authData.sf.password.passwordSz = passwordSz;

        Log("    Testing scenario: DefaultUserAuth with non-NUL-terminated password (OOB read check).");
        rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
        if (rc == WOLFSSH_USERAUTH_INVALID_USER ||
                rc == WOLFSSH_USERAUTH_FAILURE ||
                rc == WOLFSSH_USERAUTH_REJECTED) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }

        WFREE(passwordHeap, NULL, DYNTYPE_STRING);
    }
    else {
        ret = WS_MEMORY_E;
    }

    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

#ifdef WOLFSSHD_HAVE_SHADOW
/* Coverage for GetFakeHashFromTemplate's format-specific branches: bcrypt's
 * fixed-width copy, the dollar-counting split used by SHA/MD5/yescrypt, and
 * the buffer-bound fallbacks that must not overflow `out`. */
static int test_GetFakeHashFromTemplate(void)
{
    int ret = WS_SUCCESS;
    char out[256];

    Log("    Non modular-crypt-format template falls back to '!' alone: ");
    WMEMSET(out, 0, sizeof(out));
    GetFakeHashFromTemplate("plaintextnotahash", out, sizeof(out));
    /* Must be "!" alone, not "!*": CheckPasswordHashUnix only reuses the
     * stored salt when storedSz > 1, so a bare "!" correctly falls through
     * to the fixed-cost fakeHashSHA512 salt instead of reusing a "*" that
     * fails crypt() immediately and skips that cost. */
    if (out[0] == '!' && out[1] == '\0') {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        /* bcrypt: prefix+cost (7) + salt (22) copied, never the 31-byte
         * digest that follows. */
        const char* bcryptTmpl =
            "$2b$12$abcdefghijklmnopqrstuvXYZZYXWVUTSRQPONMLKJIHGFEDCBA";

        Log("    bcrypt template copies only prefix+salt, not digest: ");
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate(bcryptTmpl, out, sizeof(out));
        if (out[0] == '!' && WSTRLEN(out) == 1 + 7 + 22 &&
                WSTRNCMP(out + 1, bcryptTmpl, 4) == 0 &&
                WSTRSTR(out, "XYZZYXWVUTSRQPONMLKJIHGFEDCBA") == NULL &&
                WSTRSTR(out, "abcdefghijklmnopqrstuv") == NULL) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        /* Legacy "$2$NN$" bcrypt has a 6-byte prefix, one shorter than
         * "$2b$NN$"'s 7. */
        const char* bcryptBareTmpl =
            "$2$12$abcdefghijklmnopqrstuvXYZZYXWVUTSRQPONMLKJIHGFEDCBA";

        Log("    Bare \"$2$NN$\" bcrypt template copies only prefix+salt, "
            "not digest: ");
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate(bcryptBareTmpl, out, sizeof(out));
        if (out[0] == '!' && WSTRLEN(out) == 1 + 6 + 22 &&
                WSTRNCMP(out + 1, bcryptBareTmpl, 3) == 0 &&
                WSTRSTR(out, "XYZZYXWVUTSRQPONMLKJIHGFEDCBA") == NULL) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        const char* bcryptTruncated = "$2a$10$tooshort";

        Log("    bcrypt template shorter than salt length is not overrun: ");
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate(bcryptTruncated, out, sizeof(out));
        if (out[0] == '!' &&
                WSTRLEN(out) == 1 + WSTRLEN(bcryptTruncated)) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        /* $6$rounds=5000$salt$digest -- prevDollarIdx sits just before the
         * real salt, so the copied prefix is "$6$rounds=5000$"; both the
         * real salt and digest are dropped and replaced by a fixed dummy
         * salt, keeping only the algorithm id and rounds cost. */
        const char* sha512Tmpl =
            "$6$rounds=5000$realsaltvalue$realdigestshouldnotappearhere";

        Log("    SHA-512 template drops real salt and digest, keeps "
            "prefix+rounds: ");
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate(sha512Tmpl, out, sizeof(out));
        if (WSTRCMP(out, "!$6$rounds=5000$wolfSSHFakeSalt$") == 0 &&
                WSTRSTR(out, "realsaltvalue") == NULL &&
                WSTRSTR(out, "realdigestshouldnotappearhere") == NULL) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        /* Only a single '$' in the whole template: dollarCount < 3, so this
         * must fall back to '!*' rather than reading past the template. */
        const char* singleDollar = "$onlyonedollar";

        Log("    Template with fewer than 3 salt dollars falls back: ");
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate(singleDollar, out, sizeof(out));
        if (out[0] == '!' && WSTRCMP(out + 1, "*") == 0) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        /* A tiny output buffer must not be overrun regardless of template
         * shape or which branch is taken. */
        char tiny[3];
        const char* sha512Tmpl =
            "$6$rounds=5000$realsaltvalue$realdigestshouldnotappearhere";

        Log("    Undersized output buffer is not overrun: ");
        WMEMSET(tiny, 0, sizeof(tiny));
        GetFakeHashFromTemplate(sha512Tmpl, tiny, sizeof(tiny));
        if (tiny[0] == '!' && WSTRLEN(tiny) < sizeof(tiny)) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    NULL template/out and outSz < 3 are rejected without a crash: ");
        GetFakeHashFromTemplate(NULL, out, sizeof(out));
        GetFakeHashFromTemplate("$6$a$b$c", NULL, sizeof(out));
        WMEMSET(out, 0, sizeof(out));
        GetFakeHashFromTemplate("$6$a$b$c", out, 2);
        if (out[0] == '\0') {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* WOLFSSHD_HAVE_SHADOW */


#ifdef WOLFSSHD_HAVE_SHADOW
/* wolfSSHD_AuthInit() (which populates cachedFakeHash) is never called by
 * this suite, so seed it directly to exercise DoFakePasswordCheck(), which
 * RequestAuthentication calls after DoCheckUser rejects the nonexistent
 * user (CheckPasswordUnix is never reached for this username). */
static int test_CachedFakeHashConsumption(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    char* passwordHeap;
    word32 passwordSz = 8;
    int rc;
    static const char line1[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    /* Privilege separation is irrelevant to this test's scenario and its
     * real raise/reduce syscalls require resolving an actual "sshd"
     * account; disable it so the test doesn't depend on host state and
     * doesn't leave the test process's privileges altered for later
     * tests. */
    if (ParseConfigLine(&conf, line1, (int)WSTRLEN(line1), 0) != WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        Log("    Skipping test: wolfSSHD_AuthCreateUser failed (likely missing 'sshd' user).\n");
        return WS_SUCCESS;
    }

    wolfSSHD_SetCachedFakeHashForTest("!$6$wolfsshtestsalt$wolfSSHFakeSalt$");

    passwordHeap = (char*)WMALLOC(passwordSz, NULL, DYNTYPE_STRING);
    if (passwordHeap != NULL) {
        WMEMCPY(passwordHeap, "guessme", passwordSz);

        WMEMSET(&authData, 0, sizeof(authData));
        authData.type = WOLFSSH_USERAUTH_PASSWORD;
        authData.username = (const byte*)"nonexistent_test_user_xyz";
        authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);
        authData.sf.password.password = (const byte*)passwordHeap;
        authData.sf.password.passwordSz = passwordSz;

        Log("    Testing scenario: nonexistent user checked against seeded "
            "cachedFakeHash.");
        rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
        if (rc == WOLFSSH_USERAUTH_FAILURE || rc == WOLFSSH_USERAUTH_REJECTED ||
                rc == WOLFSSH_USERAUTH_INVALID_PASSWORD ||
                rc == WOLFSSH_USERAUTH_INVALID_USER) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }

        WFREE(passwordHeap, NULL, DYNTYPE_STRING);
    }
    else {
        ret = WS_MEMORY_E;
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

/* Synthetic account used to drive CheckPasswordUnix's shadow-lookup
 * branches without depending on the host's real shadow file contents. */
static struct passwd stub_shadow_test_pw;
static struct spwd   stub_shadow_test_sp;
static char          stub_shadow_test_hash[300];

static struct passwd* stub_getpwnam_shadowUser(const char* name)
{
    if (name != NULL && WSTRCMP(name, "shadow_branch_test_user") == 0) {
        WMEMSET(&stub_shadow_test_pw, 0, sizeof(stub_shadow_test_pw));
        stub_shadow_test_pw.pw_name   = (char*)"shadow_branch_test_user";
        stub_shadow_test_pw.pw_uid    = 1002;
        stub_shadow_test_pw.pw_gid    = 1002;
        stub_shadow_test_pw.pw_passwd = (char*)"x";
        return &stub_shadow_test_pw;
    }
    return NULL;
}

static struct passwd* stub_getpwnam_null(const char* name)
{
    (void)name;
    return NULL;
}

static struct spwd* stub_getspnam_null(const char* name)
{
    (void)name;
    return NULL;
}

static struct spwd* stub_getspnam_oversizedHash(const char* name)
{
    (void)name;
    WMEMSET(&stub_shadow_test_sp, 0, sizeof(stub_shadow_test_sp));
    stub_shadow_test_sp.sp_namp = (char*)"shadow_branch_test_user";
    /* hashBuf in CheckPasswordUnix is 256 bytes; this exceeds it. */
    WMEMSET(stub_shadow_test_hash, 'A', sizeof(stub_shadow_test_hash) - 1);
    stub_shadow_test_hash[sizeof(stub_shadow_test_hash) - 1] = '\0';
    stub_shadow_test_sp.sp_pwdp = stub_shadow_test_hash;
    return &stub_shadow_test_sp;
}

/* getspnam() entry exists (e.g. NIS/LDAP-backed root account) but has no
 * password field populated. */
static struct spwd* stub_getspnam_nullPassword(const char* name)
{
    (void)name;
    WMEMSET(&stub_shadow_test_sp, 0, sizeof(stub_shadow_test_sp));
    stub_shadow_test_sp.sp_namp = (char*)"root";
    stub_shadow_test_sp.sp_pwdp = NULL;
    return &stub_shadow_test_sp;
}

/* Unknown user must fall through to the "*" stored hash and fail via
 * CheckPasswordHashUnix, not crash or succeed. */
static int test_CheckPasswordUnix_unknownUser(void)
{
    int ret = WS_SUCCESS;
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
    int rc;
    struct passwd* (*savedGetpwnam)(const char*);
    static const byte pw[] = "guessme";

    savedGetpwnam = wsshd_getpwnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_null;

    rc = CheckPasswordUnix("nonexistent_test_user_xyz", pw,
            (word32)(sizeof(pw) - 1), NULL);
    if (rc != WSSHD_AUTH_FAILURE) {
        Log("    FAILED: expected WSSHD_AUTH_FAILURE for unknown user, "
            "got %d.\n", rc);
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
#else
    (void)stub_getpwnam_null;
    Log("    Skipping test: password hash checking not compiled in.\n");
#endif
    return ret;
}

/* getspnam() failing (e.g. SSHD not run as root) must fail closed rather
 * than silently falling through to compare against the "*" default hash. */
static int test_CheckPasswordUnix_shadowLookupFails(void)
{
    int ret = WS_SUCCESS;
    int rc;
    struct passwd* (*savedGetpwnam)(const char*);
    struct spwd* (*savedGetspnam)(const char*);
    static const byte pw[] = "guessme";

    savedGetpwnam = wsshd_getpwnam_cb;
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    wsshd_getspnam_cb = stub_getspnam_null;

    rc = CheckPasswordUnix("shadow_branch_test_user", pw,
            (word32)(sizeof(pw) - 1), NULL);
    if (rc != WS_FATAL_ERROR) {
        Log("    FAILED: expected WS_FATAL_ERROR when getspnam() fails.\n");
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getspnam_cb = savedGetspnam;
    return ret;
}

/* A shadow hash too long for CheckPasswordUnix's fixed hashBuf must fail
 * closed instead of being silently truncated. */
static int test_CheckPasswordUnix_shadowHashTooLong(void)
{
    int ret = WS_SUCCESS;
    int rc;
    struct passwd* (*savedGetpwnam)(const char*);
    struct spwd* (*savedGetspnam)(const char*);
    static const byte pw[] = "guessme";

    savedGetpwnam = wsshd_getpwnam_cb;
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    wsshd_getspnam_cb = stub_getspnam_oversizedHash;

    rc = CheckPasswordUnix("shadow_branch_test_user", pw,
            (word32)(sizeof(pw) - 1), NULL);
    if (rc != WS_FATAL_ERROR) {
        Log("    FAILED: expected WS_FATAL_ERROR for oversized shadow hash.\n");
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getspnam_cb = savedGetspnam;
    return ret;
}

/* A shadow entry with a NULL sp_pwdp (e.g. an NIS/LDAP-backed account) must
 * fail closed instead of crashing on a NULL dereference in WSTRLEN(). */
static int test_CheckPasswordUnix_shadowNullPassword(void)
{
    int ret = WS_SUCCESS;
    int rc;
    struct passwd* (*savedGetpwnam)(const char*);
    struct spwd* (*savedGetspnam)(const char*);
    static const byte pw[] = "guessme";

    savedGetpwnam = wsshd_getpwnam_cb;
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    wsshd_getspnam_cb = stub_getspnam_nullPassword;

    rc = CheckPasswordUnix("shadow_branch_test_user", pw,
            (word32)(sizeof(pw) - 1), NULL);
    if (rc != WS_FATAL_ERROR) {
        Log("    FAILED: expected WS_FATAL_ERROR for a shadow entry with a "
            "NULL password field, got %d.\n", rc);
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getspnam_cb = savedGetspnam;
    return ret;
}

static struct spwd* stub_getspnam_validHash(const char* name)
{
    (void)name;
    WMEMSET(&stub_shadow_test_sp, 0, sizeof(stub_shadow_test_sp));
    stub_shadow_test_sp.sp_namp = (char*)"shadow_branch_test_user";
    stub_shadow_test_sp.sp_pwdp = stub_shadow_test_hash;
    return &stub_shadow_test_sp;
}

/* Copy-then-succeed path: a normal-length shadow hash copied into
 * CheckPasswordUnix's hashBuf, then compared for real. */
static int test_CheckPasswordUnix_shadowLookupSucceeds(void)
{
    int ret = WS_SUCCESS;
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
    int rc;
    struct passwd* (*savedGetpwnam)(const char*);
    struct spwd* (*savedGetspnam)(const char*);
    static const byte correctPw[] = "guessme";
    static const byte wrongPw[] = "wrongpw";
    /* SHA-512 crypt salt; portable across glibc-based crypt() impls. */
    const char* salt = "$6$wolfsshtestsalt$";
    char* hash;

    hash = crypt((const char*)correctPw, salt);
    /* See test_CheckPasswordHashUnix: some libc (macOS/BSD) ignore the
     * modular salt and fall back to legacy DES, so skip there. */
    if (hash == NULL || hash[0] == '*' || WSTRLEN(hash) == 0 ||
            WSTRNCMP(hash, "$6$", 3) != 0) {
        Log("    crypt() did not honor $6$ SHA-512, skipping.\n");
        return WS_SUCCESS;
    }
    if (WSTRLEN(hash) >= sizeof(stub_shadow_test_hash)) {
        return WS_FATAL_ERROR;
    }
    WMEMCPY(stub_shadow_test_hash, hash, WSTRLEN(hash) + 1);

    savedGetpwnam = wsshd_getpwnam_cb;
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    wsshd_getspnam_cb = stub_getspnam_validHash;

    Log("    Testing scenario: correct password against copied shadow hash.");
    rc = CheckPasswordUnix("shadow_branch_test_user", correctPw,
            (word32)(sizeof(correctPw) - 1), NULL);
    if (rc == WSSHD_AUTH_SUCCESS) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: wrong password against copied shadow hash.");
        rc = CheckPasswordUnix("shadow_branch_test_user", wrongPw,
                (word32)(sizeof(wrongPw) - 1), NULL);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getspnam_cb = savedGetspnam;
#else
    Log("    Skipping test: password hash checking not compiled in.\n");
#endif
    return ret;
}

/* authData->sf is a union; for a non-password auth type DoFakePasswordCheck
 * must not read the password/passwordSz members at all. Poison those exact
 * bytes (invalid pointer, huge length) via the union before tagging the type
 * as PUBLICKEY, so a regression that reinstates an unconditional read would
 * dereference an invalid pointer here instead of quietly working by luck. */
static int test_DoFakePasswordCheck_pubkeyUnionSafety(void)
{
    WS_UserAuthData authData;

    WMEMSET(&authData, 0, sizeof(authData));
    authData.sf.password.password = (const byte*)(size_t)1;
    authData.sf.password.passwordSz = 0xFFFFFFFFU;
    authData.type = WOLFSSH_USERAUTH_PUBLICKEY;

    Log("    Testing scenario: DoFakePasswordCheck with PUBLICKEY type and "
        "poisoned password union fields.");
    DoFakePasswordCheck(&authData);
    Log(" PASSED.\n");

    return WS_SUCCESS;
}

/* Exercises wolfSSHD_AuthInit() itself, rather than just seeding
 * cachedFakeHash through the test hook, to catch regressions in its
 * getspnam("root")/sp_pwdp wiring (wrong struct field, wrong sizeof, etc).
 * Requires read access to the shadow file; skips gracefully otherwise. */
static int test_AuthInit(void)
{
    int ret = WS_SUCCESS;
    struct spwd* rootShadow;
    struct spwd* (*savedGetspnam)(const char*);
    char expected[256];
    char actual[256];

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    /* Force the real getspnam(), independent of what earlier tests left
     * this global as. */
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getspnam_cb = getspnam;

    rootShadow = getspnam("root");
    if (rootShadow == NULL || rootShadow->sp_pwdp == NULL) {
        Log("    Skipping test: no read access to the shadow file "
            "(likely not running as root).\n");
        wsshd_getspnam_cb = savedGetspnam;
        return WS_SUCCESS;
    }

    WMEMSET(expected, 0, sizeof(expected));
    GetFakeHashFromTemplate(rootShadow->sp_pwdp, expected, sizeof(expected));

    /* If the hash is not a valid modular crypt format (e.g. locked '!' or '*'),
     * AuthInit intentionally skips it. Reflect that in expected. */
    if (expected[0] == '\0' || expected[1] == '\0' || expected[1] == '*') {
        expected[0] = '\0';
    }

    wolfSSHD_AuthInit();

    WMEMSET(actual, 0, sizeof(actual));
    wolfSSHD_GetCachedFakeHashForTest(actual, sizeof(actual));

    if (WSTRNCMP(expected, actual, sizeof(expected)) != 0) {
        printf("EXPECTED: %s\nACTUAL: %s\n", expected, actual);
        Log("    FAILED: wolfSSHD_AuthInit() did not populate "
            "cachedFakeHash as expected.\n");
        ret = WS_FATAL_ERROR;
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);
    wsshd_getspnam_cb = savedGetspnam;

    return ret;
}

/* test_AuthInit only covers the getspnam("root") success path and skips
 * when not root. Stub getspnam() to force the degraded-mode branch
 * regardless of process privileges. */
static int test_AuthInit_degradedMode(void)
{
    int ret = WS_SUCCESS;
    struct spwd* (*savedGetspnam)(const char*);
    char actual[256];

    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getspnam_cb = stub_getspnam_null;

    /* Cache must be empty so AuthInit() reaches the getspnam() fallback. */
    wolfSSHD_SetCachedFakeHashForTest(NULL);

    Log("    Testing scenario: wolfSSHD_AuthInit() with getspnam() "
        "failing.");
    wolfSSHD_AuthInit();

    /* Degraded mode must leave cachedFakeHash empty. */
    WMEMSET(actual, 0, sizeof(actual));
    wolfSSHD_GetCachedFakeHashForTest(actual, sizeof(actual));
    if (actual[0] != '\0') {
        Log(" FAILED: cachedFakeHash was populated on getspnam() "
            "failure.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);
    wsshd_getspnam_cb = savedGetspnam;

    return ret;
}

/* getspnam("root") succeeding but with a null sp_pwdp (e.g. NIS/LDAP-backed
 * root accounts) must also degrade gracefully, not call
 * GetFakeHashFromTemplate() with a NULL template. */
static int test_AuthInit_nullPasswordField(void)
{
    int ret = WS_SUCCESS;
    struct spwd* (*savedGetspnam)(const char*);
    char actual[256];

    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getspnam_cb = stub_getspnam_nullPassword;

    /* Cache must be empty so AuthInit() reaches the getspnam() fallback. */
    wolfSSHD_SetCachedFakeHashForTest(NULL);

    Log("    Testing scenario: wolfSSHD_AuthInit() with getspnam(\"root\") "
        "returning a null sp_pwdp.");
    wolfSSHD_AuthInit();

    /* Degraded mode must leave cachedFakeHash empty. */
    WMEMSET(actual, 0, sizeof(actual));
    wolfSSHD_GetCachedFakeHashForTest(actual, sizeof(actual));
    if (actual[0] != '\0') {
        Log(" FAILED: cachedFakeHash was populated when sp_pwdp was "
            "NULL.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);
    wsshd_getspnam_cb = savedGetspnam;

    return ret;
}

/* Two users sharing a hash template must dedup to one cached entry. */
static int test_AddShadowLineToFakeHashCache_dedup(void)
{
    int ret = WS_SUCCESS;
    char line1[] = "alice:$6$samesalt$samedigest:19000:0:99999:7:::";
    char line2[] = "bob:$6$samesalt$samedigest:19000:0:99999:7:::";

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    Log("    Testing scenario: AddShadowLineToFakeHashCache() with two "
        "users sharing the same hash template.");
    AddShadowLineToFakeHashCache(line1);
    AddShadowLineToFakeHashCache(line2);

    if (wolfSSHD_GetCachedFakeHashCountForTest() != 1) {
        Log(" FAILED: duplicate hash template was cached twice.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    return ret;
}

/* Distinct hash templates must stop accumulating once the fixed-size
 * cachedFakeHashes array is full, rather than overrunning it. */
static int test_AddShadowLineToFakeHashCache_cap(void)
{
    int ret = WS_SUCCESS;
    int i;
    char line[64];
    int count;

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    Log("    Testing scenario: AddShadowLineToFakeHashCache() with more "
        "distinct hashes than the cache can hold.");
    for (i = 0; i < 20; i++) {
        WSNPRINTF(line, sizeof(line), "user%d:$6$salt%d$digest%d:::::::",
            i, i, i);
        AddShadowLineToFakeHashCache(line);
    }

    count = wolfSSHD_GetCachedFakeHashCountForTest();
    if (count <= 0 || count > 8 || count >= 20) {
        Log(" FAILED: cache count %d did not stay within its fixed "
            "capacity.\n", count);
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    return ret;
}

/* Drives ScanShadowFile() with a synthetic tmpfile() stream instead of a
 * real /etc/shadow. */
static int test_ScanShadowFile_multipleEntries(void)
{
    int ret = WS_SUCCESS;
    WFILE* f;

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    f = tmpfile();
    if (f == NULL) {
        Log("    Skipping test: unable to create a tmpfile().\n");
        return WS_SUCCESS;
    }

    /* GetFakeHashFromTemplate drops the real salt for plain $N$salt$hash,
     * so templates only differ by algorithm id ($6$ vs $5$) here. */
    fputs("alice:$6$saltA$digestA:19000:0:99999:7:::\n", f);
    fputs("bob:$5$saltB$digestB:19000:0:99999:7:::\n", f);
    fputs("carol:$6$saltA$digestA:19000:0:99999:7:::\n", f);
    rewind(f);

    Log("    Testing scenario: ScanShadowFile() over a synthetic multi-user "
        "shadow stream.");
    ScanShadowFile(f);
    fclose(f);

    if (wolfSSHD_GetCachedFakeHashCountForTest() != 2) {
        Log(" FAILED: expected 2 cached templates, got %d.\n",
            wolfSSHD_GetCachedFakeHashCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    return ret;
}

/* A line over WSSHD_SHADOW_LINE_SZ must have its remainder drained so the
 * next line isn't swallowed as its continuation. */
static int test_ScanShadowFile_truncatedLine(void)
{
    int ret = WS_SUCCESS;
    WFILE* f;
    char overlong[1024];

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    f = tmpfile();
    if (f == NULL) {
        Log("    Skipping test: unable to create a tmpfile().\n");
        return WS_SUCCESS;
    }

    WMEMSET(overlong, 'x', sizeof(overlong) - 1);
    overlong[sizeof(overlong) - 1] = '\0';
    fputs(overlong, f);
    fputc('\n', f);
    fputs("dave:$6$saltD$digestD:19000:0:99999:7:::\n", f);
    rewind(f);

    Log("    Testing scenario: ScanShadowFile() with a line longer than "
        "its read buffer.");
    ScanShadowFile(f);
    fclose(f);

    if (wolfSSHD_GetCachedFakeHashCountForTest() != 1) {
        Log(" FAILED: expected 1 cached template after the overlong line, "
            "got %d.\n", wolfSSHD_GetCachedFakeHashCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wolfSSHD_SetCachedFakeHashForTest(NULL);

    return ret;
}
#endif /* WOLFSSHD_HAVE_SHADOW */
#endif /* WOLFSSH_HAVE_LIBCRYPT || WOLFSSH_HAVE_LIBLOGIN */

#ifdef WOLFSSL_BASE64_ENCODE
/* Build a mutable "<type> <base64(key)>" line; WSTRTOK mutates in place. */
static int BuildAuthKeysLineType(const char* type, const byte* key,
                                 word32 keySz, char* lineOut, word32 lineOutSz)
{
    word32 typeLen = (word32)WSTRLEN(type);
    word32 prefixLen = typeLen + 1;
    word32 b64Sz;

    if (lineOutSz <= prefixLen) {
        return WS_BUFFER_E;
    }
    WMEMCPY(lineOut, type, typeLen);
    lineOut[typeLen] = ' ';
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

static int BuildAuthKeysLine(const byte* key, word32 keySz,
                             char* lineOut, word32 lineOutSz)
{
    return BuildAuthKeysLineType("ssh-rsa", key, keySz, lineOut, lineOutSz);
}

/* Confirms every key-type CheckAuthKeysLine accepts via wolfSSH_QueryKey()
 * is recognized. */
static int test_CheckAuthKeysLineTypes(void)
{
    static const char* types[] = {
    #ifndef WOLFSSH_NO_RSA
        "ssh-rsa",
    #endif
    #ifndef WOLFSSH_NO_ED25519
        "ssh-ed25519",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        "ecdsa-sha2-nistp256",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        "ecdsa-sha2-nistp384",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        "ecdsa-sha2-nistp521",
    #endif
    #ifdef WOLFSSH_CERTS
    #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        "x509v3-ssh-rsa",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        "x509v3-ecdsa-sha2-nistp256",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        "x509v3-ecdsa-sha2-nistp384",
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        "x509v3-ecdsa-sha2-nistp521",
    #endif
    #endif
    #ifndef WOLFSSH_NO_MLDSA
        #ifndef WOLFSSH_NO_MLDSA44
        "ssh-mldsa-44",
        #endif
        #ifndef WOLFSSH_NO_MLDSA65
        "ssh-mldsa-65",
        #endif
        #ifndef WOLFSSH_NO_MLDSA87
        "ssh-mldsa-87",
        #endif
        #ifdef WOLFSSH_CERTS
        #ifndef WOLFSSH_NO_MLDSA44
        "x509v3-ssh-mldsa-44",
        #endif
        #ifndef WOLFSSH_NO_MLDSA65
        "x509v3-ssh-mldsa-65",
        #endif
        #ifndef WOLFSSH_NO_MLDSA87
        "x509v3-ssh-mldsa-87",
        #endif
        #endif
    #endif
    #if !defined(WOLFSSH_NO_MLDSA44) && !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256)
        "ssh-mldsa44-es256@wolfssl.com",
    #endif
    #if !defined(WOLFSSH_NO_MLDSA65) && \
            !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) && !defined(NO_SHA512)
        "ssh-mldsa65-es256@wolfssl.com",
    #endif
    #if !defined(WOLFSSH_NO_MLDSA87) && \
            !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) && !defined(NO_SHA512)
        "ssh-mldsa87-es384@wolfssl.com",
    #endif
    #if !defined(WOLFSSH_NO_MLDSA44) && !defined(WOLFSSH_NO_ED25519) && \
            !defined(NO_SHA512)
        "ssh-mldsa44-ed25519@openssh.com",
    #endif
    #if !defined(WOLFSSH_NO_MLDSA65) && !defined(WOLFSSH_NO_ED25519) && \
            !defined(NO_SHA512)
        "ssh-mldsa65-ed25519@wolfssl.com",
    #endif
    #if !defined(WOLFSSH_NO_MLDSA87) && defined(HAVE_ED448)
        "ssh-mldsa87-ed448@wolfssl.com",
    #endif
    };
    static const char keyAStr[] = "wolfssh-auth-key-test-A-AAAAAAA";
    const byte* keyA = (const byte*)keyAStr;
    const word32 keySz = (word32)(sizeof(keyAStr) - 1);
    char line[256];
    char lineCopy[256];
    word32 i;
    int ret = WS_SUCCESS;
    int rc;

    for (i = 0; i < (word32)(sizeof(types) / sizeof(types[0])); i++) {
        ret = BuildAuthKeysLineType(types[i], keyA, keySz, line, sizeof(line));
        if (ret != WS_SUCCESS) {
            Log("    CheckAuthKeysLine type %s: build failed.\n", types[i]);
            return ret;
        }
        Log("    Testing scenario: known type %s reaches key comparison.",
            types[i]);
        WMEMCPY(lineCopy, line, WSTRLEN(line) + 1);
        /* Matching key: a recognized type must proceed to the key
         * comparison and report success. */
        rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy),
                               keyA, keySz);
        if (rc == WSSHD_AUTH_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            return WS_FATAL_ERROR;
        }
    }

    /* An unknown type must be skipped (not matched) rather than aborting
     * the whole authorized_keys scan with a fatal error. */
    ret = BuildAuthKeysLineType("ssh-bogus-type", keyA, keySz, line,
                                sizeof(line));
    if (ret != WS_SUCCESS) {
        return ret;
    }
    Log("    Testing scenario: unknown type is rejected.");
    WMEMCPY(lineCopy, line, WSTRLEN(line) + 1);
    rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy), keyA, keySz);
    if (rc == WSSHD_AUTH_FAILURE) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED (rc=%d).\n", rc);
        return WS_FATAL_ERROR;
    }

    return WS_SUCCESS;
}

#ifndef WOLFSSH_NO_MLDSA
/* Builds a worst-case "<type> <base64(key)>" line, confirms it fits
 * within MAX_LINE_SZ, and round-trips it through CheckAuthKeysLine(). */
static int CheckAuthKeysLineMaxSzCase(const char* type, word32 keySz,
        word32 maxLineSz)
{
    int ret = WS_SUCCESS;
    int rc;
    word32 lineBufSz = maxLineSz + 1;
    byte* key = NULL;
    char* line = NULL;
    char* lineCopy = NULL;

    /* keySz as passed in is just the raw ML-DSA/trad key material. The
     * real authorized_keys line base64-encodes the full SSH wire blob,
     * which also carries the string type-name and string key-data length
     * prefixes; account for that so the MAX_LINE_SZ fit check below is
     * not under-strict. */
    keySz += LENGTH_SZ * 2 + (word32)WSTRLEN(type);

    key = (byte*)WMALLOC(keySz, NULL, DYNTYPE_BUFFER);
    line = (char*)WMALLOC(lineBufSz, NULL, DYNTYPE_BUFFER);
    lineCopy = (char*)WMALLOC(lineBufSz, NULL, DYNTYPE_BUFFER);
    if (key == NULL || line == NULL || lineCopy == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        word32 i;
        /* Non-repeating pattern so a truncation bug shows up as a
         * mismatch, not accidental luck. */
        for (i = 0; i < keySz; i++) {
            key[i] = (byte)(i * 31 + 7);
        }

        ret = BuildAuthKeysLineType(type, key, keySz, line, lineBufSz);
    }

    if (ret == WS_SUCCESS) {
        word32 lineLen = (word32)WSTRLEN(line);

        Log("    Testing scenario: max-size %s (%u byte key, %u byte line) "
            "fits within MAX_LINE_SZ (%u) and round-trips.",
            type, keySz, lineLen, maxLineSz);
        if (lineLen + 1 > maxLineSz) {
            Log(" FAILED (line len %u exceeds MAX_LINE_SZ %u).\n",
                lineLen + 1, maxLineSz);
            ret = WS_FATAL_ERROR;
        }
        else {
            WMEMCPY(lineCopy, line, lineLen + 1);
            rc = CheckAuthKeysLine(lineCopy, lineLen, key, keySz);
            if (rc == WSSHD_AUTH_SUCCESS) {
                Log(" PASSED.\n");
            }
            else {
                Log(" FAILED (rc=%d).\n", rc);
                ret = WS_FATAL_ERROR;
            }
        }
    }

    if (key != NULL) {
        WFREE(key, NULL, DYNTYPE_BUFFER);
    }
    if (line != NULL) {
        WFREE(line, NULL, DYNTYPE_BUFFER);
    }
    if (lineCopy != NULL) {
        WFREE(lineCopy, NULL, DYNTYPE_BUFFER);
    }

    return ret;
}

/* MAX_LINE_SZ is sized off the largest ML-DSA level, not the 32-byte
 * dummy keys test_CheckAuthKeysLineTypes() uses; build a full-size key
 * to actually catch a miscalculation there. */
static int test_CheckAuthKeysLineMaxSz(void)
{
    int ret;
    const char* type;
    word32 keySz;
    word32 maxLineSz = wolfsshd_test_MaxLineSz();

#if !defined(WOLFSSH_NO_MLDSA87)
    keySz = WC_MLDSA_87_PUB_KEY_SIZE + COMPOSITE_MAX_TRAD_PUB_SZ;
    #if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) && !defined(NO_SHA512)
        type = "ssh-mldsa87-es384@wolfssl.com";
    #elif defined(HAVE_ED448)
        type = "ssh-mldsa87-ed448@wolfssl.com";
    #else
        type = "ssh-mldsa-87";
        keySz = WC_MLDSA_87_PUB_KEY_SIZE;
    #endif
#elif !defined(WOLFSSH_NO_MLDSA65)
    keySz = WC_MLDSA_65_PUB_KEY_SIZE + COMPOSITE_MAX_TRAD_PUB_SZ;
    #if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) && !defined(NO_SHA512)
        type = "ssh-mldsa65-es256@wolfssl.com";
    #elif !defined(WOLFSSH_NO_ED25519) && !defined(NO_SHA512)
        type = "ssh-mldsa65-ed25519@wolfssl.com";
    #else
        type = "ssh-mldsa-65";
        keySz = WC_MLDSA_65_PUB_KEY_SIZE;
    #endif
#else
    keySz = WC_MLDSA_44_PUB_KEY_SIZE + COMPOSITE_MAX_TRAD_PUB_SZ;
    #if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256)
        type = "ssh-mldsa44-es256@wolfssl.com";
    #elif !defined(WOLFSSH_NO_ED25519) && !defined(NO_SHA512)
        type = "ssh-mldsa44-ed25519@openssh.com";
    #else
        type = "ssh-mldsa-44";
        keySz = WC_MLDSA_44_PUB_KEY_SIZE;
    #endif
#endif

    ret = CheckAuthKeysLineMaxSzCase(type, keySz, maxLineSz);

    /* The WOLFSSH_CERTS branch of MAX_LINE_SZ adds headroom for x509v3
     * composite-cert lines, but composite certs aren't supported by this
     * codebase (composite signatures only) and there's no real generated
     * cert to derive an assertion from, so that headroom goes untested
     * here rather than re-deriving MAX_LINE_SZ's own formula as fake
     * coverage. */

    return ret;
}
#endif /* !WOLFSSH_NO_MLDSA */

/* Negative-path coverage for CheckAuthKeysLine so mutation of the
 * ConstantCompare clause (the only substantive bytewise check after the
 * length comparison) does not survive the test suite. */
static int test_CheckAuthKeysLine(void)
{
    int ret = WS_SUCCESS;
    /* keyALastByte differs from keyA only in the final byte, killing a
     * dropped-ConstantCompare mutation that the length check alone would miss. */
    static const char keyAStr[] = "wolfssh-auth-key-test-A-AAAAAAA";
    static const char keyBStr[] = "wolfssh-auth-key-test-B-BBBBBBB";
    const byte* keyA = (const byte*)keyAStr;
    const byte* keyB = (const byte*)keyBStr;
    const word32 keySz = (word32)(sizeof(keyAStr) - 1);
    byte keyALastByte[sizeof(keyAStr) - 1];
    char line[256];
    char lineCopy[320]; /* fits the longer unsupported-type scenario line */
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

    if (ret == WS_SUCCESS) {
        /* An unsupported key type must be skipped (WSSHD_AUTH_FAILURE), not
         * treated as a hard error, so SearchKeysFile keeps scanning later
         * TrustedUserCAKeys entries. */
        Log("    Testing scenario: unsupported key type is skipped.");
        WSNPRINTF(lineCopy, sizeof(lineCopy), "sk-ssh-ed25519@openssh.com %s",
                  line + WSTRLEN("ssh-rsa "));
        rc = CheckAuthKeysLine(lineCopy, (word32)WSTRLEN(lineCopy),
                               keyA, keySz);
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

#ifndef _WIN32
/* Drive SearchForPubKey against a temp authorized_keys file to cover the
 * "no line matched -> WSSHD_AUTH_FAILURE" gate: the authorized key kills a
 * condition inversion, the unauthorized key kills a deletion of the gate. */
static int test_SearchForPubKey(void)
{
    int ret = WS_SUCCESS;
    static const char keyAStr[] = "wolfssh-auth-key-test-A-AAAAAAA";
    static const char keyBStr[] = "wolfssh-auth-key-test-B-BBBBBBB";
    const byte* keyA = (const byte*)keyAStr;
    const byte* keyB = (const byte*)keyBStr;
    const word32 keySz = (word32)(sizeof(keyAStr) - 1);
    char base[] = "/tmp/wolfsshd_pkXXXXXX";
    char keysPath[64] = "";
    char missPath[64] = "";
    char line[256];
    WS_UserAuthData_PublicKey pubKeyCtx;
    WUID_T uid = getuid();
    FILE* f = NULL;
    int rc;

    if (mkdtemp(base) == NULL) {
        Log("    mkdtemp failed.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        snprintf(keysPath, sizeof(keysPath), "%s/authorized_keys", base);
        snprintf(missPath, sizeof(missPath), "%s/absent_keys", base);
        ret = BuildAuthKeysLine(keyA, keySz, line, sizeof(line));
    }

    if (ret == WS_SUCCESS) {
        f = fopen(keysPath, "w");
        if (f == NULL) {
            Log("    fopen of authorized_keys failed.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(line, f);
            fputs("\n", f);
            fclose(f);
        }
    }

    /* Force 0600 so the StrictModes secure-open is not tripped by a permissive
     * umask leaving the file group or world writable. */
    if (ret == WS_SUCCESS && chmod(keysPath, S_IRUSR | S_IWUSR) != 0) {
        Log("    chmod of authorized_keys failed.\n");
        ret = WS_FATAL_ERROR;
    }

    WMEMSET(&pubKeyCtx, 0, sizeof(pubKeyCtx));
    pubKeyCtx.publicKeySz = keySz;

    /* StrictModes disabled so the check stays hermetic (no ownership gate). */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: authorized key is accepted.");
        pubKeyCtx.publicKey = keyA;
        rc = SearchForPubKey(base, keysPath, "testuser", &pubKeyCtx, uid, 0);
        if (rc == WSSHD_AUTH_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    /* The temp file is user-owned with safe perms, so the StrictModes
     * secure-open branch must also accept the authorized key. */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: authorized key accepted under StrictModes.");
        pubKeyCtx.publicKey = keyA;
        rc = SearchForPubKey(base, keysPath, "testuser", &pubKeyCtx, uid, 1);
        if (rc == WSSHD_AUTH_SUCCESS) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: unauthorized key is rejected.");
        pubKeyCtx.publicKey = keyB;
        rc = SearchForPubKey(base, keysPath, "testuser", &pubKeyCtx, uid, 0);
        if (rc == WSSHD_AUTH_FAILURE) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    /* A missing authorized_keys file is an error, not a silent accept. */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: missing keys file returns an error.");
        pubKeyCtx.publicKey = keyA;
        rc = SearchForPubKey(base, missPath, "testuser", &pubKeyCtx, uid, 0);
        if (rc < 0) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    if (keysPath[0] != '\0') {
        unlink(keysPath);
    }
    rmdir(base);

    return ret;
}
#endif /* !_WIN32 */
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

#define GROUP_STUB_MAX 16
static WGID_T       s_grouplist_groups[GROUP_STUB_MAX];
static int          s_grouplist_count;
static int          s_grouplist_always_fail;
static int          s_grouplist_calls;
static WGID_T       s_setgroups_seen[GROUP_STUB_MAX];
static int          s_setgroups_size;
static int          s_setgroups_list_nonnull;
static int          s_setgroups_ret;
static int          s_setgroups_called;

static int stub_getgrouplist(const char* usr, WGID_T grp, WGID_T* groups,
        int* ngroups)
{
    int i;

    WOLFSSH_UNUSED(usr);
    WOLFSSH_UNUSED(grp);
    s_grouplist_calls++;
    /* simulate a lookup that never fits, exercising the resolve failure path */
    if (s_grouplist_always_fail) {
        *ngroups = s_grouplist_count;
        return -1;
    }
    /* too-small buffer: echo the needed size and return -1 so the caller grows
     * and retries, matching the getgrouplist(3) contract. */
    if (groups == NULL || *ngroups < s_grouplist_count) {
        *ngroups = s_grouplist_count;
        return -1;
    }
    for (i = 0; i < s_grouplist_count; i++) {
        groups[i] = s_grouplist_groups[i];
    }
    *ngroups = s_grouplist_count;
#if defined(__QNX__) || defined(__QNXNTO__)
    /* QNX getgrouplist returns 0 on success rather than the count */
    return 0;
#else
    return s_grouplist_count;
#endif
}

static int stub_setgroups(int size, const WGID_T* list)
{
    int i;

    s_setgroups_called = 1;
    s_setgroups_size   = size;
    /* record what we can while the buffer is live; the caller frees it on
     * return, so the pointer itself must not be inspected afterwards. */
    s_setgroups_list_nonnull = (list != NULL);
    for (i = 0; list != NULL && i < size && i < GROUP_STUB_MAX; i++) {
        s_setgroups_seen[i] = list[i];
    }
    return s_setgroups_ret;
}

static void InstallGroupStubs(int setgroupsRet,
    int (**savedGrouplist)(const char*, WGID_T, WGID_T*, int*),
    int (**savedSetgroups)(int, const WGID_T*))
{
    int i;

    *savedGrouplist       = wsshd_getgrouplist_cb;
    *savedSetgroups       = wsshd_setgroups_cb;
    wsshd_getgrouplist_cb = stub_getgrouplist;
    wsshd_setgroups_cb    = stub_setgroups;
    s_grouplist_count     = 3;
    s_grouplist_groups[0] = 1001;
    s_grouplist_groups[1] = 1002;
    s_grouplist_groups[2] = 1003;
    s_grouplist_always_fail = 0;
    s_grouplist_calls     = 0;
    s_setgroups_ret       = setgroupsRet;
    s_setgroups_called    = 0;
    s_setgroups_size      = 0;
    s_setgroups_list_nonnull = 0;
    for (i = 0; i < GROUP_STUB_MAX; i++) {
        s_setgroups_seen[i] = 0;
    }
}

/* Exercises the group-name enumeration helper against the account running the
 * test. Covers the allocation and ownership contract end to end (the names
 * array, each duplicated name, and the gid scratch buffer) so a sanitizer run
 * guards the new auth.c cleanup paths. */
static int test_GetUserGroupNames(void)
{
    int ret = WS_SUCCESS;
    struct passwd* pw;
    char** names = NULL;
    word32 count = 0;
    word32 i;

    pw = getpwuid(getuid());
    if (pw == NULL) {
        /* no account for the running uid, nothing to exercise */
        return WS_SUCCESS;
    }

    ret = wolfSSHD_GetUserGroupNames(NULL, pw->pw_name, pw->pw_gid, &names,
            &count);

    /* every user belongs to at least their primary group */
    if (ret == WS_SUCCESS) {
        if (names == NULL || count == 0)
            ret = WS_FATAL_ERROR;
    }

    /* unresolvable gids are skipped, so every populated entry is non-NULL */
    if (ret == WS_SUCCESS) {
        for (i = 0; i < count; i++) {
            if (names[i] == NULL) {
                ret = WS_FATAL_ERROR;
                break;
            }
        }
    }

    wolfSSHD_FreeUserGroupNames(NULL, names, count);
    return ret;
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

static WGID_T s_setegid_arg;
static WUID_T s_seteuid_arg;
static int    s_setegid_ret;
static int    s_seteuid_ret;
static int    s_setegid_called;
static int    s_seteuid_called;

static int stub_setegid(WGID_T egid)
{
    s_setegid_called = 1;
    s_setegid_arg    = egid;
    return s_setegid_ret;
}

static int stub_seteuid(WUID_T euid)
{
    s_seteuid_called = 1;
    s_seteuid_arg    = euid;
    return s_seteuid_ret;
}

static void InstallPrivRaiseStubs(int egidRet, int euidRet,
    int (**savedEgid)(WGID_T), int (**savedEuid)(WUID_T))
{
    *savedEgid       = wsshd_setegid_cb;
    *savedEuid       = wsshd_seteuid_cb;
    wsshd_setegid_cb = stub_setegid;
    wsshd_seteuid_cb = stub_seteuid;
    s_setegid_ret    = egidRet;
    s_seteuid_ret    = euidRet;
    s_setegid_called = 0;
    s_seteuid_called = 0;
    s_setegid_arg    = 0;
    s_seteuid_arg    = 0;
}

#if (defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)) && \
        defined(WOLFSSHD_HAVE_SHADOW)
/* Fails only its first invocation, then succeeds. RequestAuthentication()
 * calls wolfSSHD_AuthReducePermissions() unconditionally after every auth
 * attempt regardless of whether raising permissions succeeded, and a
 * reduce failure is fatal (exit(1)). A stub that always fails would take
 * down the test process the moment that unconditional reduce call runs;
 * this lets the first (raise) call fail as intended while the later
 * reduce call(s) succeed. */
static int s_setegidFailOnceCalls;

static int stub_setegid_failOnce(WGID_T egid)
{
    s_setegid_called = 1;
    s_setegid_arg    = egid;
    s_setegidFailOnceCalls++;
    return (s_setegidFailOnceCalls == 1) ? -1 : 0;
}

static void InstallPrivRaiseFailOnceStubs(int (**savedEgid)(WGID_T),
    int (**savedEuid)(WUID_T))
{
    *savedEgid            = wsshd_setegid_cb;
    *savedEuid            = wsshd_seteuid_cb;
    wsshd_setegid_cb      = stub_setegid_failOnce;
    wsshd_seteuid_cb      = stub_seteuid;
    s_setegidFailOnceCalls = 0;
    s_seteuid_ret         = 0;
    s_setegid_called      = 0;
    s_seteuid_called      = 0;
    s_setegid_arg         = 0;
    s_seteuid_arg         = 0;
}
#endif

/* Synthetic "sshd" account used so privilege-separation tests don't depend
 * on the host actually having an sshd system user configured. */
static struct passwd stub_sshd_pw;

static struct passwd* stub_getpwnam(const char* name)
{
    if (name != NULL && WSTRCMP(name, WOLFSSH_USER_STRING(WOLFSSH_SSHD_USER)) == 0) {
        WMEMSET(&stub_sshd_pw, 0, sizeof(stub_sshd_pw));
        stub_sshd_pw.pw_name = (char*)WOLFSSH_USER_STRING(WOLFSSH_SSHD_USER);
        stub_sshd_pw.pw_uid  = 1000;
        stub_sshd_pw.pw_gid  = 1000;
        return &stub_sshd_pw;
    }
    return NULL;
}

static void InstallGetpwnamStub(struct passwd* (**savedGetpwnam)(const char*))
{
    *savedGetpwnam   = wsshd_getpwnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam;
}

/* UsePrivilegeSeparation no must let SetDefaultUserID succeed without a
 * configured sshd system user, since no uid/gid switching will ever happen. */
static int test_AuthCreateUser_privSepOff(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    static const char line[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    if (ParseConfigLine(&conf, line, (int)WSTRLEN(line), 0) != WS_SUCCESS) {
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            wolfSSHD_AuthFreeUser(auth);
        }
    }

    wolfSSHD_ConfigFree(conf);
    return ret;
}

#if (defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)) && \
        defined(WOLFSSHD_HAVE_SHADOW)
/* PasswordAuthentication no must reject through RequestAuthentication's
 * DoFakePasswordCheck() branch without ever calling checkPasswordCb. */
static int test_RequestAuth_pwAuthNoRejectsBeforePasswordCheck(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    struct passwd* (*savedGetpwnam)(const char*);
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    static const byte pw[] = "guessme";
    static const char line1[] = "UsePrivilegeSeparation no";
    static const char line2[] = "PasswordAuthentication no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    if (ParseConfigLine(&conf, line1, (int)WSTRLEN(line1), 0) != WS_SUCCESS ||
            ParseConfigLine(&conf, line2, (int)WSTRLEN(line2), 0) !=
                    WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    savedGetpwnam = wsshd_getpwnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type = WOLFSSH_USERAUTH_PASSWORD;
    authData.username = (const byte*)"shadow_branch_test_user";
    authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);
    authData.sf.password.password = pw;
    authData.sf.password.passwordSz = (word32)(sizeof(pw) - 1);

    Log("    Testing scenario: PasswordAuthentication no rejects.");
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
    if (rc == WOLFSSH_USERAUTH_REJECTED &&
            wolfSSHD_GetFakePasswordCheckCountForTest() != 0) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED: got %d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb = savedSetgroups;
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

/* Test that denying an empty password with PermitEmptyPw=no fakes a
 * password check to prevent timing leaks. */
static int test_RequestAuth_permitEmptyPwDeniedFakesPasswordCheck(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    struct passwd* (*savedGetpwnam)(const char*);
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    static const char line1[] = "UsePrivilegeSeparation no";
    static const char line2[] = "PermitEmptyPasswords no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    if (ParseConfigLine(&conf, line1, (int)WSTRLEN(line1), 0) != WS_SUCCESS ||
            ParseConfigLine(&conf, line2, (int)WSTRLEN(line2), 0) !=
                    WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    savedGetpwnam = wsshd_getpwnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type = WOLFSSH_USERAUTH_PASSWORD;
    authData.username = (const byte*)"shadow_branch_test_user";
    authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);
    authData.sf.password.password = NULL;
    authData.sf.password.passwordSz = 0;

    Log("    Testing scenario: PermitEmptyPw no denies empty password.");
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
    if (rc == WOLFSSH_USERAUTH_FAILURE &&
            wolfSSHD_GetFakePasswordCheckCountForTest() != 0) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED: got %d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb = savedSetgroups;
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

/* checkPasswordCb returning something other than WSSHD_AUTH_SUCCESS/FAILURE
 * (e.g. CheckPasswordUnix's oversized-shadow-hash fail-closed path) must
 * surface as WOLFSSH_USERAUTH_FAILURE through RequestAuthentication, taking
 * the DoFakePasswordCheck() branch rather than crashing or succeeding. */
static int test_RequestAuth_checkPasswordCbErrorFailsClosed(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    struct passwd* (*savedGetpwnam)(const char*);
    struct spwd* (*savedGetspnam)(const char*);
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    static const byte pw[] = "guessme";
    static const char line1[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    if (ParseConfigLine(&conf, line1, (int)WSTRLEN(line1), 0) != WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    savedGetpwnam = wsshd_getpwnam_cb;
    savedGetspnam = wsshd_getspnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    wsshd_getspnam_cb = stub_getspnam_oversizedHash;
    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.type = WOLFSSH_USERAUTH_PASSWORD;
    authData.username = (const byte*)"shadow_branch_test_user";
    authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);
    authData.sf.password.password = pw;
    authData.sf.password.passwordSz = (word32)(sizeof(pw) - 1);

    Log("    Testing scenario: checkPasswordCb error fails closed.");
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
    if (rc == WOLFSSH_USERAUTH_FAILURE) {
        Log(" PASSED.\n");
    }
    else {
        Log(" FAILED: got %d.\n", rc);
        ret = WS_FATAL_ERROR;
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wsshd_getspnam_cb = savedGetspnam;
    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb = savedSetgroups;
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

/* wolfSSHD_AuthRaisePermissions() failing must equalize timing with a fake
 * crypt() only for password auth; doing so for pubkey auth would itself be a
 * timing oracle (see the comment on RequestAuthentication's DoCheckUser()
 * call). Drives both auth types through the same failure so a regression
 * that re-ungates the pubkey path is caught by an actual call count rather
 * than by a return code that looks identical either way. */
static int test_RequestAuth_raisePermissionsFailFakeCheckGating(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    struct passwd* (*savedGetpwnam)(const char*);
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    static const byte pw[] = "guessme";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    /* privilege separation defaults to on; stub getpwnam("sshd") so
     * AuthCreateUser can resolve the saved uid/gid without a real system
     * account. */
    InstallGetpwnamStub(&savedGetpwnam);
    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wsshd_getpwnam_cb = savedGetpwnam;
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    /* swap to the auth-target stub for the DoCheckUser() lookups below */
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    InstallPrivRaiseFailOnceStubs(&savedEgid, &savedEuid);

    WMEMSET(&authData, 0, sizeof(authData));
    authData.username = (const byte*)"shadow_branch_test_user";
    authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);

    Log("    Testing scenario: AuthRaisePermissions failure fakes password "
        "check for PASSWORD auth.");
    authData.type = WOLFSSH_USERAUTH_PASSWORD;
    authData.sf.password.password = pw;
    authData.sf.password.passwordSz = (word32)(sizeof(pw) - 1);
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
    if (rc != WOLFSSH_USERAUTH_FAILURE ||
            wolfSSHD_GetFakePasswordCheckCountForTest() == 0) {
        Log(" FAILED: rc=%d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    Log("    Testing scenario: AuthRaisePermissions failure must not fake "
        "password check for PUBLICKEY auth.");
    /* Clear union fields before reinterpreting as sf.publicKey. */
    WMEMSET(&authData.sf, 0, sizeof(authData.sf));
    authData.type = WOLFSSH_USERAUTH_PUBLICKEY;
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    /* Re-arm the fail-once stub to hit the raise-permissions failure. */
    s_setegidFailOnceCalls = 0;
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PUBLICKEY, &authData, authCtx);
    if (rc != WOLFSSH_USERAUTH_FAILURE ||
            wolfSSHD_GetFakePasswordCheckCountForTest() != 0) {
        Log(" FAILED: rc=%d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wsshd_setegid_cb = savedEgid;
    wsshd_seteuid_cb = savedEuid;
    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}

/* Test that AuthGetUserConf() NULL failure fakes a password check for
 * password auth, using a mocked group failure. */
static int test_RequestAuth_userConfNullFakeCheckGating(void)
{
    int ret = WS_SUCCESS;
    int rc;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* authCtx;
    WS_UserAuthData authData;
    struct passwd* (*savedGetpwnam)(const char*);
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    static const byte pw[] = "guessme";
    static const char line1[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) return WS_MEMORY_E;

    if (ParseConfigLine(&conf, line1, (int)WSTRLEN(line1), 0) != WS_SUCCESS) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    authCtx = wolfSSHD_AuthCreateUser(NULL, conf);
    if (authCtx == NULL) {
        wolfSSHD_ConfigFree(conf);
        return WS_FATAL_ERROR;
    }

    savedGetpwnam = wsshd_getpwnam_cb;
    wsshd_getpwnam_cb = stub_getpwnam_shadowUser;
    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);
    s_grouplist_always_fail = 1;

    WMEMSET(&authData, 0, sizeof(authData));
    authData.username = (const byte*)"shadow_branch_test_user";
    authData.usernameSz = (word32)WSTRLEN((const char*)authData.username);

    Log("    Testing scenario: AuthGetUserConf NULL fakes password check "
        "for PASSWORD auth.");
    authData.type = WOLFSSH_USERAUTH_PASSWORD;
    authData.sf.password.password = pw;
    authData.sf.password.passwordSz = (word32)(sizeof(pw) - 1);
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PASSWORD, &authData, authCtx);
    if (rc != WOLFSSH_USERAUTH_FAILURE ||
            wolfSSHD_GetFakePasswordCheckCountForTest() == 0) {
        Log(" FAILED: rc=%d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    Log("    Testing scenario: AuthGetUserConf NULL must not fake password "
        "check for PUBLICKEY auth.");
    /* Clear union fields before reinterpreting as sf.publicKey. */
    WMEMSET(&authData.sf, 0, sizeof(authData.sf));
    authData.type = WOLFSSH_USERAUTH_PUBLICKEY;
    wolfSSHD_ResetFakePasswordCheckCountForTest();
    rc = DefaultUserAuth(WOLFSSH_USERAUTH_PUBLICKEY, &authData, authCtx);
    if (rc != WOLFSSH_USERAUTH_FAILURE ||
            wolfSSHD_GetFakePasswordCheckCountForTest() != 0) {
        Log(" FAILED: rc=%d, fakeCheckCount=%d.\n", rc,
            wolfSSHD_GetFakePasswordCheckCountForTest());
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb = savedSetgroups;
    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_AuthFreeUser(authCtx);
    wolfSSHD_ConfigFree(conf);

    return ret;
}
#endif /* (WOLFSSH_HAVE_LIBCRYPT || WOLFSSH_HAVE_LIBLOGIN) &&
        * WOLFSSHD_HAVE_SHADOW */

/* wolfSSHD_AuthRaisePermissions must not touch setegid/seteuid at all when
 * privilege separation is off, since the process never dropped privileges. */
static int test_AuthRaisePermissions_offSkipsSyscalls(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    static const char line[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    if (ParseConfigLine(&conf, line, (int)WSTRLEN(line), 0) != WS_SUCCESS) {
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            InstallPrivRaiseStubs(0, 0, &savedEgid, &savedEuid);

            if (wolfSSHD_AuthRaisePermissions(auth) != WS_SUCCESS)
                ret = WS_FATAL_ERROR;
            if (ret == WS_SUCCESS
                    && (s_setegid_called || s_seteuid_called))
                ret = WS_FATAL_ERROR;

            wsshd_setegid_cb = savedEgid;
            wsshd_seteuid_cb = savedEuid;
            wolfSSHD_AuthFreeUser(auth);
        }
    }

    wolfSSHD_ConfigFree(conf);
    return ret;
}

/* With privilege separation on, wolfSSHD_AuthRaisePermissions restores the
 * uid/gid the process started with (captured at AuthCreateUser time). Uses a
 * stubbed getpwnam("sshd") so the test doesn't depend on the environment
 * actually having an sshd system user configured. */
static int test_AuthRaisePermissions_separateCallsSyscalls(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    /* privilege separation defaults to on */
    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(0, 0, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthRaisePermissions(auth) != WS_SUCCESS)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && (!s_setegid_called || !s_seteuid_called))
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && s_setegid_arg != getgid())
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && s_seteuid_arg != getuid())
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

/* wolfSSHD_AuthRaisePermissions must reject a NULL auth argument instead of
 * dereferencing it. */
static int test_AuthRaisePermissions_nullArg(void)
{
    if (wolfSSHD_AuthRaisePermissions(NULL) != WS_BAD_ARGUMENT)
        return WS_FATAL_ERROR;
    return WS_SUCCESS;
}

/* When setegid fails, wolfSSHD_AuthRaisePermissions must report the failure
 * and short-circuit seteuid rather than attempting it anyway. */
static int test_AuthRaisePermissions_gidFailSkipsUid(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    /* privilege separation defaults to on */
    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(-1, 0, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthRaisePermissions(auth) != WS_FATAL_ERROR)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_setegid_called)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && s_seteuid_called)
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

/* When setegid succeeds but seteuid fails, wolfSSHD_AuthRaisePermissions must
 * still report the failure. */
static int test_AuthRaisePermissions_uidFail(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    /* privilege separation defaults to on */
    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(0, -1, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthRaisePermissions(auth) != WS_FATAL_ERROR)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_setegid_called)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_seteuid_called)
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

/* Drives the supplementary-group drop with getgrouplist and setgroups mocked
 * so it is deterministic across platforms; asserts setgroups is invoked with
 * the resolved group count. */

static int test_AuthReducePermissions_offSkipsSyscalls(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    static const char line[] = "UsePrivilegeSeparation no";

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    if (ParseConfigLine(&conf, line, (int)WSTRLEN(line), 0) != WS_SUCCESS) {
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            InstallPrivRaiseStubs(0, 0, &savedEgid, &savedEuid);

            if (wolfSSHD_AuthReducePermissions(auth) != WS_SUCCESS)
                ret = WS_FATAL_ERROR;
            if (ret == WS_SUCCESS
                    && (s_setegid_called || s_seteuid_called))
                ret = WS_FATAL_ERROR;

            wsshd_setegid_cb = savedEgid;
            wsshd_seteuid_cb = savedEuid;
            wolfSSHD_AuthFreeUser(auth);
        }
    }

    wolfSSHD_ConfigFree(conf);
    return ret;
}

static int test_AuthReducePermissions_separateCallsSyscalls(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(0, 0, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthReducePermissions(auth) != WS_SUCCESS)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && (!s_setegid_called || !s_seteuid_called))
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

static int test_AuthReducePermissions_nullArg(void)
{
    if (wolfSSHD_AuthReducePermissions(NULL) != WS_BAD_ARGUMENT)
        return WS_FATAL_ERROR;
    return WS_SUCCESS;
}

static int test_AuthReducePermissions_gidFailContinuesToUid(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(-1, 0, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthReducePermissions(auth) != WS_FATAL_ERROR)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_setegid_called)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_seteuid_called)
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

static int test_AuthReducePermissions_uidFail(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_AUTH* auth;
    int (*savedEgid)(WGID_T);
    int (*savedEuid)(WUID_T);
    struct passwd* (*savedGetpwnam)(const char*) = NULL;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        return WS_MEMORY_E;
    }

    InstallGetpwnamStub(&savedGetpwnam);

    auth = wolfSSHD_AuthCreateUser(NULL, conf);
    if (auth == NULL) {
        ret = WS_FATAL_ERROR;
    }
    else {
        InstallPrivRaiseStubs(0, -1, &savedEgid, &savedEuid);

        if (wolfSSHD_AuthReducePermissions(auth) != WS_FATAL_ERROR)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_setegid_called)
            ret = WS_FATAL_ERROR;
        if (ret == WS_SUCCESS && !s_seteuid_called)
            ret = WS_FATAL_ERROR;

        wsshd_setegid_cb = savedEgid;
        wsshd_seteuid_cb = savedEuid;
        wolfSSHD_AuthFreeUser(auth);
    }

    wsshd_getpwnam_cb = savedGetpwnam;
    wolfSSHD_ConfigFree(conf);
    return ret;
}

static int test_AuthSetGroups_ok(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf = NULL;
    WOLFSSHD_AUTH*   auth = NULL;
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    struct passwd* (*savedGetpwnam)(const char*) = wsshd_getpwnam_cb;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_FATAL_ERROR;
    /* privilege separation defaults to on, so stub getpwnam rather than
     * depending on the host having an sshd user */
    if (ret == WS_SUCCESS) {
        InstallGetpwnamStub(&savedGetpwnam);
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            wsshd_getpwnam_cb = savedGetpwnam;
            wolfSSHD_ConfigFree(conf);
            return WS_FATAL_ERROR;
        }
    }

    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);

    if (ret == WS_SUCCESS
            && wolfSSHD_AuthSetGroups(auth, "testuser", 1000) != WS_SUCCESS)
        ret = WS_FATAL_ERROR;

    /* the drop must actually call setgroups with the resolved list */
    if (ret == WS_SUCCESS && !s_setgroups_called)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && s_setgroups_size != s_grouplist_count)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setgroups_list_nonnull)
        ret = WS_FATAL_ERROR;
    /* the exact resolved gids must reach setgroups, not just the count */
    if (ret == WS_SUCCESS
            && (s_setgroups_seen[0] != 1001 || s_setgroups_seen[1] != 1002
                || s_setgroups_seen[2] != 1003))
        ret = WS_FATAL_ERROR;
#if !defined(__QNX__) && !defined(__QNXNTO__)
    /* the small init size (-DWOLFSSHD_GROUP_LIST_INIT=1) forces at least one
     * grow-and-retry before the lookup fits, covering that branch */
    if (ret == WS_SUCCESS && s_grouplist_calls < 2)
        ret = WS_FATAL_ERROR;
#endif

    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb    = savedSetgroups;
    wsshd_getpwnam_cb     = savedGetpwnam;
    if (auth != NULL)
        (void)wolfSSHD_AuthFreeUser(auth);
    if (conf != NULL)
        wolfSSHD_ConfigFree(conf);
    return ret;
}

/* A setgroups(2) failure must abort the privilege setup with WS_FATAL_ERROR
 * rather than being silently ignored. */
static int test_AuthSetGroups_setgroups_fail(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf = NULL;
    WOLFSSHD_AUTH*   auth = NULL;
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    struct passwd* (*savedGetpwnam)(const char*) = wsshd_getpwnam_cb;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_FATAL_ERROR;
    /* privilege separation defaults to on, so stub getpwnam rather than
     * depending on the host having an sshd user */
    if (ret == WS_SUCCESS) {
        InstallGetpwnamStub(&savedGetpwnam);
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            wsshd_getpwnam_cb = savedGetpwnam;
            wolfSSHD_ConfigFree(conf);
            return WS_FATAL_ERROR;
        }
    }

    InstallGroupStubs(-1, &savedGrouplist, &savedSetgroups);

    if (ret == WS_SUCCESS
            && wolfSSHD_AuthSetGroups(auth, "testuser", 1000) != WS_FATAL_ERROR)
        ret = WS_FATAL_ERROR;
    if (ret == WS_SUCCESS && !s_setgroups_called)
        ret = WS_FATAL_ERROR;

    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb    = savedSetgroups;
    wsshd_getpwnam_cb     = savedGetpwnam;
    if (auth != NULL)
        (void)wolfSSHD_AuthFreeUser(auth);
    if (conf != NULL)
        wolfSSHD_ConfigFree(conf);
    return ret;
}

/* A getgrouplist lookup that never succeeds must fail closed with
 * WS_FATAL_ERROR and never reach the setgroups drop. */
static int test_AuthSetGroups_getgrouplist_fail(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf = NULL;
    WOLFSSHD_AUTH*   auth = NULL;
    int (*savedGrouplist)(const char*, WGID_T, WGID_T*, int*);
    int (*savedSetgroups)(int, const WGID_T*);
    struct passwd* (*savedGetpwnam)(const char*) = wsshd_getpwnam_cb;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL)
        ret = WS_FATAL_ERROR;
    /* privilege separation defaults to on, so stub getpwnam rather than
     * depending on the host having an sshd user */
    if (ret == WS_SUCCESS) {
        InstallGetpwnamStub(&savedGetpwnam);
        auth = wolfSSHD_AuthCreateUser(NULL, conf);
        if (auth == NULL) {
            wsshd_getpwnam_cb = savedGetpwnam;
            wolfSSHD_ConfigFree(conf);
            return WS_FATAL_ERROR;
        }
    }

    InstallGroupStubs(0, &savedGrouplist, &savedSetgroups);
    s_grouplist_always_fail = 1;

    if (ret == WS_SUCCESS
            && wolfSSHD_AuthSetGroups(auth, "testuser", 1000) != WS_FATAL_ERROR)
        ret = WS_FATAL_ERROR;
    /* group resolution failed, so the drop must not have run */
    if (ret == WS_SUCCESS && s_setgroups_called)
        ret = WS_FATAL_ERROR;

    wsshd_getgrouplist_cb = savedGrouplist;
    wsshd_setgroups_cb    = savedSetgroups;
    wsshd_getpwnam_cb     = savedGetpwnam;
    if (auth != NULL)
        (void)wolfSSHD_AuthFreeUser(auth);
    if (conf != NULL)
        wolfSSHD_ConfigFree(conf);
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

/* Locks in the enforcement decisions RequestAuthentication and DoCheckUser
 * make for each PermitRootLogin mode, without needing a live sshd (the
 * Match-aware end-to-end behavior is covered separately by
 * sshd_permitroot_test.sh, sshd_permitroot_prohibit_password.sh, and
 * sshd_permitroot_forced_cmd.sh). */
static int test_PermitRootLoginModes(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    WOLFSSHD_CONFIG* head;

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)

    /* PermitRootLogin no: root is denied outright, and never reaches the
     * password/pubkey checks since DoCheckUser rejects first. */
    Log("    Testing scenario: PermitRootLogin no.");
    head = wolfSSHD_ConfigNew(NULL);
    conf = head;
    if (conf == NULL || PCL("PermitRootLogin no") != WS_SUCCESS) {
        ret = WS_FATAL_ERROR;
    }
    else if (IsRootLoginDenied(1, conf) != 1 ||
             IsRootLoginDenied(0, conf) != 0) {
        ret = WS_FATAL_ERROR;
    }
    Log((ret == WS_SUCCESS) ? " PASSED.\n" : " FAILED.\n");
    wolfSSHD_ConfigFree(head);

    /* PermitRootLogin yes: nothing is blocked for root. */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: PermitRootLogin yes.");
        head = wolfSSHD_ConfigNew(NULL);
        conf = head;
        if (conf == NULL || PCL("PermitRootLogin yes") != WS_SUCCESS) {
            ret = WS_FATAL_ERROR;
        }
        else if (IsRootLoginDenied(1, conf) != 0 ||
                 IsRootPasswordAuthBlocked(1, conf) != 0 ||
                 IsRootPubKeyForcedCmdMissing(1, conf) != 0) {
            ret = WS_FATAL_ERROR;
        }
        Log((ret == WS_SUCCESS) ? " PASSED.\n" : " FAILED.\n");
        wolfSSHD_ConfigFree(head);
    }

    /* PermitRootLogin prohibit-password: password auth blocked, pubkey auth
     * is not required to carry a forced command. */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: PermitRootLogin prohibit-password.");
        head = wolfSSHD_ConfigNew(NULL);
        conf = head;
        if (conf == NULL ||
                PCL("PermitRootLogin prohibit-password") != WS_SUCCESS) {
            ret = WS_FATAL_ERROR;
        }
        else if (IsRootLoginDenied(1, conf) != 0 ||
                 IsRootPasswordAuthBlocked(1, conf) != 1 ||
                 IsRootPasswordAuthBlocked(0, conf) != 0 ||
                 IsRootPubKeyForcedCmdMissing(1, conf) != 0) {
            ret = WS_FATAL_ERROR;
        }
        Log((ret == WS_SUCCESS) ? " PASSED.\n" : " FAILED.\n");
        wolfSSHD_ConfigFree(head);
    }

    /* PermitRootLogin forced-commands-only: password auth blocked; pubkey
     * auth requires a ForceCommand, and passes once one is configured. */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: PermitRootLogin forced-commands-only, "
            "no ForceCommand.");
        head = wolfSSHD_ConfigNew(NULL);
        conf = head;
        if (conf == NULL ||
                PCL("PermitRootLogin forced-commands-only") != WS_SUCCESS) {
            ret = WS_FATAL_ERROR;
        }
        else if (IsRootPasswordAuthBlocked(1, conf) != 1 ||
                 IsRootPubKeyForcedCmdMissing(1, conf) != 1 ||
                 IsRootPubKeyForcedCmdMissing(0, conf) != 0) {
            ret = WS_FATAL_ERROR;
        }
        Log((ret == WS_SUCCESS) ? " PASSED.\n" : " FAILED.\n");

        if (ret == WS_SUCCESS) {
            Log("    Testing scenario: PermitRootLogin "
                "forced-commands-only, with ForceCommand.");
            if (PCL("ForceCommand internal-sftp") != WS_SUCCESS) {
                ret = WS_FATAL_ERROR;
            }
            else if (IsRootPubKeyForcedCmdMissing(1, conf) != 0) {
                ret = WS_FATAL_ERROR;
            }
            Log((ret == WS_SUCCESS) ? " PASSED.\n" : " FAILED.\n");
        }
        wolfSSHD_ConfigFree(head);
    }

#undef PCL

    return ret;
}

/* The config parser matches option names with WSTRNCMP over the options table
 * in order, so no entry may be a strict prefix of a later one (e.g. "HostKey"
 * must come after the "HostKeyStore*" names). */
static int test_ConfigOptionPrefixOrder(void)
{
    int ret = WS_SUCCESS;
    const char* earlier = NULL;
    const char* later = NULL;

    Log("    Testing scenario: option table prefix ordering.");
    if (wolfSSHD_ConfigOptionPrefixShadow(&earlier, &later)) {
        Log(" option '%s' shadows later option '%s'.", earlier, later);
        ret = WS_FATAL_ERROR;
    }
    Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");

    return ret;
}

/* Every CheckNotInMatch-guarded option must fail to parse inside a Match
 * block with WS_BAD_ARGUMENT (the value CheckNotInMatch returns, so a
 * rejection cannot be confused with an unrecognised option name), while the
 * same line parses successfully at global scope as a positive control.
 * TrustedUserCAKeys is deliberately absent: its per-user resolved value is
 * honored live at authentication time, so a Match-scoped setting is
 * supported and must keep parsing (asserted at the end). */
static int test_ConfigGlobalOnlyOptionsInMatch(void)
{
    int ret = WS_SUCCESS;
    int i;
    int rc;
    WOLFSSHD_CONFIG* head;
    WOLFSSHD_CONFIG* conf;
    static const char* lines[] = {
        "wolfSSH_TrustedSystemCAKeys yes",
        "wolfSSH_TrustedUserCAStore yes",
        "HostKey /etc/ssh/host_key",
        "HostCertificate /etc/ssh/host_cert.pem",
#ifdef WOLFSSHD_WIN_STORE_CONFIG
        "HostKeyStore MY",
        "HostKeyStoreSubject wolfSSH Host",
        "HostKeyStoreFlags 0x1000",
        "wolfSSH_WinUserStores CERT_STORE_PROV_SYSTEM",
        "wolfSSH_WinUserDwFlags LOCAL_MACHINE",
        "wolfSSH_WinUserPvPara SSH_UserCA",
#endif
    };

#define PCL(s) ParseConfigLine(&conf, s, (int)WSTRLEN(s), 0)
    for (i = 0; i < (int)(sizeof(lines) / sizeof(*lines)); i++) {
        Log("    Testing scenario: '%s' in Match block rejected.", lines[i]);
        head = wolfSSHD_ConfigNew(NULL);
        conf = head;
        if (head == NULL) {
            ret = WS_MEMORY_E;
        }
        /* positive control: the same line is valid at global scope */
        if (ret == WS_SUCCESS) {
            rc = ParseConfigLine(&conf, lines[i],
                    (int)WSTRLEN(lines[i]), 0);
            if (rc != WS_SUCCESS) {
                Log(" global-scope control parse failed (%d).", rc);
                ret = WS_FATAL_ERROR;
            }
        }
        if (ret == WS_SUCCESS) {
            ret = PCL("Match User testuser");
        }
        if (ret == WS_SUCCESS) {
            rc = ParseConfigLine(&conf, lines[i],
                    (int)WSTRLEN(lines[i]), 0);
            if (rc != WS_BAD_ARGUMENT) {
                Log(" expected WS_BAD_ARGUMENT, got %d.", rc);
                ret = WS_FATAL_ERROR;
            }
        }
        Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");
        wolfSSHD_ConfigFree(head);
        if (ret != WS_SUCCESS) {
            break;
        }
    }

    /* TrustedUserCAKeys stays legal inside a Match block */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: TrustedUserCAKeys in Match block "
            "accepted.");
        head = wolfSSHD_ConfigNew(NULL);
        conf = head;
        if (head == NULL) {
            ret = WS_MEMORY_E;
        }
        if (ret == WS_SUCCESS) {
            ret = PCL("Match User testuser");
        }
        if (ret == WS_SUCCESS) {
            ret = PCL("TrustedUserCAKeys /etc/ssh/ca.pub");
        }
        Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");
        wolfSSHD_ConfigFree(head);
    }
#undef PCL

    return ret;
}

#ifdef WOLFSSHD_WIN_STORE_CONFIG
/* NULL-argument and replace-existing coverage for the three wolfSSH_WinUser*
 * setters, modelled on test_ConfigSetAuthKeysFile. The replace path frees
 * the previous value, which the sanitizer builds verify. */
static int test_ConfigSetWinUserOptions(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: WinUser setters NULL arguments.");
        if (wolfSSHD_ConfigSetWinUserStores(NULL, "x") != WS_BAD_ARGUMENT ||
            wolfSSHD_ConfigSetWinUserStores(conf, NULL) != WS_BAD_ARGUMENT ||
            wolfSSHD_ConfigSetWinUserDwFlags(NULL, "x") != WS_BAD_ARGUMENT ||
            wolfSSHD_ConfigSetWinUserDwFlags(conf, NULL) != WS_BAD_ARGUMENT ||
            wolfSSHD_ConfigSetWinUserPvPara(NULL, "x") != WS_BAD_ARGUMENT ||
            wolfSSHD_ConfigSetWinUserPvPara(conf, NULL) != WS_BAD_ARGUMENT) {
            ret = WS_FATAL_ERROR;
        }
        Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: WinUser setters replace existing value.");
        if (wolfSSHD_ConfigSetWinUserStores(conf,
                    "CERT_STORE_PROV_SYSTEM") != WS_SUCCESS ||
            wolfSSHD_ConfigSetWinUserStores(conf, "second") != WS_SUCCESS ||
            WSTRCMP(wolfSSHD_ConfigGetWinUserStores(conf), "second") != 0) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                (wolfSSHD_ConfigSetWinUserDwFlags(conf,
                    "LOCAL_MACHINE") != WS_SUCCESS ||
                 wolfSSHD_ConfigSetWinUserDwFlags(conf,
                    "CURRENT_USER") != WS_SUCCESS ||
                 WSTRCMP(wolfSSHD_ConfigGetWinUserDwFlags(conf),
                    "CURRENT_USER") != 0)) {
            ret = WS_FATAL_ERROR;
        }
        if (ret == WS_SUCCESS &&
                (wolfSSHD_ConfigSetWinUserPvPara(conf,
                    "SSH_UserCA") != WS_SUCCESS ||
                 wolfSSHD_ConfigSetWinUserPvPara(conf,
                    "OtherStore") != WS_SUCCESS ||
                 WSTRCMP(wolfSSHD_ConfigGetWinUserPvPara(conf),
                    "OtherStore") != 0)) {
            ret = WS_FATAL_ERROR;
        }
        Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");
    }

    wolfSSHD_ConfigFree(conf);

    return ret;
}
#endif /* WOLFSSHD_WIN_STORE_CONFIG */

/* Exercises the exported per-user AuthorizedKeysFile predicate that decides
 * whether an entry in the resolved file is an implicit user binding. */
static int test_AuthKeysPatternIsPerUser(void)
{
    int ret = WS_SUCCESS;
    int i;
    int got;
    static const struct {
        const char* desc;
        const char* pattern;
        int expect;
    } vectors[] = {
        {"NULL uses the built-in per-user default", NULL, 1},
        {"empty string uses the built-in default", "", 1},
        {"relative path resolves under home", ".ssh/authorized_keys", 1},
        {"absolute shared file", "/etc/ssh/authorized_keys_all", 0},
        {"absolute with %u component", "/etc/ssh/keys/%u", 1},
        {"absolute with %h component", "/etc/ssh/%h/keys", 1},
        {"absolute with embedded %u", "/etc/ssh/keys%u", 1},
        {"absolute with only literal %%u", "/etc/ssh/%%u", 0},
        /* relative, so per-user regardless of its percent content */
        {"relative with literal percents", "%%%u", 1},
        {"absolute literal percent then %u", "/a%%%u", 1},
        /* the %% skip must not let the 'u' after a literal percent pair
         * count as a %u token */
        {"absolute double literal percent then u", "/a%%%%u", 0},
        {"absolute %u escaped by ..", "/etc/ssh/%u/../shared", 0},
        {"relative escaped by ..", "../shared", 0},
#ifdef _WIN32
        /* Windows-rooted forms are only absolute on a _WIN32 build; these
         * are the security-relevant shared-file shapes that must NOT
         * classify as per-user there */
        {"drive-rooted shared file",
            "C:\\ProgramData\\ssh\\authorized_keys_all", 0},
        {"UNC shared file", "\\\\server\\share\\authorized_keys", 0},
        {"drive-rooted with %u", "C:\\ProgramData\\ssh\\%u", 1},
        {"drive-rooted %u escaped by ..", "C:\\keys\\%u\\..\\shared", 0},
        /* drive-relative resolves under home and fails closed there */
        {"drive-relative path", "C:foo", 1},
#endif
    };

    for (i = 0; i < (int)(sizeof(vectors) / sizeof(*vectors)); i++) {
        Log("    Testing scenario: %s.", vectors[i].desc);
        got = wolfSSHD_AuthKeysPatternIsPerUser(vectors[i].pattern);
        if (got != vectors[i].expect) {
            Log(" got %d expected %d. FAILED.\n", got, vectors[i].expect);
            ret = WS_FATAL_ERROR;
            break;
        }
        Log(" PASSED.\n");
    }

    return ret;
}

/* Parses an AuthorizedUPNDomains line and confirms the stored value is
 * returned by the getter, locking in the new config option's plumbing. */
static int test_ConfigParseAuthorizedUPNDomains(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_CONFIG* conf;
    const char* line = "AuthorizedUPNDomains corp.example other.example";
    char* got;

    conf = wolfSSHD_ConfigNew(NULL);
    if (conf == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: parse AuthorizedUPNDomains.");
        ret = ParseConfigLine(&conf, line, (int)WSTRLEN(line), 0);
        if (ret == WS_SUCCESS) {
            got = wolfSSHD_ConfigGetAuthorizedUPNDomains(conf);
            if (got == NULL ||
                    XSTRCMP(got, "corp.example other.example") != 0) {
                ret = WS_FATAL_ERROR;
            }
        }
        Log(ret == WS_SUCCESS ? " PASSED.\n" : " FAILED.\n");
    }

    if (conf != NULL) {
        wolfSSHD_ConfigFree(conf);
    }

    return ret;
}

/* Exercises the UPN-to-user binding helper directly: local-part matching with
 * no allowlist (back-compat), and the realm allowlist enforcement that fixes
 * the cross-domain authentication bypass. */
static int test_MatchUPNToUser(void)
{
    int ret = WS_SUCCESS;
    int i;
    int sz;

    /* name buffers are not necessarily NUL terminated in a real cert, so the
     * helper is length bounded. For vectors with nameSz == 0, the test derives
     * the length from WSTRLEN(name); a non-zero nameSz bounds a longer buffer to
     * prove bytes past it are ignored. */
    static const struct {
        const char* desc;
        const char* usr;
        const char* name;
        const char* allowList;
        int expect;
        int nameSz;
    } vectors[] = {
        /* no allowlist: local part only, any/absent domain is accepted */
        {"no allowlist, domain ignored", "alice", "alice@other.example", NULL,
            1, 0},
        {"no allowlist, bare local part", "alice", "alice", NULL, 1, 0},
        {"no allowlist, wrong local part", "bob", "alice@corp.example", NULL,
            0, 0},
        {"empty allowlist, domain ignored", "alice", "alice@x.example", "", 1,
            0},

        /* allowlist set: realm must be present and listed */
        {"allowlist match", "alice", "alice@corp.example", "corp.example", 1,
            0},
        {"allowlist mismatch", "alice", "alice@other.example", "corp.example",
            0, 0},
        {"allowlist, missing domain", "alice", "alice", "corp.example", 0, 0},
        {"allowlist, empty domain", "alice", "alice@", "corp.example", 0, 0},
        {"allowlist, wrong local part", "bob", "alice@corp.example",
            "corp.example", 0, 0},
        /* Windows account names are case-insensitive and the local part
         * match follows suit there; on Unix the match stays exact. */
#ifdef _WIN32
        {"case-differing local part", "ALICE", "alice@corp.example",
            "corp.example", 1, 0},
#else
        {"case-differing local part", "ALICE", "alice@corp.example",
            "corp.example", 0, 0},
#endif
        {"allowlist multi, first", "alice", "alice@corp.example",
            "corp.example other.example", 1, 0},
        {"allowlist multi, second", "alice", "alice@other.example",
            "corp.example other.example", 1, 0},
        {"allowlist comma separated", "alice", "alice@other.example",
            "corp.example,other.example", 1, 0},
        {"allowlist case-insensitive", "alice", "alice@CORP.EXAMPLE",
            "corp.example", 1, 0},
        {"allowlist tab separated", "alice", "alice@other.example",
            "corp.example\tother.example", 1, 0},
        {"allowlist mixed ws separators", "alice", "alice@other.example",
            "corp.example\t\r\nother.example", 1, 0},

        /* length-bounded: bytes past nameSz must be ignored. With the full
         * string these would flip the result, so expect=1 only holds if the
         * helper honors nameSz instead of reading to the NUL. */
        {"bounded domain ignores trailing", "alice", "alice@corp.exampleEVIL",
            "corp.example", 1, 18}, /* 18 == strlen("alice@corp.example") */
        {"bounded '@' search ignores trailing", "alice",
            "alice.bob@corp.example", NULL, 1, 5}, /* 5 == strlen("alice") */
    };
    const int numVectors = (int)(sizeof(vectors) / sizeof(*vectors));

    for (i = 0; i < numVectors && ret == WS_SUCCESS; ++i) {
        sz = (vectors[i].nameSz != 0) ? vectors[i].nameSz
                                      : (int)WSTRLEN(vectors[i].name);
        Log("    Testing scenario: %s.", vectors[i].desc);
        if (MatchUPNToUser(vectors[i].usr, vectors[i].name, sz,
                vectors[i].allowList) != vectors[i].expect) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    return ret;
}

/* Exercises the auth-method advertisement logic used by DefaultUserAuthTypes:
 * a method is only offered when its config option is enabled. Covers all four
 * permutations of PasswordAuthentication and PubkeyAuthentication, including the
 * security-relevant cases where pubkey is disabled and where both are disabled
 * (no methods advertised, mask == 0). */
static int test_GetUserAuthTypes(void)
{
    int ret = WS_SUCCESS;
    int i;

    static const struct {
        const char* desc;
        int pwAuth;     /* 1 = leave enabled, 0 = PasswordAuthentication no */
        int pubKeyAuth; /* 1 = leave enabled, 0 = PubkeyAuthentication no */
        int expected;
    } vectors[] = {
        {"both enabled advertises both", 1, 1,
            WOLFSSH_USERAUTH_PASSWORD | WOLFSSH_USERAUTH_PUBLICKEY},
        {"pubkey disabled advertises password only", 1, 0,
            WOLFSSH_USERAUTH_PASSWORD},
        {"password disabled advertises pubkey only", 0, 1,
            WOLFSSH_USERAUTH_PUBLICKEY},
        {"both disabled advertises nothing", 0, 0, 0},
    };
    const int numVectors = (int)(sizeof(vectors) / sizeof(*vectors));
    WOLFSSHD_CONFIG* conf;

    for (i = 0; i < numVectors && ret == WS_SUCCESS; ++i) {
        Log("    Testing scenario: %s.", vectors[i].desc);

        conf = wolfSSHD_ConfigNew(NULL);
        if (conf == NULL) {
            Log(" FAILED.\n");
            ret = WS_MEMORY_E;
            break;
        }

        /* both options default to enabled in wolfSSHD_ConfigNew, so only the
         * disabled cases need an explicit directive */
        if (vectors[i].pwAuth == 0) {
            ret = ParseConfigLine(&conf, "PasswordAuthentication no",
                    (int)WSTRLEN("PasswordAuthentication no"), 0);
        }
        if (ret == WS_SUCCESS && vectors[i].pubKeyAuth == 0) {
            ret = ParseConfigLine(&conf, "PubkeyAuthentication no",
                    (int)WSTRLEN("PubkeyAuthentication no"), 0);
        }

        if (ret == WS_SUCCESS) {
            if (wolfSSHD_GetUserAuthTypes(conf) != vectors[i].expected) {
                Log(" FAILED.\n");
                ret = WS_FATAL_ERROR;
            }
            else {
                Log(" PASSED.\n");
            }
        }
        else {
            Log(" FAILED.\n");
        }

        wolfSSHD_ConfigFree(conf);
    }

    return ret;
}

/* Ensures DefaultUserAuthTypes returns a safe 0 (no auth methods) on NULL args instead of corrupting the bitmask with an error code. */
static int test_DefaultUserAuthTypesNullArgs(void)
{
    int ret = WS_SUCCESS;

    Log("    Testing scenario: DefaultUserAuthTypes with NULL ssh and ctx.");
    if (DefaultUserAuthTypes(NULL, NULL) != 0) {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    return ret;
}

#ifndef _WIN32
/* report a single secure-open scenario; returns WS_SUCCESS when the observed
 * result matches expectation (wantOk != 0 means expect acceptance) */
static int smExpect(const char* desc, int gotRet, int wantOk)
{
    int ok = wantOk ? (gotRet == WS_SUCCESS) : (gotRet != WS_SUCCESS);

    Log("    Testing scenario: %s. %s\n", desc, ok ? "PASSED" : "FAILED");
    return ok ? WS_SUCCESS : WS_FATAL_ERROR;
}

/* establish a scenario precondition; returns WS_SUCCESS when the chmod
 * succeeded so a failed setup does not masquerade as a passing scenario */
static int smChmod(const char* path, mode_t mode)
{
    int ret = WS_SUCCESS;

    if (chmod(path, mode) != 0) {
        Log("    chmod of %s failed.\n", path);
        ret = WS_FATAL_ERROR;
    }
    return ret;
}

/* open 'path' through the secure gate and immediately close it, returning the
 * gate's verdict so a scenario can assert acceptance or rejection */
static int smOpen(const char* path, WUID_T ownerUid, int rejectReadable)
{
    WFILE* f = WBADFILE;
    int ret = wolfSSHD_OpenSecureFile(path, ownerUid, rejectReadable, NULL, &f);

    if (ret == WS_SUCCESS && f != WBADFILE) {
        /* read-only handle; a close failure has no bearing on the verdict */
        (void)WFCLOSE(NULL, f);
    }
    return ret;
}

static int test_OpenSecureFile(void)
{
    int ret = WS_SUCCESS;
    char base[] = "/tmp/wolfsshd_smXXXXXX";
    /* initialized so the unconditional cleanup is harmless if mkdtemp fails */
    char ssh[64] = "";
    char keys[96] = "";
    char hostkey[96] = "";
    char linkKeys[96] = "";
    char wopen[80] = "";
    char wopenKeys[160] = "";
    WUID_T uid = getuid();
    FILE* f = NULL;

    if (mkdtemp(base) == NULL) {
        Log("    mkdtemp failed.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        snprintf(ssh, sizeof(ssh), "%s/.ssh", base);
        snprintf(keys, sizeof(keys), "%s/.ssh/authorized_keys", base);
        snprintf(hostkey, sizeof(hostkey), "%s/host_key", base);
        snprintf(linkKeys, sizeof(linkKeys), "%s/.ssh/link_keys", base);
        snprintf(wopen, sizeof(wopen), "%s/wopen", base);
        snprintf(wopenKeys, sizeof(wopenKeys), "%s/wopen/keys", base);

        if (mkdir(ssh, 0700) != 0) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        f = fopen(keys, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs("ssh-rsa AAAA test\n", f);
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS) {
        f = fopen(hostkey, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs("KEYDATA\n", f);
            fclose(f);
        }
    }

    /* authorized_keys style: owner, writable path, and symlink checks. The temp
     * tree lives under /tmp (mode 1777); the sticky bit makes that world
     * writable ancestor safe, so a good 0600 file is still accepted. */
    if (ret == WS_SUCCESS)
        ret = smChmod(base, 0700);
    if (ret == WS_SUCCESS)
        ret = smChmod(ssh, 0700);
    if (ret == WS_SUCCESS)
        ret = smChmod(keys, 0600);
    if (ret == WS_SUCCESS) {
        ret = smExpect("good perms accepted", smOpen(keys, uid, 0), 1);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(keys, 0660);
    if (ret == WS_SUCCESS) {
        ret = smExpect("group-writable file rejected", smOpen(keys, uid, 0), 0);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(keys, 0606);
    if (ret == WS_SUCCESS) {
        ret = smExpect("world-writable file rejected", smOpen(keys, uid, 0), 0);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(keys, 0600);
    if (ret == WS_SUCCESS)
        ret = smChmod(ssh, 0770);
    if (ret == WS_SUCCESS) {
        ret = smExpect("group-writable parent dir rejected",
            smOpen(keys, uid, 0), 0);
    }
    /* a sticky world-writable parent (as /tmp itself is) is tolerated, since
     * the sticky bit blocks substitution by other users */
    if (ret == WS_SUCCESS)
        ret = smChmod(ssh, 01777);
    if (ret == WS_SUCCESS) {
        ret = smExpect("sticky world-writable parent dir accepted",
            smOpen(keys, uid, 0), 1);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(ssh, 0700);
    /* The helper accepts root-owned files, so the wrong-owner assertion is only
     * meaningful when the test is not running as root. */
    if (ret == WS_SUCCESS && uid != 0) {
        ret = smExpect("wrong owner rejected", smOpen(keys, uid + 1, 0), 0);
    }
    /* a symlinked leaf is rejected outright; lstat() sees the link */
    if (ret == WS_SUCCESS) {
        if (symlink(keys, linkKeys) != 0) {
            Log("    symlink creation failed.\n");
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = smExpect("symlinked leaf rejected", smOpen(linkKeys, uid, 0), 0);
    }
    /* a non-sticky world-writable ancestor directory is rejected */
    if (ret == WS_SUCCESS) {
        if (mkdir(wopen, 0700) != 0) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        f = fopen(wopenKeys, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs("ssh-rsa AAAA test\n", f);
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(wopenKeys, 0600);
    if (ret == WS_SUCCESS)
        ret = smChmod(wopen, 0777);
    if (ret == WS_SUCCESS) {
        ret = smExpect("non-sticky world-writable ancestor rejected",
            smOpen(wopenKeys, uid, 0), 0);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(wopen, 0700);
    /* a non-regular-file target (here a directory) is rejected */
    if (ret == WS_SUCCESS) {
        ret = smExpect("directory target rejected (not a regular file)",
            smOpen(ssh, uid, 0), 0);
    }

    /* host key style: secret, reject group/world readable */
    if (ret == WS_SUCCESS)
        ret = smChmod(hostkey, 0600);
    if (ret == WS_SUCCESS) {
        ret = smExpect("host key 0600 accepted", smOpen(hostkey, uid, 1), 1);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(hostkey, 0640);
    if (ret == WS_SUCCESS) {
        ret = smExpect("group-readable host key rejected",
            smOpen(hostkey, uid, 1), 0);
    }
    if (ret == WS_SUCCESS)
        ret = smChmod(hostkey, 0604);
    if (ret == WS_SUCCESS) {
        ret = smExpect("world-readable host key rejected",
            smOpen(hostkey, uid, 1), 0);
    }
    if (ret == WS_SUCCESS) {
        ret = smExpect("missing file rejected",
            smOpen("/tmp/wolfsshd_sm_dne_xyz", uid, 0), 0);
    }
    if (ret == WS_SUCCESS) {
        ret = smExpect("NULL path rejected", smOpen(NULL, uid, 0), 0);
    }

    /* cleanup */
    unlink(linkKeys);
    unlink(keys);
    unlink(hostkey);
    unlink(wopenKeys);
    rmdir(wopen);
    rmdir(ssh);
    rmdir(base);

    return ret;
}

/* write a config file whose PidFile is 'pidTarget' */
static int pidConfWrite(const char* confPath, const char* pidTarget)
{
    FILE* f;

    f = fopen(confPath, "w");
    if (f == NULL) {
        return WS_FATAL_ERROR;
    }
    fprintf(f, "PidFile %s\n", pidTarget);
    fclose(f);
    return WS_SUCCESS;
}

/* load 'confPath' and run wolfSSHD_ConfigSavePID under umask(0), restoring the
 * umask afterward so later tests are unaffected */
static int pidSaveRun(const char* confPath)
{
    int ret;
    mode_t old;
    WOLFSSHD_CONFIG* cfg;

    cfg = wolfSSHD_ConfigNew(NULL);
    if (cfg == NULL) {
        return WS_MEMORY_E;
    }
    ret = wolfSSHD_ConfigLoad(cfg, confPath);
    if (ret == WS_SUCCESS) {
        /* deliberate worst case: prove the explicit 0644 mode holds even when
         * the umask would not mask any bits */
        old = umask(0);
        wolfSSHD_ConfigSavePID(cfg);
        umask(old);
    }
    wolfSSHD_ConfigFree(cfg);
    return ret;
}

static int pidSave(const char* confPath, const char* pidTarget)
{
    int ret;

    ret = pidConfWrite(confPath, pidTarget);
    if (ret == WS_SUCCESS) {
        ret = pidSaveRun(confPath);
    }
    return ret;
}

/* wolfSSHD_ConfigSavePID must refuse a symlink at the PID path so a planted
 * link cannot truncate another file, and must leave the PID file without group
 * or world write even under a permissive umask, whether it creates the file or
 * reuses an existing one. */
static int test_ConfigSavePID(void)
{
    int ret = WS_SUCCESS;
    int rd;
    long pid = -1;
    char base[] = "/tmp/wolfsshd_pidXXXXXX";
    char conf[80] = "";
    char pidPath[96] = "";
    char victim[96] = "";
    char linkPath[96] = "";
    char hvictim[96] = "";
    char hlink[96] = "";
    char fifo[96] = "";
    char stale[96] = "";
    char foreign[96] = "";
    const char* secret = "VICTIM-CONTENTS\n";
    FILE* f = NULL;
    struct stat st;
    char rbuf[64];
#ifdef RLIMIT_FSIZE
    char failPath[96] = "";
    struct rlimit rlOld;
    struct rlimit rlNew;
    void (*prevXfsz)(int);
#endif

    /* Every path below lives in this directory, which mkdtemp() creates mode
     * 0700. No other user can traverse it, so none of the path-based checks
     * here can be raced. */
    if (mkdtemp(base) == NULL) {
        Log("    mkdtemp failed.\n");
        ret = WS_FATAL_ERROR;
    }

    if (ret == WS_SUCCESS) {
        snprintf(conf, sizeof(conf), "%s/sshd_config", base);
        snprintf(pidPath, sizeof(pidPath), "%s/wolfsshd.pid", base);
        snprintf(victim, sizeof(victim), "%s/victim", base);
        snprintf(linkPath, sizeof(linkPath), "%s/link.pid", base);
        snprintf(hvictim, sizeof(hvictim), "%s/hvictim", base);
        snprintf(hlink, sizeof(hlink), "%s/hlink.pid", base);
        snprintf(fifo, sizeof(fifo), "%s/fifo.pid", base);
        snprintf(stale, sizeof(stale), "%s/stale.pid", base);
        snprintf(foreign, sizeof(foreign), "%s/foreign.pid", base);
#ifdef RLIMIT_FSIZE
        snprintf(failPath, sizeof(failPath), "%s/fail.pid", base);
#endif
    }

    /* Scenario 1: a normal path is written with our PID and is not group or
     * world writable despite umask(0). */
    if (ret == WS_SUCCESS) {
        ret = pidSave(conf, pidPath);
    }
    if (ret == WS_SUCCESS) {
        /* fstat() the open handle instead of stat()ing the path a second
         * time, so the mode asserted below belongs to the same file the PID
         * was read from. */
        f = fopen(pidPath, "r");
        if (f == NULL || fstat(fileno(f), &st) != 0) {
            Log("    Could not open or stat %s.\n", pidPath);
            ret = WS_FATAL_ERROR;
        }
        else {
            rd = fscanf(f, "%ld", &pid);
            ret = smExpect("normal PID file written with our PID",
                (rd == 1 && pid == (long)getpid()) ? WS_SUCCESS
                                                    : WS_FATAL_ERROR, 1);
            if (ret == WS_SUCCESS) {
                ret = smExpect("PID file not group or world writable",
                    (st.st_mode & (S_IWGRP | S_IWOTH)) ? WS_FATAL_ERROR
                                                        : WS_SUCCESS, 1);
            }
        }
        if (f != NULL) {
            fclose(f);
        }
    }

    /* Scenario 2: a symlink at the PID path is refused, link target untouched.
     * The common build exercises the atomic O_NOFOLLOW path; the lstat fallback
     * needs a symlink-capable platform without O_NOFOLLOW. */
    if (ret == WS_SUCCESS) {
        f = fopen(victim, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(secret, f);
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS && symlink(victim, linkPath) != 0) {
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        ret = pidSave(conf, linkPath);
    }
    if (ret == WS_SUCCESS) {
        f = fopen(victim, "r");
        WMEMSET(rbuf, 0, sizeof(rbuf));
        rd = (f != NULL) ? (int)fread(rbuf, 1, sizeof(rbuf) - 1, f) : -1;
        if (f != NULL) {
            fclose(f);
        }
        (void)rd;
        /* A WOLFSSH_NO_SYMLINK_CHECK build does no symlink check by design, so
         * only assert the target survived when the check is compiled in. */
#ifdef WOLFSSH_HAVE_SYMLINK
        ret = smExpect("symlinked PID path not followed, target intact",
            (WSTRCMP(rbuf, secret) == 0) ? WS_SUCCESS : WS_FATAL_ERROR, 1);
#else
        (void)rbuf;
#endif
    }

    /* Scenario 3: a hard link at the PID path is refused (O_NOFOLLOW stops a
     * symlink but not a hard link), leaving the link target untouched. The
     * st_nlink check that enforces this is unconditional, so this always runs. */
    if (ret == WS_SUCCESS) {
        f = fopen(hvictim, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(secret, f);
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS && link(hvictim, hlink) != 0) {
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        ret = pidSave(conf, hlink);
    }
    if (ret == WS_SUCCESS) {
        f = fopen(hvictim, "r");
        WMEMSET(rbuf, 0, sizeof(rbuf));
        rd = (f != NULL) ? (int)fread(rbuf, 1, sizeof(rbuf) - 1, f) : -1;
        if (f != NULL) {
            fclose(f);
        }
        (void)rd;
        ret = smExpect("hard-linked PID path refused, target intact",
            (WSTRCMP(rbuf, secret) == 0) ? WS_SUCCESS : WS_FATAL_ERROR, 1);
    }

    /* Scenario 4: a FIFO at the PID path is rejected (O_NONBLOCK fast-fails the
     * open and the S_ISREG check refuses it), and the FIFO is left in place
     * rather than replaced by a regular PID file. */
    if (ret == WS_SUCCESS && mkfifo(fifo, 0600) != 0) {
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        ret = pidSave(conf, fifo);
    }
    if (ret == WS_SUCCESS) {
        ret = smExpect("FIFO PID path refused, still a FIFO",
            (lstat(fifo, &st) == 0 && S_ISFIFO(st.st_mode)) ? WS_SUCCESS
                                                            : WS_FATAL_ERROR, 1);
    }

    /* Scenario 5: an already existing PID file is reused, but its mode is reset
     * so a world-writable file left behind by an earlier run does not stay
     * world writable. The mode passed to open() applies only on creation. */
    if (ret == WS_SUCCESS) {
        f = fopen(stale, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(secret, f);
            fclose(f);
            if (chmod(stale, 0666) != 0) {
                ret = WS_FATAL_ERROR;
            }
        }
    }
    if (ret == WS_SUCCESS) {
        ret = pidSave(conf, stale);
    }
    if (ret == WS_SUCCESS) {
        pid = -1;
        f = fopen(stale, "r");
        if (f == NULL || fstat(fileno(f), &st) != 0) {
            Log("    Could not open or stat %s.\n", stale);
            ret = WS_FATAL_ERROR;
        }
        else {
            rd = fscanf(f, "%ld", &pid);
            ret = smExpect("existing PID file rewritten with our PID",
                (rd == 1 && pid == (long)getpid()) ? WS_SUCCESS
                                                    : WS_FATAL_ERROR, 1);
            if (ret == WS_SUCCESS) {
                ret = smExpect("existing PID file mode reset, not world "
                    "writable",
                    (st.st_mode & (S_IWGRP | S_IWOTH)) ? WS_FATAL_ERROR
                                                        : WS_SUCCESS, 1);
            }
        }
        if (f != NULL) {
            fclose(f);
        }
    }

    /* Scenario 6: a PID file owned by another user is refused instead of being
     * truncated and adopted. Handing a file to another uid needs root, so this
     * only runs when the test is executed as root. */
    if (ret == WS_SUCCESS && geteuid() == 0) {
        f = fopen(foreign, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(secret, f);
            fclose(f);
            if (chown(foreign, 1, 1) != 0) {
                ret = WS_FATAL_ERROR;
            }
        }
        if (ret == WS_SUCCESS) {
            ret = pidSave(conf, foreign);
        }
        if (ret == WS_SUCCESS) {
            f = fopen(foreign, "r");
            WMEMSET(rbuf, 0, sizeof(rbuf));
            rd = (f != NULL) ? (int)fread(rbuf, 1, sizeof(rbuf) - 1, f) : -1;
            if (f != NULL) {
                fclose(f);
            }
            (void)rd;
            ret = smExpect("PID file owned by another user refused, intact",
                (WSTRCMP(rbuf, secret) == 0) ? WS_SUCCESS : WS_FATAL_ERROR, 1);
        }
    }

#ifdef RLIMIT_FSIZE
    /* Scenario 7: a PID file whose write fails is removed rather than left
     * behind empty. A zero RLIMIT_FSIZE makes the flush at close fail, which is
     * the recovery path taken by a short or unflushed write. */
    if (ret == WS_SUCCESS) {
        ret = pidConfWrite(conf, failPath);
    }
    if (ret == WS_SUCCESS && getrlimit(RLIMIT_FSIZE, &rlOld) != 0) {
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        /* exceeding the limit raises SIGXFSZ, which would kill the test */
        prevXfsz = signal(SIGXFSZ, SIG_IGN);
        rlNew = rlOld;
        rlNew.rlim_cur = 0;
        /* flush first: while the cap is set, a write to a redirected
         * stdout/stderr would silently fail (SIGXFSZ is ignored) */
        fflush(stdout);
        if (setrlimit(RLIMIT_FSIZE, &rlNew) != 0) {
            ret = WS_FATAL_ERROR;
        }
        else {
            ret = pidSaveRun(conf);
            if (setrlimit(RLIMIT_FSIZE, &rlOld) != 0) {
                ret = WS_FATAL_ERROR;
            }
        }
        signal(SIGXFSZ, prevXfsz);
    }
    if (ret == WS_SUCCESS) {
        ret = smExpect("PID file removed when the write fails",
            (stat(failPath, &st) != 0) ? WS_SUCCESS : WS_FATAL_ERROR, 1);
    }
#endif /* RLIMIT_FSIZE */

    /* cleanup */
    unlink(fifo);
    unlink(linkPath);
    unlink(victim);
    unlink(hlink);
    unlink(hvictim);
    unlink(stale);
    unlink(foreign);
#ifdef RLIMIT_FSIZE
    unlink(failPath);
#endif
    unlink(pidPath);
    unlink(conf);
    rmdir(base);

    return ret;
}
#endif /* !_WIN32 */
#if defined(WOLFSSH_OSSH_CERTS) && !defined(_WIN32)
/* Direct coverage for the bit-level prefix matcher used by the certificate
 * source-address check: byte boundaries, partial-byte masks, the zero-prefix
 * match-all case, and the out-of-range guard. */
static int test_OsshPrefixMatch(void)
{
    int ret = WS_SUCCESS;
    int i;
    static const byte a[4] = { 0xAB, 0xCD, 0xEF, 0x12 };
    static const byte b[4] = { 0xAB, 0xCD, 0x00, 0x00 };
    static const byte c[4] = { 0xAB, 0xCD, 0xE0, 0xFF };
    static const struct {
        const char* desc;
        const byte* other;
        int bits;
        int expected;
    } vectors[] = {
        { "zero prefix matches anything",   b,  0, 1 },
        { "one full byte matches",          b,  8, 1 },
        { "two full bytes match",           b, 16, 1 },
        { "third full byte differs",        b, 24, 0 },
        { "partial byte differs at bit 17", b, 17, 0 },
        { "full-length compare differs",    b, 32, 0 },
        { "prefix beyond length rejected",  b, 33, 0 },
        { "negative prefix rejected",       b, -1, 0 },
        { "partial-byte mask matches",      c, 20, 1 },
        { "partial-byte boundary differs",  c, 24, 0 },
    };

    for (i = 0; i < (int)(sizeof(vectors) / sizeof(vectors[0])); i++) {
        Log("    Testing OsshPrefixMatch: %s.", vectors[i].desc);
        if (OsshPrefixMatch(a, vectors[i].other, vectors[i].bits, 4)
                != vectors[i].expected) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
            break;
        }
        Log(" PASSED.\n");
    }

    return ret;
}

/* Direct coverage for the comma-separated CIDR matcher: IPv4/IPv6 prefixes,
 * exact entries, the match-all /0 case, family mismatch, and the OpenSSH
 * negation and malformed-entry rules. */
static int test_OsshSourceAddrMatch(void)
{
    int ret = WS_SUCCESS;
    int i;
    word32 n;
    char buf[160];
    /* 90-character entry, longer than the matcher's internal buffer: must deny
     * rather than be truncated-and-parsed. */
    static const char longEnt[] =
        "123456789012345678901234567890123456789012345678901234567890"
        "123456789012345678901234567890";
    static const struct {
        const char* desc;
        const char* list;
        const char* peer;
        int expected;
    } vectors[] = {
        { "ipv4 inside /24",            "192.168.1.0/24",  "192.168.1.50", 1 },
        { "ipv4 outside /24",           "192.168.1.0/24",  "192.168.2.50", 0 },
        { "ipv4 exact no-prefix match", "10.0.0.5",        "10.0.0.5",     1 },
        { "ipv4 exact no-prefix miss",  "10.0.0.5",        "10.0.0.6",     0 },
        { "ipv4 /32 exact",             "192.168.1.5/32",  "192.168.1.5",  1 },
        { "ipv4 /0 matches all",        "0.0.0.0/0",       "8.8.8.8",      1 },
        { "second list entry matches",
                "192.168.1.0/24,10.0.0.0/8", "10.1.2.3",                   1 },
        { "ipv6 inside /32",            "2001:db8::/32",   "2001:db8::1",  1 },
        { "ipv6 outside /32",           "2001:db8::/32",   "2001:db9::1",  0 },
        { "family mismatch v4 vs v6",   "192.168.1.0/24",  "2001:db8::1",  0 },
        { "oversize prefix denies",     "192.168.1.0/33",  "192.168.1.1",  0 },
        { "empty prefix denies",        "192.168.1.0/",    "192.168.1.1",  0 },
        { "v4-mapped peer matches v4",  "127.0.0.0/8", "::ffff:127.0.0.1",  1 },
        { "v4-mapped peer outside v4",  "10.0.0.0/8",  "::ffff:127.0.0.1",  0 },
        /* The cert option is validated with OpenSSH's addr_match_cidr_list,
         * which has no negation, so any "!" voids the list. ssh-keygen refuses
         * to sign such a certificate in the first place. */
        { "negated entry denies",       "!192.168.1.0/24", "192.168.1.1",  0 },
        { "negation voids earlier match",
                "0.0.0.0/0,!10.0.0.5", "10.0.0.5",                          0 },
        { "negation voids unrelated peer",
                "10.0.0.0/8,!10.0.0.99", "10.0.0.1",                        0 },
        { "negation first voids list",
                "!10.0.0.99,10.0.0.0/8", "10.0.0.1",                        0 },
        { "malformed entry denies",     "not-an-ip",       "1.2.3.4",      0 },
        /* a malformed entry poisons the whole list, so the valid entry that
         * follows it must not rescue the match */
        { "malformed entry denies list",
                "not-an-ip,1.2.3.4", "1.2.3.4",                             0 },
        { "empty entry denies list",    "1.2.3.4,,5.6.7.8", "1.2.3.4",     0 },
        { "bare negation denies list",  "!",               "1.2.3.4",      0 },
        { "family mismatch is not malformed",
                "2001:db8::/32,10.0.0.0/8", "10.1.2.3",                     1 },
    };

    for (i = 0; i < (int)(sizeof(vectors) / sizeof(vectors[0])); i++) {
        Log("    Testing OsshSourceAddrMatch: %s.", vectors[i].desc);
        if (OsshSourceAddrMatch((const byte*)vectors[i].list,
                (word32)WSTRLEN(vectors[i].list), vectors[i].peer)
                != vectors[i].expected) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
            break;
        }
        Log(" PASSED.\n");
    }

    if (ret == WS_SUCCESS) {
        /* An over-length entry cannot be parsed, so it denies the whole list;
         * the valid entry after it must not rescue the match. */
        n = (word32)WSTRLEN(longEnt);
        WMEMCPY(buf, longEnt, n);
        WMEMCPY(buf + n, ",10.0.0.0/8", WSTRLEN(",10.0.0.0/8") + 1);
        Log("    Testing OsshSourceAddrMatch: over-length entry denies list.");
        if (OsshSourceAddrMatch((const byte*)buf, (word32)WSTRLEN(buf),
                "10.1.1.1") != 0) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    return ret;
}

/* Direct coverage for principal binding: empty list rejected (matching OpenSSH
 * sshd), exact and multi-entry matches/misses, and a malformed length-prefixed
 * blob. */
static int test_OsshCertCheckPrincipal(void)
{
    int ret = WS_SUCCESS;
    WS_UserAuthData_PublicKey pub;
    /* SSH string list: uint32 length prefix + bytes, repeated. */
    static const byte one[] = { 0,0,0,4, 'f','r','e','d' };
    static const byte two[] = { 0,0,0,5, 'a','l','i','c','e',
                                0,0,0,4, 'f','r','e','d' };
    static const byte bad[] = { 0,0,0,9, 'f','r','e','d' }; /* len > data */

    WMEMSET(&pub, 0, sizeof(pub));
    pub.principals = NULL;
    pub.principalsSz = 0;
    Log("    Testing OsshCertCheckPrincipal: empty list rejected.");
    if (OsshCertCheckPrincipal(&pub, "anyone") != WSSHD_AUTH_FAILURE) {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    if (ret == WS_SUCCESS) {
        pub.principals = one;
        pub.principalsSz = (word32)sizeof(one);
        Log("    Testing OsshCertCheckPrincipal: exact match / miss.");
        if (OsshCertCheckPrincipal(&pub, "fred") != WSSHD_AUTH_SUCCESS ||
                OsshCertCheckPrincipal(&pub, "bob") != WSSHD_AUTH_FAILURE) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        pub.principals = two;
        pub.principalsSz = (word32)sizeof(two);
        Log("    Testing OsshCertCheckPrincipal: multi-entry match / miss.");
        if (OsshCertCheckPrincipal(&pub, "fred") != WSSHD_AUTH_SUCCESS ||
                OsshCertCheckPrincipal(&pub, "alice") != WSSHD_AUTH_SUCCESS ||
                OsshCertCheckPrincipal(&pub, "carol") != WSSHD_AUTH_FAILURE) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        pub.principals = bad;
        pub.principalsSz = (word32)sizeof(bad);
        Log("    Testing OsshCertCheckPrincipal: malformed blob rejected.");
        if (OsshCertCheckPrincipal(&pub, "fred") != WSSHD_AUTH_FAILURE) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    return ret;
}

/* Direct coverage for the validity window: inclusive lower bound, exclusive
 * upper bound, expired, and not-yet-valid, relative to the current time. */
static int test_OsshCertCheckValidity(void)
{
    int ret = WS_SUCCESS;
    WS_UserAuthData_PublicKey pub;
    word64 now = (word64)WTIME(NULL);

    WMEMSET(&pub, 0, sizeof(pub));
    pub.validAfter = now;            /* inclusive lower bound */
    pub.validBefore = now + 1000;
    Log("    Testing OsshCertCheckValidity: inside window.");
    if (OsshCertCheckValidity(&pub) != WSSHD_AUTH_SUCCESS) {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    if (ret == WS_SUCCESS) {
        pub.validAfter = 0;
        pub.validBefore = now;       /* exclusive upper bound */
        Log("    Testing OsshCertCheckValidity: expired at upper bound.");
        if (OsshCertCheckValidity(&pub) != WSSHD_AUTH_FAILURE) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        pub.validAfter = now + 1000;
        pub.validBefore = now + 2000;
        Log("    Testing OsshCertCheckValidity: not yet valid.");
        if (OsshCertCheckValidity(&pub) != WSSHD_AUTH_FAILURE) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    return ret;
}

/* Cert force-command stash/retrieve on the auth context: the data path
 * GetEffectiveForcedCmd reads to override a configured ForceCommand. */
static int test_OsshCertForcedCmd(void)
{
    int ret = WS_SUCCESS;
    WOLFSSHD_AUTH* auth;
    const char* got;
    static const byte cmd1[] = { 'e','c','h','o',' ','h','i' };
    static const byte cmd2[] = { '/','b','i','n','/','t','r','u','e' };
    struct passwd* (*savedGetpwnam)(const char*);

    /* privilege separation is on by default, so stub getpwnam rather than
     * depending on the host having an sshd user */
    InstallGetpwnamStub(&savedGetpwnam);

    auth = wolfSSHD_AuthCreateUser(NULL, NULL);
    if (auth == NULL) {
        Log("    wolfSSHD_AuthCreateUser failed.\n");
        wsshd_getpwnam_cb = savedGetpwnam;
        return WS_FATAL_ERROR;
    }

    Log("    Testing AuthGetForcedCmd: none set returns NULL.");
    if (wolfSSHD_AuthGetForcedCmd(auth) != NULL) {
        Log(" FAILED.\n");
        ret = WS_FATAL_ERROR;
    }
    else {
        Log(" PASSED.\n");
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing AuthSetCertForcedCmd: stores a retrievable copy.");
        got = NULL;
        if (wolfSSHD_AuthSetCertForcedCmd(auth, cmd1, (word32)sizeof(cmd1))
                != WS_SUCCESS ||
                (got = wolfSSHD_AuthGetForcedCmd(auth)) == NULL ||
                got == (const char*)cmd1 ||
                WSTRLEN(got) != (size_t)sizeof(cmd1) ||
                WMEMCMP(got, cmd1, sizeof(cmd1)) != 0) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing AuthSetCertForcedCmd: second set replaces the first.");
        if (wolfSSHD_AuthSetCertForcedCmd(auth, cmd2, (word32)sizeof(cmd2))
                != WS_SUCCESS ||
                (got = wolfSSHD_AuthGetForcedCmd(auth)) == NULL ||
                WSTRLEN(got) != (size_t)sizeof(cmd2) ||
                WMEMCMP(got, cmd2, sizeof(cmd2)) != 0) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    if (ret == WS_SUCCESS) {
        Log("    Testing AuthSetCertForcedCmd: empty/NULL rejected, no clobber.");
        if (wolfSSHD_AuthSetCertForcedCmd(auth, cmd1, 0) != WS_BAD_ARGUMENT ||
                wolfSSHD_AuthSetCertForcedCmd(NULL, cmd1, (word32)sizeof(cmd1))
                    != WS_BAD_ARGUMENT ||
                (got = wolfSSHD_AuthGetForcedCmd(auth)) == NULL ||
                WMEMCMP(got, cmd2, sizeof(cmd2)) != 0) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    /* A configured ForceCommand must win over a certificate force-command; the
     * cert command applies only when no ForceCommand is configured. */
    if (ret == WS_SUCCESS) {
        Log("    Testing AuthMergeForcedCmd: config overrides cert.");
        if (WSTRCMP(wolfSSHD_AuthMergeForcedCmd("cfgcmd", "certcmd"),
                    "cfgcmd") != 0 ||
                WSTRCMP(wolfSSHD_AuthMergeForcedCmd("cfgcmd", NULL),
                    "cfgcmd") != 0 ||
                WSTRCMP(wolfSSHD_AuthMergeForcedCmd(NULL, "certcmd"),
                    "certcmd") != 0 ||
                wolfSSHD_AuthMergeForcedCmd(NULL, NULL) != NULL) {
            Log(" FAILED.\n");
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    wolfSSHD_AuthFreeUser(auth);
    wsshd_getpwnam_cb = savedGetpwnam;
    return ret;
}

#ifdef WOLFSSL_BASE64_ENCODE
/* Run CheckPublicKeyUnix for one scenario and check acceptance vs rejection. */
static int pkExpect(const char* desc, const char* user,
        const WS_UserAuthData_PublicKey* pub, const char* caFile,
        WOLFSSHD_AUTH* authCtx, int wantOk)
{
    int rc = CheckPublicKeyUnix(user, pub, caFile, NULL, authCtx);
    int ok = (rc == WSSHD_AUTH_SUCCESS);

    Log("    Testing CheckPublicKeyUnix: %s.", desc);
    if (ok == wantOk) {
        Log(" PASSED.\n");
        return WS_SUCCESS;
    }
    Log(" FAILED (rc=%d).\n", rc);
    return WS_FATAL_ERROR;
}

/* Unit coverage for the CheckPublicKeyUnix certificate gate ordering: CA-key ->
 * TrustedUserCAKeys -> account -> CA trust -> principal -> validity -> source.
 * Each scenario flips one input from an all-valid baseline. */
static int test_CheckPublicKeyUnixOrdering(void)
{
    int ret = WS_SUCCESS;
    WS_UserAuthData_PublicKey good, p;
    struct passwd* pw;
    const char* user;
    const char* tmpDir;
    char base[128];
    char caFile[160] = "";   /* base + "/ca_keys" without truncation */
    char emptyFile[160] = "";
    char line[1024];
    byte principals[128];
    word32 nameLen;
    word32 pSz;
    word64 now = (word64)WTIME(NULL);
    FILE* f = NULL;
    WOLFSSHD_AUTH* auth = NULL;
    /* Arbitrary bytes standing in for a CA signing-key blob; only byte-for-byte
     * trust-list membership is checked here, not a signature. */
    static const byte caBlob[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };
    /* principals list that does not contain the running account. */
    static const byte wrongP[] = { 0,0,0,7, 'n','o','m','a','t','c','h' };

    pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        Log("    getpwuid failed.\n");
        return WS_FATAL_ERROR;
    }
    user = pw->pw_name;
    nameLen = (word32)WSTRLEN(user);
    if (nameLen == 0 || nameLen + 4 > (word32)sizeof(principals)) {
        return WS_FATAL_ERROR;
    }
    /* principals list holding the running account: [uint32 len][name]. */
    principals[0] = (byte)((nameLen >> 24) & 0xff);
    principals[1] = (byte)((nameLen >> 16) & 0xff);
    principals[2] = (byte)((nameLen >> 8) & 0xff);
    principals[3] = (byte)(nameLen & 0xff);
    WMEMCPY(principals + 4, user, nameLen);
    pSz = 4 + nameLen;

    /* Honor TMPDIR for the scratch dir, falling back to /tmp. */
    tmpDir = getenv("TMPDIR");
    if (tmpDir == NULL || tmpDir[0] == '\0') {
        tmpDir = "/tmp";
    }
    WSNPRINTF(base, sizeof(base), "%s/wolfsshd_pkXXXXXX", tmpDir);

    if (mkdtemp(base) == NULL) {
        Log("    mkdtemp failed.\n");
        return WS_FATAL_ERROR;
    }
    snprintf(caFile, sizeof(caFile), "%s/ca_keys", base);
    snprintf(emptyFile, sizeof(emptyFile), "%s/empty", base);

    /* A TrustedUserCAKeys file that trusts caBlob, plus an empty one. */
    ret = BuildAuthKeysLine(caBlob, (word32)sizeof(caBlob), line, sizeof(line));
    if (ret == WS_SUCCESS) {
        f = fopen(caFile, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fputs(line, f);
            fputs("\n", f);
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS) {
        f = fopen(emptyFile, "w");
        if (f == NULL) {
            ret = WS_FATAL_ERROR;
        }
        else {
            fclose(f);
        }
    }
    if (ret == WS_SUCCESS && chmod(caFile, 0600) != 0) {
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS && chmod(emptyFile, 0600) != 0) {
        ret = WS_FATAL_ERROR;
    }

    /* All-valid baseline: trusted CA, real account, matching principal, inside
     * validity window, no source-address restriction. */
    WMEMSET(&good, 0, sizeof(good));
    good.isOsshCert = 1;
    good.caKey = caBlob;
    good.caKeySz = (word32)sizeof(caBlob);
    good.principals = principals;
    good.principalsSz = pSz;
    good.validAfter = 0;
    good.validBefore = now + 1000;

    if (ret == WS_SUCCESS) {
        ret = pkExpect("baseline accepted", user, &good, caFile, NULL, 1);
    }
    if (ret == WS_SUCCESS) {
        p = good; p.caKey = NULL; p.caKeySz = 0;
        ret = pkExpect("missing CA key rejected", user, &p, caFile, NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        ret = pkExpect("no TrustedUserCAKeys rejected", user, &good, NULL,
            NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        ret = pkExpect("unknown local account rejected",
            "wolfsshd_nouser_xyz", &good, caFile, NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        ret = pkExpect("untrusted CA rejected", user, &good, emptyFile,
            NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        p = good; p.principals = wrongP; p.principalsSz = (word32)sizeof(wrongP);
        ret = pkExpect("wrong principal rejected", user, &p, caFile, NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        p = good; p.validBefore = 1; /* already expired */
        ret = pkExpect("expired cert rejected", user, &p, caFile, NULL, 0);
    }
    if (ret == WS_SUCCESS) {
        p = good;
        p.sourceAddress = (const byte*)"10.0.0.0/8";
        p.sourceAddressSz = (word32)WSTRLEN("10.0.0.0/8");
        ret = pkExpect("source-address fails closed without peer IP",
            user, &p, caFile, NULL, 0);
    }
    /* With a peer IP supplied, the source-address restriction accepts an
     * in-range peer and denies an out-of-range one. */
    if (ret == WS_SUCCESS) {
        /* privilege separation is on by default, so stub getpwnam rather than
         * depending on the host having an sshd user. Restore it immediately:
         * the scenarios below resolve the real running account. */
        struct passwd* (*savedGetpwnam)(const char*);

        InstallGetpwnamStub(&savedGetpwnam);
        auth = wolfSSHD_AuthCreateUser(NULL, NULL);
        wsshd_getpwnam_cb = savedGetpwnam;
        if (auth == NULL) {
            Log("    wolfSSHD_AuthCreateUser failed.\n");
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        wolfSSHD_AuthSetPeerIp(auth, "127.0.0.1");
        p = good;
        p.sourceAddress = (const byte*)"127.0.0.0/8";
        p.sourceAddressSz = (word32)WSTRLEN("127.0.0.0/8");
        ret = pkExpect("source-address peer in range accepted",
            user, &p, caFile, auth, 1);
    }
    if (ret == WS_SUCCESS) {
        p = good;
        p.sourceAddress = (const byte*)"10.0.0.0/8";
        p.sourceAddressSz = (word32)WSTRLEN("10.0.0.0/8");
        ret = pkExpect("source-address peer out of range rejected",
            user, &p, caFile, auth, 0);
    }

    if (auth != NULL) {
        wolfSSHD_AuthFreeUser(auth);
    }
    unlink(caFile);
    unlink(emptyFile);
    rmdir(base);

    return ret;
}
#endif /* WOLFSSL_BASE64_ENCODE */
#endif /* WOLFSSH_OSSH_CERTS && !_WIN32 */

/* Verify AuthorizedKeysFile token substitution so an absolute pattern with %u
 * resolves to a per-user path instead of the same literal string for every
 * user. */
static int test_ResolveAuthKeysPath(void)
{
    int ret = WS_SUCCESS;
    int rc;
    word32 i;
    char resolved[MAX_PATH_SZ];
    char longPat[MAX_PATH_SZ + 16];
    char longHome[MAX_PATH_SZ];
    static const struct {
        const char* home;
        const char* pattern;
        const char* user;
        int expectRet;
        const char* expect;
    } vectors[] = {
        /* absolute pattern with %u resolves to a distinct path per user */
        { "/home/alice", "/etc/ssh/keys/%u", "alice", WS_SUCCESS,
          "/etc/ssh/keys/alice" },
        { "/home/bob",   "/etc/ssh/keys/%u", "bob",   WS_SUCCESS,
          "/etc/ssh/keys/bob" },
        /* %h expands to the home directory */
        { "/home/alice", "%h/.ssh/authorized_keys", "alice", WS_SUCCESS,
          "/home/alice/.ssh/authorized_keys" },
        /* %% is a literal percent */
        { "/home/alice", "/keys/100%%/%u", "alice", WS_SUCCESS,
          "/keys/100%/alice" },
        /* relative pattern is taken under the home directory */
        { "/home/alice", "keys/%u", "alice", WS_SUCCESS,
          "/home/alice/keys/alice" },
#ifdef _WIN32
        /* drive-letter and backslash roots are absolute on Windows */
        { "/home/alice", "C:\\keys\\%u", "alice", WS_SUCCESS,
          "C:\\keys\\alice" },
        { "/home/alice", "\\keys\\%u", "alice", WS_SUCCESS,
          "\\keys\\alice" },
#else
        /* on POSIX they are relative, taken under the home directory */
        { "/home/alice", "C:\\keys\\%u", "alice", WS_SUCCESS,
          "/home/alice/C:\\keys\\alice" },
        { "/home/alice", "\\keys\\%u", "alice", WS_SUCCESS,
          "/home/alice/\\keys\\alice" },
#endif
        /* a bare "X:" is drive-relative, not absolute, on either platform and
         * so resolves under the home directory */
        { "/home/alice", "C:keys\\%u", "alice", WS_SUCCESS,
          "/home/alice/C:keys\\alice" },
        { "/home/alice", "C:%u", "alice", WS_SUCCESS,
          "/home/alice/C:alice" },
        /* NULL pattern falls back to the default location */
        { "/home/alice", NULL, "alice", WS_SUCCESS,
          "/home/alice/.ssh/authorized_keys" },
        /* a trailing lone '%' is treated as a literal */
        { "/home/alice", "/etc/keys/%u%", "alice", WS_SUCCESS,
          "/etc/keys/alice%" },
        /* unrecognized token fails closed */
        { "/home/alice", "/etc/keys/%q", "alice", WS_FATAL_ERROR, NULL },
        /* recognized token with no available value (NULL user) fails closed */
        { "/home/alice", "/etc/keys/%u", NULL, WS_FATAL_ERROR, NULL },
    };

    for (i = 0; ret == WS_SUCCESS && i < sizeof(vectors) / sizeof(vectors[0]);
         i++) {
        Log("    Testing scenario: pattern \"%s\" user \"%s\".",
            vectors[i].pattern != NULL ? vectors[i].pattern : "(null)",
            vectors[i].user != NULL ? vectors[i].user : "(null)");
        /* non-zero fill so a missing null terminator cannot pass unnoticed */
        WMEMSET(resolved, 0xA5, sizeof(resolved));
        rc = ResolveAuthKeysPath(vectors[i].home, vectors[i].pattern,
                                 vectors[i].user, resolved);
        if (rc != vectors[i].expectRet) {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
        else if (vectors[i].expect != NULL &&
                 WSTRCMP(resolved, vectors[i].expect) != 0) {
            Log(" FAILED (got \"%s\").\n", resolved);
            ret = WS_FATAL_ERROR;
        }
        else {
            Log(" PASSED.\n");
        }
    }

    /* an expansion that exceeds MAX_PATH_SZ fails closed */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: over-length pattern is rejected.");
        WMEMSET(longPat, 'a', sizeof(longPat) - 1);
        longPat[0] = '/';
        longPat[sizeof(longPat) - 1] = '\0';
        WMEMSET(resolved, 0, sizeof(resolved));
        rc = ResolveAuthKeysPath("/home/alice", longPat, "alice", resolved);
        if (rc == WS_FATAL_ERROR) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    /* a relative pattern under a long home directory fails closed */
    if (ret == WS_SUCCESS) {
        Log("    Testing scenario: relative pattern under long home is "
            "rejected.");
        WMEMSET(longHome, 'a', sizeof(longHome) - 1);
        longHome[0] = '/';
        longHome[sizeof(longHome) - 1] = '\0';
        WMEMSET(resolved, 0, sizeof(resolved));
        rc = ResolveAuthKeysPath(longHome, "keys/%u", "alice", resolved);
        if (rc == WS_FATAL_ERROR) {
            Log(" PASSED.\n");
        }
        else {
            Log(" FAILED (rc=%d).\n", rc);
            ret = WS_FATAL_ERROR;
        }
    }

    return ret;
}

/* read an entire file into a heap buffer; *outSz is set to the file size.
 * returns NULL on any failure */
static byte* ReadWholeFile(const char* path, word32* outSz)
{
    FILE* f;
    byte* buf = NULL;
    long sz;

    f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
            fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    /* malloc(0) may return NULL, which this helper reports as a read failure */
    buf = (byte*)malloc((size_t)(sz > 0 ? sz : 1));
    if (buf != NULL) {
        if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    if (buf != NULL) {
        *outSz = (word32)sz;
    }
    return buf;
}

/* locate the repo's keys/ directory regardless of whether this binary is run
 * from the repo root, from apps/wolfsshd/test/, or by "make check". Automake
 * runs TESTS from the build directory and exports srcdir, which is the only
 * way to find keys/ in a VPATH build. */
static int BuildKeyPath(const char* name, char* out, size_t outSz)
{
    static const char* candidates[] = { "keys/", "../../../keys/" };
    const char* srcDir;
    word32 i;
    int n;
    FILE* f;

    srcDir = getenv("srcdir");
    if (srcDir != NULL) {
        n = WSNPRINTF(out, outSz, "%s/keys/%s", srcDir, name);
        /* srcdir is absolute in a VPATH build, so a truncated path is a real
         * possibility; a truncated name must not be opened */
        if (n > 0 && (size_t)n < outSz) {
            f = fopen(out, "rb");
            if (f != NULL) {
                fclose(f);
                return WS_SUCCESS;
            }
        }
    }

    for (i = 0; i < (word32)(sizeof(candidates) / sizeof(candidates[0]));
            i++) {
        n = WSNPRINTF(out, outSz, "%s%s", candidates[i], name);
        if (n <= 0 || (size_t)n >= outSz) {
            continue;
        }
        f = fopen(out, "rb");
        if (f != NULL) {
            fclose(f);
            return WS_SUCCESS;
        }
    }
    return WS_FATAL_ERROR;
}

/* Regression coverage for wolfSSHD_DetectPrivKeyFormat(), the host-key
 * format auto-detection SetupCTX() relies on to load PEM-armored OpenSSH
 * keys, raw binary openssh-key-v1 blobs (including composite ML-DSA host
 * keys, which are only ever stored in that raw form), PKCS#8 PEM keys
 * (e.g. ML-DSA), and traditional PEM/DER keys. */
static int test_DetectPrivKeyFormat(void)
{
    typedef struct {
        const char* desc;
        const char* file;
        int wantFormat;
        /* Expected wc_KeyPemToDer() outcome (1 = succeeds, keyDer non-NULL;
         * 0 = fails, keyDer NULL); pins down which branch each case hits. */
        int wantKeyDerNonNull;
    } DPK_CASE;
    static const DPK_CASE cases[] = {
        { "PEM-armored OpenSSH key", "id_ecdsa", WOLFSSH_FORMAT_OPENSSH, 0 },
        { "raw binary openssh-key-v1 composite ML-DSA key",
            "server-key-mldsa44ed25519", WOLFSSH_FORMAT_OPENSSH, 0 },
        { "PEM traditional key decodes to DER/ASN1", "server-key-ecc.pem",
            WOLFSSH_FORMAT_ASN1, 1 },
        { "un-armored raw DER key falls through to ASN1",
            "server-key-mldsa44.der", WOLFSSH_FORMAT_ASN1, 0 },
        { "PKCS#8 PEM ML-DSA key decodes to DER/ASN1 without PKCS8 "
            "stripping", "server-key-mldsa44.pem", WOLFSSH_FORMAT_ASN1, 1 },
    };
    word32 i;
    int ret = WS_SUCCESS;
    int ranCases = 0;
    byte dummy = 0;
    byte* badKeyDer = NULL;
    byte* badPrivBuf = NULL;
    word32 badPrivBufSz = 0;
    int badGot;

    /* A 0-byte host key file (or otherwise bad arguments) must be rejected
     * without touching the out-params, matching the empty-file case
     * getBufferFromFile() can hand back. Poison out-params with sentinels
     * first, so the NULL/0 checks below catch a skipped reset instead of
     * matching by coincidence. */
    badKeyDer = (byte*)&dummy;
    badPrivBuf = (byte*)&dummy;
    badPrivBufSz = 0xDEADBEEF;
    badGot = wolfSSHD_DetectPrivKeyFormat(&dummy, 0, NULL, &badKeyDer,
            &badPrivBuf, &badPrivBufSz);
    Log("    Testing scenario: 0-length buffer. %s\n",
        (badGot == WS_BAD_ARGUMENT && badKeyDer == NULL &&
            badPrivBuf == NULL && badPrivBufSz == 0) ? "PASSED" : "FAILED");
    if (badGot != WS_BAD_ARGUMENT || badKeyDer != NULL ||
            badPrivBuf != NULL || badPrivBufSz != 0) {
        return WS_FATAL_ERROR;
    }

    badGot = wolfSSHD_DetectPrivKeyFormat(NULL, sizeof(dummy), NULL,
            &badKeyDer, &badPrivBuf, &badPrivBufSz);
    Log("    Testing scenario: NULL data pointer. %s\n",
        (badGot == WS_BAD_ARGUMENT) ? "PASSED" : "FAILED");
    if (badGot != WS_BAD_ARGUMENT) {
        return WS_FATAL_ERROR;
    }

    badGot = wolfSSHD_DetectPrivKeyFormat(&dummy, sizeof(dummy), NULL, NULL,
            &badPrivBuf, &badPrivBufSz);
    Log("    Testing scenario: NULL keyDer pointer. %s\n",
        (badGot == WS_BAD_ARGUMENT) ? "PASSED" : "FAILED");
    if (badGot != WS_BAD_ARGUMENT) {
        return WS_FATAL_ERROR;
    }

    badGot = wolfSSHD_DetectPrivKeyFormat(&dummy, sizeof(dummy), NULL,
            &badKeyDer, NULL, &badPrivBufSz);
    Log("    Testing scenario: NULL privBuf pointer. %s\n",
        (badGot == WS_BAD_ARGUMENT) ? "PASSED" : "FAILED");
    if (badGot != WS_BAD_ARGUMENT) {
        return WS_FATAL_ERROR;
    }

    badGot = wolfSSHD_DetectPrivKeyFormat(&dummy, sizeof(dummy), NULL,
            &badKeyDer, &badPrivBuf, NULL);
    Log("    Testing scenario: NULL privBufSz pointer. %s\n",
        (badGot == WS_BAD_ARGUMENT) ? "PASSED" : "FAILED");
    if (badGot != WS_BAD_ARGUMENT) {
        return WS_FATAL_ERROR;
    }

    for (i = 0; i < (word32)(sizeof(cases) / sizeof(cases[0])); i++) {
        /* srcdir is an absolute path under "make check", so leave room */
        char path[512];
        byte* data;
        word32 dataSz = 0;
        byte* keyDer = NULL;
        byte* privBuf = NULL;
        word32 privBufSz = 0;
        int gotFormat;

        /* not being able to find keys/ says nothing about the code under
         * test, so skip rather than fail the run */
        if (BuildKeyPath(cases[i].file, path, sizeof(path)) != WS_SUCCESS) {
            Log("    Testing scenario: %s. SKIPPED (couldn't locate %s)\n",
                cases[i].desc, cases[i].file);
            continue;
        }
        ranCases++;

        data = ReadWholeFile(path, &dataSz);
        if (data == NULL) {
            Log("    Testing scenario: %s. FAILED (couldn't read %s)\n",
                cases[i].desc, path);
            return WS_FATAL_ERROR;
        }

        gotFormat = wolfSSHD_DetectPrivKeyFormat(data, dataSz, NULL, &keyDer,
                &privBuf, &privBufSz);

        Log("    Testing scenario: %s. %s\n", cases[i].desc,
            (gotFormat == cases[i].wantFormat) ? "PASSED" : "FAILED");
        if (gotFormat != cases[i].wantFormat) {
            ret = WS_FATAL_ERROR;
        }

        Log("    Testing scenario: %s wc_KeyPemToDer branch. %s\n",
            cases[i].desc,
            ((keyDer != NULL) == (cases[i].wantKeyDerNonNull != 0)) ?
                "PASSED" : "FAILED");
        if ((keyDer != NULL) != (cases[i].wantKeyDerNonNull != 0)) {
            ret = WS_FATAL_ERROR;
        }

        if (gotFormat >= 0) {
            int privOk = 0;
            if (keyDer != NULL && privBuf == keyDer && privBufSz > 0) {
                privOk = 1;
            } else if (keyDer == NULL && privBuf == data && privBufSz == dataSz) {
                privOk = 1;
            }
            Log("    Testing scenario: %s privBuf correctness. %s\n",
                cases[i].desc, privOk ? "PASSED" : "FAILED");
            if (!privOk) {
                ret = WS_FATAL_ERROR;
            }
        }

        if (keyDer != NULL) {
            WFREE(keyDer, NULL, DYNTYPE_SSHD);
        }
        free(data);
        if (ret != WS_SUCCESS) {
            return ret;
        }
    }

    /* Synthetic case: wc_KeyPemToDer() succeeds but the decoded body starts
     * with the openssh-key-v1 magic -- forces the "PEM-decoded result may
     * still be OpenSSH binary" path no file-based case above reaches. */
    {
        /* base64 of "openssh-key-v1\0PADPADPADPADPAD" */
        static const char pemOpenSshBody[] =
            "-----BEGIN PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAUEFEUEFEUEFEUEFEUEFE\n"
            "-----END PRIVATE KEY-----\n";
        byte* keyDer = NULL;
        byte* privBuf = NULL;
        word32 privBufSz = 0;
        int gotFormat;

        gotFormat = wolfSSHD_DetectPrivKeyFormat(
                (byte*)pemOpenSshBody, (word32)(sizeof(pemOpenSshBody) - 1),
                NULL, &keyDer, &privBuf, &privBufSz);

        Log("    Testing scenario: PEM decodes to an OpenSSH blob. %s\n",
            (gotFormat == WOLFSSH_FORMAT_OPENSSH && keyDer != NULL) ?
                "PASSED" : "FAILED");
        if (gotFormat != WOLFSSH_FORMAT_OPENSSH || keyDer == NULL) {
            ret = WS_FATAL_ERROR;
        }

        if (keyDer != NULL) {
            WFREE(keyDer, NULL, DYNTYPE_SSHD);
        }
        if (ret != WS_SUCCESS) {
            return ret;
        }
    }

    if (ranCases == 0) {
        Log("    test_DetectPrivKeyFormat FAILED: No file-based cases ran. "
            "(Are we in the right directory?)\n");
        return WS_FATAL_ERROR;
    }

    /* Synthetic case: Corrupt/unsupported PEM buffer that fails wc_KeyPemToDer
     * and does not start with OpenSSH magic, nor raw DER (0x30). */
    {
        static const char corruptPem[] =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "not valid base64 !!!\n"
            "-----END RSA PRIVATE KEY-----\n";
        byte* keyDer = NULL;
        byte* privBuf = NULL;
        word32 privBufSz = 0;
        int gotFormat;

        gotFormat = wolfSSHD_DetectPrivKeyFormat(
                (byte*)corruptPem, (word32)(sizeof(corruptPem) - 1),
                NULL, &keyDer, &privBuf, &privBufSz);

        Log("    Testing scenario: Corrupt/unsupported PEM buffer. %s\n",
            (gotFormat == WS_BAD_FILE_E && keyDer == NULL) ?
                "PASSED" : "FAILED");
        if (gotFormat != WS_BAD_FILE_E || keyDer != NULL) {
            ret = WS_FATAL_ERROR;
        }

        if (keyDer != NULL) {
            WFREE(keyDer, NULL, DYNTYPE_SSHD);
        }
        if (ret != WS_SUCCESS) {
            return ret;
        }
    }

    return ret;
}

const TEST_CASE testCases[] = {
    TEST_DECL(test_ConfigDefaults),
    TEST_DECL(test_PermitRootProhibitPassword),
    TEST_DECL(test_ParseConfigLine),
    TEST_DECL(test_ConfigOptionPrefixOrder),
    TEST_DECL(test_ConfigGlobalOnlyOptionsInMatch),
#ifdef WOLFSSHD_WIN_STORE_CONFIG
    TEST_DECL(test_ConfigSetWinUserOptions),
#endif
    TEST_DECL(test_AuthKeysPatternIsPerUser),
    TEST_DECL(test_ConfigCopy),
    TEST_DECL(test_GetUserConfMatchOverride),
    TEST_DECL(test_MatchUnsupportedSelector),
    TEST_DECL(test_GetUserConfMatchSubstring),
    TEST_DECL(test_GetUserConfMatchSubstringGroup),
    TEST_DECL(test_GetUserConfMatchLiteralKeywordName),
    TEST_DECL(test_GetUserConfMatchBareKeyword),
    TEST_DECL(test_GetUserConfMatchRepeatedKeyword),
    TEST_DECL(test_GetUserConfMatchGroupAnd),
    TEST_DECL(test_GetUserConfMatchSecondaryGroup),
    TEST_DECL(test_CAKeysFileDiffers),
    TEST_DECL(test_PermitRootLoginModes),
    TEST_DECL(test_ConfigParseAuthorizedUPNDomains),
    TEST_DECL(test_MatchUPNToUser),
    TEST_DECL(test_IncludeRecursionBound),
    TEST_DECL(test_GetUserConfMatchNoInherit),
    TEST_DECL(test_ConfigIncludeMatchChain),
    TEST_DECL(test_GetUserAuthTypes),
    TEST_DECL(test_DefaultUserAuthTypesNullArgs),
    TEST_DECL(test_ConfigSetAuthKeysFile),
    TEST_DECL(test_ResolveAuthKeysPath),
    TEST_DECL(test_ConfigFree),
#ifndef _WIN32
    TEST_DECL(test_OpenSecureFile),
    TEST_DECL(test_ConfigSavePID),
#endif
    TEST_DECL(test_DetectPrivKeyFormat),
#ifdef WOLFSSL_BASE64_ENCODE
    TEST_DECL(test_CheckAuthKeysLine),
    TEST_DECL(test_CheckAuthKeysLineTypes),
    #ifndef WOLFSSH_NO_MLDSA
    TEST_DECL(test_CheckAuthKeysLineMaxSz),
    #endif
#endif
#if defined(WOLFSSL_BASE64_ENCODE) && !defined(_WIN32)
    TEST_DECL(test_SearchForPubKey),
#endif
#ifndef _WIN32
    TEST_DECL(test_GetUserGroupNames),
    TEST_DECL(test_AuthReducePermissionsUser_ok),
    TEST_DECL(test_AuthReducePermissionsUser_gid_fail),
    TEST_DECL(test_AuthReducePermissionsUser_uid_fail),
    TEST_DECL(test_AuthCreateUser_privSepOff),
#if (defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)) && \
        defined(WOLFSSHD_HAVE_SHADOW)
    TEST_DECL(test_RequestAuth_pwAuthNoRejectsBeforePasswordCheck),
    TEST_DECL(test_RequestAuth_permitEmptyPwDeniedFakesPasswordCheck),
    TEST_DECL(test_RequestAuth_checkPasswordCbErrorFailsClosed),
    TEST_DECL(test_RequestAuth_raisePermissionsFailFakeCheckGating),
    TEST_DECL(test_RequestAuth_userConfNullFakeCheckGating),
#endif
    TEST_DECL(test_AuthRaisePermissions_offSkipsSyscalls),
    TEST_DECL(test_AuthRaisePermissions_separateCallsSyscalls),
    TEST_DECL(test_AuthRaisePermissions_nullArg),
    TEST_DECL(test_AuthRaisePermissions_gidFailSkipsUid),
    TEST_DECL(test_AuthRaisePermissions_uidFail),

    TEST_DECL(test_AuthReducePermissions_offSkipsSyscalls),
    TEST_DECL(test_AuthReducePermissions_separateCallsSyscalls),
    TEST_DECL(test_AuthReducePermissions_nullArg),
    TEST_DECL(test_AuthReducePermissions_gidFailContinuesToUid),
    TEST_DECL(test_AuthReducePermissions_uidFail),

    TEST_DECL(test_AuthSetGroups_ok),
    TEST_DECL(test_AuthSetGroups_setgroups_fail),
    TEST_DECL(test_AuthSetGroups_getgrouplist_fail),
#endif
#if defined(WOLFSSH_HAVE_LIBCRYPT) || defined(WOLFSSH_HAVE_LIBLOGIN)
    TEST_DECL(test_CheckPasswordHashUnix),
#ifdef WOLFSSHD_HAVE_SHADOW
    TEST_DECL(test_GetFakeHashFromTemplate),
    TEST_DECL(test_CachedFakeHashConsumption),
    TEST_DECL(test_CheckPasswordUnix_shadowLookupFails),
    TEST_DECL(test_CheckPasswordUnix_shadowHashTooLong),
    TEST_DECL(test_CheckPasswordUnix_shadowNullPassword),
    TEST_DECL(test_CheckPasswordUnix_shadowLookupSucceeds),
    TEST_DECL(test_CheckPasswordUnix_unknownUser),
    TEST_DECL(test_DoFakePasswordCheck_pubkeyUnionSafety),
    TEST_DECL(test_AuthInit),
    TEST_DECL(test_AuthInit_degradedMode),
    TEST_DECL(test_AuthInit_nullPasswordField),
    TEST_DECL(test_AddShadowLineToFakeHashCache_dedup),
    TEST_DECL(test_AddShadowLineToFakeHashCache_cap),
    TEST_DECL(test_ScanShadowFile_multipleEntries),
    TEST_DECL(test_ScanShadowFile_truncatedLine),
#endif
    TEST_DECL(test_DefaultUserAuth_OOBRead),
#endif
#if defined(WOLFSSH_OSSH_CERTS) && !defined(_WIN32)
    TEST_DECL(test_OsshPrefixMatch),
    TEST_DECL(test_OsshSourceAddrMatch),
    TEST_DECL(test_OsshCertCheckPrincipal),
    TEST_DECL(test_OsshCertCheckValidity),
    TEST_DECL(test_OsshCertForcedCmd),
#ifdef WOLFSSL_BASE64_ENCODE
    TEST_DECL(test_CheckPublicKeyUnixOrdering),
#endif
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
