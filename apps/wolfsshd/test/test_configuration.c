#include <stdarg.h>

#include <wolfssh/ssh.h>
#include <configuration.h>

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
                WSNPRINTF(filepath, sizeof filepath, "%s%s",
                        "./sshd_config.d/", d->d_name);
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
        Log("%s FAILED.\n", tc->name);
    }
    else {
        Log("%s PASSED.\n", tc->name);
    }

    TestCleanup();

    return ret;
}

typedef struct {
    const char* desc;
    const char* line;
    int shouldFail;
} CONFIG_LINE_VECTOR;

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

const TEST_CASE testCases[] = {
    TEST_DECL(test_ParseConfigLine)
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
