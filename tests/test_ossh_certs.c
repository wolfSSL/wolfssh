#include <wolfssh/ossh_certs.h>
#include <wolfssh/error.h>
#include <wolfssh/port.h>
#include <wolfssh/ssh.h>

/*
 * Reads an OpenSSH-style cert from file into buf. Returns the length of buf on
 * success and negative values on failure.
 */
static int CertFileToBuffer(const char* file, char* buf, word32 bufSz)
{
    int ret;
    WFILE* f;
    char* line;
    int lineSz;

    if (file == NULL || buf == NULL || bufSz == 0) {
        ret = WS_BAD_ARGUMENT;
    }
    else {
        if (WFOPEN(&f, file, "rb") != 0) {
            ret = WS_BAD_FILE_E;
        }
        else {
            line = WFGETS(buf, bufSz, f);
            if (line == NULL) {
                ret = WS_FATAL_ERROR;
            }
            else {
                lineSz = (int)WSTRLEN(line);

                /* remove leading spaces */
                while (lineSz > 0 && line[0] == ' ') {
                    --lineSz;;
                    ++line;
                }

                ret = lineSz;
            }
        }
    }

    return ret;
}

static int ParseOsshCertFromFile(const char* file, int side)
{
    int ret = WS_SUCCESS;
    enum {
        MAX_CERT_BUF_SZ = 2048
    };
    char fileBuf[MAX_CERT_BUF_SZ];
    int fileBufSz;
    byte* certBuf = NULL;
    word32 certBufSz = 0;
    const byte* certType;
    word32 certTypeSz;
    WOLFSSH_OSSH_CERT* cert = NULL;

    fileBufSz = CertFileToBuffer(file, fileBuf, sizeof(fileBuf));
    if (fileBufSz < 0) {
        fprintf(stderr, "Failed to read %s into buffer.\n", file);
        ret = WS_FATAL_ERROR;
    }
    if (ret == WS_SUCCESS) {
        ret = wolfSSH_ReadKey_buffer((byte*)fileBuf, fileBufSz,
                  WOLFSSH_FORMAT_SSH, &certBuf, &certBufSz, &certType,
                  &certTypeSz, NULL);
        if (ret != WS_SUCCESS) {
            fprintf(stderr, "wolfSSH_ReadKey_buffer for file %s failed.\n",
                file);
        }
    }
    if (ret == WS_SUCCESS) {
        ret = ParseOsshCert(certBuf, certBufSz, &cert, side, NULL);
        if (ret != WS_SUCCESS) {
            fprintf(stderr, "ParseOsshCert for %s failed.\n", file);
        }
    }
    if (cert != NULL) {
        OsshCertFree(cert);
    }
    if (certBuf != NULL) {
        WFREE(certBuf, NULL, DYNTYPE_PUBKEY);
    }

    return ret;
}

static int test_ParseOsshCert(void)
{
    int ret;
    static const char* validHostRsaCert =
        "keys/ossh/ossh-host-rsa-key-cert.pub";
    static const char* validUserRsaCert =
        "keys/ossh/ossh-user-rsa-key-cert.pub";

    fprintf(stderr, "Testing ParseOsshCert w/ valid host RSA cert.\n");
    ret = ParseOsshCertFromFile(validHostRsaCert, WOLFSSH_ENDPOINT_SERVER);

    if (ret == WS_SUCCESS) {
        fprintf(stderr, "Testing ParseOsshCert w/ valid user RSA cert.\n");
        ret = ParseOsshCertFromFile(validUserRsaCert, WOLFSSH_ENDPOINT_CLIENT);
    }

    if (ret == WS_SUCCESS) {
        fprintf(stderr, "Testing ParseOsshCert w/ valid host RSA cert but "
            "wrong side.\n");
        ret = ParseOsshCertFromFile(validHostRsaCert, WOLFSSH_ENDPOINT_CLIENT);
        if (ret == WS_SUCCESS) {
            ret = WS_FATAL_ERROR;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    if (ret == WS_SUCCESS) {
        fprintf(stderr, "Testing ParseOsshCert w/ valid user RSA cert but "
            "wrong side.\n");
        ret = ParseOsshCertFromFile(validUserRsaCert, WOLFSSH_ENDPOINT_SERVER);
        if (ret == WS_SUCCESS) {
            ret = WS_FATAL_ERROR;
        }
        else {
            ret = WS_SUCCESS;
        }
    }

    return ret;
}

typedef int (*TEST_FUNC)(void);
typedef struct {
    const char *name;
    TEST_FUNC func;
} TEST_CASE;

#define TEST_DECL(func) { #func, func }

const TEST_CASE testCases[] = {
    TEST_DECL(test_ParseOsshCert)
};

#define TEST_CASE_CNT (int)(sizeof(testCases) / sizeof(*testCases))

static void TestSetup(const TEST_CASE* tc)
{
    fprintf(stderr, "Running %s.\n", tc->name);
}

static void TestCleanup(void)
{
}

static int RunTest(const TEST_CASE* tc)
{
    int ret;

    TestSetup(tc);

    ret = tc->func();
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "%s FAILED.\n", tc->name);
    }
    else {
        fprintf(stderr, "%s PASSED.\n", tc->name);
    }

    TestCleanup();

    return ret;
}

int main(int argc, char** argv)
{
    int i;
    int ret = WS_SUCCESS;

    (void)argc;
    (void)argv;

    for (i = 0; i < TEST_CASE_CNT; ++i) {
        ret = RunTest(&testCases[i]);
        if (ret != WS_SUCCESS) {
            break;
        }
    }

    return ret;
}
