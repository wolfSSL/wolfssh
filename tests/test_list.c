#include <wolfssh/list.h>
#include <wolfssh/error.h>
#include <wolfssh/ssh.h>
#include <wolfssh/ossh_certs.h>

#ifdef WOLFSSH_OSSH_CERTS

static int test_ListNew(void)
{
    int ret = WS_SUCCESS;
    WOLFSSH_LIST* list;
    typedef struct {
        byte type;
        const char* name;
    } LIST_TYPE_VECTOR;
    LIST_TYPE_VECTOR validTypes[] = {
        {LIST_OSSH_CA_KEY,    "LIST_OSSH_CA_KEY"},
        {LIST_OSSH_PRINCIPAL, "LIST_OSSH_PRINCIPAL"}
    };
    word32 i;

    for (i = 0; i < sizeof(validTypes)/sizeof(*validTypes); ++i) {
        fprintf(stderr, "Testing ListNew with valid type %s.\n", validTypes[i].name);
        list = ListNew(validTypes[i].type, NULL);
        if (list == NULL) {
            fprintf(stderr, "ListNew with type %s failed.\n",
                validTypes[i].name);
            ret = WS_FATAL_ERROR;
            break;
        }

        ListFree(list);
    }

    fprintf(stderr, "Testing ListNew with invalid type.\n");
    list = ListNew(-1, NULL);
    if (list != NULL) {
        fprintf(stderr, "ListNew with invalid type unexpectedly succeeded.\n");
        ListFree(list);
        ret = WS_FATAL_ERROR;
    }

    return ret;
}

static int test_ListOps(void)
{
    int ret = WS_SUCCESS;
    enum {
        NUM_LISTS = 2,
        NUM_NODES = 3,
        BUF_SZ = 4
    };
    WOLFSSH_LIST* lists[NUM_LISTS] = {NULL, NULL};
    byte listTypes[NUM_LISTS] = {
        LIST_OSSH_CA_KEY,
        LIST_OSSH_PRINCIPAL
    };
    word32 i;
    word32 j;
    const byte keyBufs[NUM_NODES][BUF_SZ] = {
        {0xDE, 0xAD, 0xBE, 0xEF},
        {0x01, 0x02, 0x03, 0x04},
        {0x11, 0x22, 0x33, 0x44}
    };
    WOLFSSH_OSSH_CA_KEY* keys[NUM_NODES];
    byte* keyFingerprints[NUM_NODES];
    const byte principalBufs[NUM_NODES][BUF_SZ] = {
        {0x11, 0x10, 0x01, 0x00},
        {0xFF, 0xEE, 0xDD, 0xCC},
        {0x12, 0x34, 0x56, 0x78}
    };
    WOLFSSH_OSSH_PRINCIPAL* principals[NUM_NODES];
    const byte* findElement;
    word32 findSz;
    const byte invalidElement[BUF_SZ] = {0};

    for (i = 0; i < NUM_LISTS; ++i) {
        lists[i] = ListNew(listTypes[i], NULL);
        if (lists[i] == NULL) {
            fprintf(stderr, "ListNew failed.\n");
            ret = WS_FATAL_ERROR;
        }

        for (j = 0; ret == WS_SUCCESS && j < NUM_NODES; ++j) {
            if (listTypes[i] == LIST_OSSH_CA_KEY) {
                keys[j] = OsshCaKeyNew(NULL);
                if (keys[j] != NULL) {
                    if (OsshCaKeyInit(keys[j], keyBufs[j], BUF_SZ)
                        == WS_SUCCESS) {
                        if (ListAdd(lists[i], keys[j]) != WS_SUCCESS) {
                            fprintf(stderr, "ListAdd failed.\n");
                            ret = WS_FATAL_ERROR;
                            break;
                        }
                        else {
                            keyFingerprints[j] = keys[j]->fingerprint;
                        }
                    }
                    else {
                        fprintf(stderr, "OsshCaKeyInit failed.\n");
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                }
                else {
                    fprintf(stderr, "OsshCaKeyNew failed.\n");
                    ret = WS_FATAL_ERROR;
                    break;
                }
            }
            else {
                principals[j] = OsshPrincipalNew(NULL);
                if (principals[j] != NULL) {
                    WMEMCPY(principals[j]->name, principalBufs[j], BUF_SZ);
                    principals[j]->nameSz = BUF_SZ;

                    if (ListAdd(lists[i], principals[j]) != WS_SUCCESS) {
                        fprintf(stderr, "ListAdd failed.\n");
                        ret = WS_FATAL_ERROR;
                        break;
                    }
                }
                else {
                    fprintf(stderr, "OsshPrincipalNew failed.\n");
                    ret = WS_FATAL_ERROR;
                    break;
                }
            }
        }
    }

    for (i = 0; ret == WS_SUCCESS && i < NUM_LISTS; ++i) {
        for (j = 0; ret == WS_SUCCESS && j < NUM_NODES; ++j) {
            if (listTypes[i] == LIST_OSSH_CA_KEY) {
                findElement = keyFingerprints[j];
                findSz = WC_SHA256_DIGEST_SIZE;
            }
            else {
                findElement = principalBufs[j];
                findSz = BUF_SZ;
            }

            if (!ListFind(lists[i], findElement, findSz)) {
                fprintf(stderr, "Failed to find element %u in list %u.\n",
                    j, i);
                ret = WS_FATAL_ERROR;
                break;
            }
        }

        if (ListFind(lists[i], invalidElement, sizeof(invalidElement))) {
            fprintf(stderr, "Unexpectedly found element that wasn't added to "
                "list.\n");
            ret = WS_FATAL_ERROR;
        }
    }

    for (i = 0; i < NUM_LISTS; ++i) {
        ListFree(lists[i]);
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
    TEST_DECL(test_ListNew),
    TEST_DECL(test_ListOps)
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

#endif /* WOLFSSH_OSSH_CERTS */
