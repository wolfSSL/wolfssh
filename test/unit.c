/* unit.c
 *
 * Copyright (C) 2014-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */


#include <stdio.h>
#include <wolfssh/ssh.h>


static int test_KDF(void);
static int ConvertHexToBin(const char* h1, uint8_t** b1, uint32_t* b1Sz,
                           const char* h2, uint8_t** b2, uint32_t* b2Sz,
                           const char* h3, uint8_t** b3, uint32_t* b3Sz,
                           const char* h4, uint8_t** b4, uint32_t* b4Sz);
static void FreeBins(uint8_t* b1, uint8_t* b2, uint8_t* b3, uint8_t* b4);
static int Base16_Decode(const uint8_t* in, uint32_t inLen,
                         uint8_t* out, uint32_t* outLen);


int main(void)
{
    int testResult = 0, unitResult = 0;

    unitResult = test_KDF();
    printf("KDF: %s\n", (unitResult == 0 ? "SUCCESS" : "FAILED"));
    testResult = testResult || unitResult;

    return (testResult ? 1 : 0);
}


typedef struct {
    uint8_t hashId;
    uint8_t keyId;
    const char* k;
    const char* h;
    const char* sessionId;
    const char* expectedKey;
} KdfTestVector;


/** Test Vector Set #1 **/
const char kdfTvSet1k[] =
    "35618FD3AABF980A5F766408961600D4933C60DD7B22D69EEB4D7A987C938F6F"
    "7BB2E60E0F638BB4289297B588E6109057325F010D021DF60EBF8BE67AD9C3E2"
    "6376A326A16210C7AF07B3FE562B8DD1DCBECB17AA7BFAF38708B0136120B2FC"
    "723E93EF4237AC3737BAE3A16EC03F605C7EEABFD526B38C826B506BBAECD2F7"
    "9932F1371AEABFBEB4F8222313506677330C714A2A6FDC70CB859B581AA18625"
    "ECCB6BA9DDEEAECF0E41D9E5076B899B477112E59DDADC4B4D9C13E9F07E1107"
    "B560FEFDC146B8ED3E73441D05345031C35F9E6911B00319481D80015855BE4D"
    "1C7D7ACC8579B1CC2E5F714109C0882C3B57529ABDA1F2255D2B27C4A83AE11E";
const char kdfTvSet1h[]         = "40555741F6DE70CDC4E740104A97E75473F49064";
const char kdfTvSet1sessionId[] = "40555741F6DE70CDC4E740104A97E75473F49064";
const char kdfTvSet1a[]         = "B2EC4CF6943632C39972EE2801DC7393";
const char kdfTvSet1b[]         = "BC92238B6FA69ECC10B2B013C2FC9785";
const char kdfTvSet1c[]         = "9EF0E2053F66C56F3E4503DA1C2FBD6B";
const char kdfTvSet1d[]         = "47C8395B08277020A0645DA3959FA1A9";
const char kdfTvSet1e[]         = "EE436BFDABF9B0313224EC800E7390445E2F575E";
const char kdfTvSet1f[]         = "FB9FDEEC78B0FB258F1A4F47F6BCE166680994BB";

/** Test Vector Set #2 **/
const char kdfTvSet2k[] =
    "19FA2B7C7F4FE7DE61CDE17468C792CCEAB0E3F2CE37CDE2DAA0974BCDFFEDD4"
    "A29415CDB330FA6A97ECA742359DC1223B581D8AC61B43CFFDF66D20952840B0"
    "2593B48354E352E2A396BDF7F1C9D414FD31C2BF47E6EED306069C4F4F5F66C3"
    "003A90E85412A1FBE89CDFB457CDA0D832E8DA701627366ADEC95B70E8A8B7BF"
    "3F85775CCF36E40631B83B32CF643088F01A82C97C5C3A820EB4149F551CAF8C"
    "C98EE6B3065E6152FF877823F7C618C1CD93CE26DB9FAAFED222F1C93E8F4068"
    "BFDA4480432E14F98FFC821F05647693040B07D71DC273121D53866294434D46"
    "0E95CFA4AB4414705BF1F8224655F907A418A6A893F2A71019225869CB7FE988";
const char kdfTvSet2h[]         = "DFB748905CC8647684C3E0B7F26A3E8E7414AC51";
const char kdfTvSet2sessionId[] = "DFB748905CC8647684C3E0B7F26A3E8E7414AC51";
const char kdfTvSet2a[]         = "52EDBFD5E414A3CC6C7F7A0F4EA60503";
const char kdfTvSet2b[]         = "926C6987696C5FFCC6511BFE34557878";
const char kdfTvSet2c[]         = "CB6D56EC5B9AFECD326D544DA2D22DED";
const char kdfTvSet2d[]         = "F712F6451F1BD6CE9BAA597AC87C5A24";
const char kdfTvSet2e[]         = "E42FC62C76B76B37818F78292D3C2226D0264760";
const char kdfTvSet2f[]         = "D14BE4DD0093A3E759580233C80BB8399CE4C4E7";

static const KdfTestVector kdfTestVectors[] = {
    {0, 'A', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1a},
    {0, 'B', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1b},
    {0, 'C', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1c},
    {0, 'D', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1d},
    {0, 'E', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1e},
    {0, 'F', kdfTvSet1k, kdfTvSet1h, kdfTvSet1sessionId, kdfTvSet1f},
    {0, 'A', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2a},
    {0, 'B', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2b},
    {0, 'C', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2c},
    {0, 'D', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2d},
    {0, 'E', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2e},
    {0, 'F', kdfTvSet2k, kdfTvSet2h, kdfTvSet2sessionId, kdfTvSet2f}
};

int test_KDF(void)
{
    int result = 0;
    uint32_t i;
    uint32_t tc = sizeof(kdfTestVectors)/sizeof(KdfTestVector);
    const KdfTestVector* tv = NULL;
    uint8_t* k = NULL;
    uint8_t* h = NULL;
    uint8_t* sId = NULL;
    uint8_t* eKey = NULL;
    uint32_t kSz, hSz, sIdSz, eKeySz;
    uint8_t cKey[20]; /* Greater of SHA_DIGEST_SIZE and AES_BLOCK_SIZE */
    /* sId - Session ID, eKey - Expected Key, cKey - Calculated Key */

    for (i = 0, tv = kdfTestVectors; i < tc; i++, tv++) {

        result = ConvertHexToBin(tv->k, &k, &kSz,
                                 tv->h, &h, &hSz,
                                 tv->sessionId, &sId, &sIdSz,
                                 tv->expectedKey, &eKey, &eKeySz);
        if (result != 0) {
            printf("KDF: Could not convert test vector %u.\n", i);
            return -100;
        }

        result = wolfSSH_KDF(tv->hashId, tv->keyId, cKey, eKeySz,
                             k, kSz, h, hSz, sId, sIdSz);

        if (result != 0) {
            printf("KDF: Could not derive key.\n");
            result = -101;
        }
        else {
            if (memcmp(cKey, eKey, eKeySz) != 0) {
                printf("KDF: Calculated Key does not match Expected Key.\n");
                result = -102;
            }
        }
        
        FreeBins(k, h, sId, eKey);

        if (result != 0) break;
    }

    return result;
}


/* convert hex string to binary, store size, 0 success (free mem on failure) */
int ConvertHexToBin(const char* h1, uint8_t** b1, uint32_t* b1Sz,
                    const char* h2, uint8_t** b2, uint32_t* b2Sz,
                    const char* h3, uint8_t** b3, uint32_t* b3Sz,
                    const char* h4, uint8_t** b4, uint32_t* b4Sz)
{
    int ret;

    /* b1 */
    if (h1 && b1 && b1Sz) {
        *b1Sz = (uint32_t)strlen(h1) / 2;
        *b1   = (uint8_t*)malloc(*b1Sz);
        if (*b1 == NULL)
            return -1;
        ret = Base16_Decode((const uint8_t*)h1, (uint32_t)strlen(h1),
                            *b1, b1Sz);
        if (ret != 0) {
            FreeBins(*b1, NULL, NULL, NULL);
            return -1;
        }
    }

    /* b2 */
    if (h2 && b2 && b2Sz) {
        *b2Sz = (uint32_t)strlen(h2) / 2;
        *b2   = (uint8_t*)malloc(*b2Sz);
        if (*b2 == NULL) {
            FreeBins(b1 ? *b1 : NULL, NULL, NULL, NULL);
            return -1;
        }
        ret = Base16_Decode((const uint8_t*)h2, (uint32_t)strlen(h2),
                            *b2, b2Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, *b2, NULL, NULL);
            return -1;
        }
    }

    /* b3 */
    if (h3 && b3 && b3Sz) {
        *b3Sz = (uint32_t)strlen(h3) / 2;
        *b3   = (uint8_t*)malloc(*b3Sz);
        if (*b3 == NULL) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, NULL, NULL);
            return -1;
        }
        ret = Base16_Decode((const uint8_t*)h3, (uint32_t)strlen(h3),
                            *b3, b3Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, *b3, NULL);
            return -1;
        }
    }

    /* b4 */
    if (h4 && b4 && b4Sz) {
        *b4Sz = (uint32_t)strlen(h4) / 2;
        *b4   = (uint8_t*)malloc(*b4Sz);
        if (*b4 == NULL) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, b3 ? *b3 : NULL, NULL);
            return -1;
        }
        ret = Base16_Decode((const uint8_t*)h4, (uint32_t)strlen(h4),
                            *b4, b4Sz);
        if (ret != 0) {
            FreeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, b3 ? *b3 : NULL, *b4);
            return -1;
        }
    }

    return 0;
}


void FreeBins(uint8_t* b1, uint8_t* b2, uint8_t* b3, uint8_t* b4)
{
    if (b1 != NULL) free(b1);
    if (b2 != NULL) free(b2);
    if (b3 != NULL) free(b3);
    if (b4 != NULL) free(b4);
}


#define BAD 0xFF

const uint8_t hexDecode[] =
{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    10, 11, 12, 13, 14, 15,  /* upper case A-F */
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, BAD,  /* G - ` */
    10, 11, 12, 13, 14, 15   /* lower case a-f */
};  /* A starts at 0x41 not 0x3A */


static int Base16_Decode(const uint8_t* in, uint32_t inLen,
                         uint8_t* out, uint32_t* outLen)
{
    uint32_t inIdx  = 0;
    uint32_t outIdx = 0;

    if (inLen == 1 && *outLen && in) {
        uint8_t b = in[inIdx++] - 0x30;  /* 0 starts at 0x30 */

        /* sanity check */
        if (b >=  sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;

        b  = hexDecode[b];

        if (b == BAD)
            return -1;
        
        out[outIdx++] = b;

        *outLen = outIdx;
        return 0;
    }

    if (inLen % 2)
        return -1;

    if (*outLen < (inLen / 2))
        return -1;

    while (inLen) {
        uint8_t b  = in[inIdx++] - 0x30;  /* 0 starts at 0x30 */
        uint8_t b2 = in[inIdx++] - 0x30;

        /* sanity checks */
        if (b >=  sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;
        if (b2 >= sizeof(hexDecode)/sizeof(hexDecode[0]))
            return -1;

        b  = hexDecode[b];
        b2 = hexDecode[b2];

        if (b == BAD || b2 == BAD)
            return -1;
        
        out[outIdx++] = (uint8_t)((b << 4) | b2);
        inLen -= 2;
    }

    *outLen = outIdx;
    return 0;
}


