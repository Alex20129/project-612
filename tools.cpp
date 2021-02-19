#include "tools.hpp"

#if defined(__WIN64__)

string base64_decode(const string &in)
{
    string out;
    vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[b[i]] = i;

    int val=0, valb=-8;
    for(u_char c : in)
    {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0)
        {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

DATA_BLOB DecryptWithKey(unsigned char *crData, unsigned int crDataLen, unsigned char *key)
{
    DATA_BLOB result;
    unsigned int bBufferLength=crDataLen-15, bTagLength=16;
    unsigned char bBuffer[bBufferLength], bIV[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    if(crDataLen>15)
    {
        memcpy(bIV, &crData[3], 12);
        memcpy(bBuffer, &crData[15], bBufferLength);

        unsigned char bTag[bTagLength];
        memcpy(bTag, &bBuffer[bBufferLength-bTagLength], bTagLength);

        unsigned char bData[bBufferLength-bTagLength];
        memcpy(bData, bBuffer, bBufferLength-bTagLength);

        result = aes_gcm_decrypt(key, bIV, bData, bTag);
    }
    return result;
}

DATA_BLOB DPAPIDecrypt(unsigned char *crData, unsigned int crDataLen)
{
    DATA_BLOB encryptedData, decryptedData;

    encryptedData.pbData=crData;
    encryptedData.cbData=crDataLen;

    CryptUnprotectData(&encryptedData, NULL, NULL, NULL, NULL, 0, &decryptedData);
    return decryptedData;
}

string EasyDecrypt(string password, unsigned char *masterKey)
{
    string result;
    if(password.find("v10")==0 || password.find("v11")==0)
    {
        result=*DecryptWithKey((unsigned char *)password.data(), password.length(), masterKey).pbData;
    }
    else
    {
        result=*DPAPIDecrypt((unsigned char *)password.data(), password.length()).pbData;
    }
    return result;
}

/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */

static const unsigned char gcm_key[] =
{
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] =
{
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_pt[] =
{
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gcm_aad[] =
{
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_ct[] =
{
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char gcm_tag[] =
{
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

DATA_BLOB aes_gcm_encrypt()
{
    DATA_BLOB result;
    EVP_CIPHER_CTX *ctx;
    int outlen;
    unsigned char outbuf[1024];
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
    result.pbData=outbuf;
    result.cbData=outlen;
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

DATA_BLOB aes_gcm_decrypt(unsigned char *gcm_key, unsigned char *gcm_iv, unsigned char *gcm_ct, unsigned char *gcm_tag)
{
    DATA_BLOB result;
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    unsigned char outbuf[1024];
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
    result.pbData=outbuf;
    result.cbData=outlen;
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag), (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    //cout<<"Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!";
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

#elif defined(__linux__)

stringstream get_chrome_pass(sqlite3* db)
{
    return stringstream(string(""));
}

#endif
