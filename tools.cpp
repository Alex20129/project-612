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

string cp_datablob_to_string(DATA_BLOB inData)
{
    string result("");
    unsigned long int i;
    char ch[2];
    ch[1]=0;
    for(i=0; inData.cbData>i; i++)
    {
        ch[0]=inData.pbData[i];
        result.append(ch);
    }
    return result;
}

DATA_BLOB DecryptWithKey(DATA_BLOB *crData, unsigned char *key)
{
    DATA_BLOB result;
    unsigned int bBufferLen=crData->cbData-15, bTagLength=16, IVLen=12;
    if(crData->cbData>32)
    {
        unsigned char bBuffer[bBufferLen];
        unsigned char bIV[IVLen];
        unsigned char bTag[bTagLength];
        unsigned char bData[bBufferLen-bTagLength];
        memcpy(bIV, &crData->pbData[3], IVLen);
        memcpy(bBuffer, &crData->pbData[15], bBufferLen);
        memcpy(bTag, &bBuffer[bBufferLen-bTagLength], bTagLength);
        memcpy(bData, bBuffer, bBufferLen-bTagLength);
        result = aes_gcm_decrypt(key, bIV, bData, bTag);
    }
    return result;
}

DATA_BLOB DPAPIDecrypt(DATA_BLOB *crData)
{
    DATA_BLOB decryptedData;
    CryptUnprotectData(crData, NULL, NULL, NULL, NULL, 0, &decryptedData);
    return decryptedData;
}

string EasyDecrypt(DATA_BLOB *crData, unsigned char *key)
{
    string result;
    DATA_BLOB blobResult;

    if(memcmp(crData->pbData, "v10", 3)==0 ||
       memcmp(crData->pbData, "v11", 3)==0)
    {
        blobResult=DecryptWithKey(crData, key);
    }
    else
    {
        blobResult=DPAPIDecrypt(crData);
    }
    result=cp_datablob_to_string(blobResult);
    delete [] blobResult.pbData;
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

static const unsigned char gcm_aad[] =
{
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_tag[] =
{
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

DATA_BLOB aes_gcm_encrypt(unsigned char *gcm_key, unsigned char *gcm_iv, unsigned char *gcm_pt)
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
    int outlen;
    unsigned char outbuf[1024];
    DATA_BLOB result;
    EVP_CIPHER_CTX *ctx;
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
    result.cbData=outlen;
    result.pbData=new unsigned char[outlen];
    memcpy(result.pbData, outbuf, outlen);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag), (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

#elif defined(__linux__)

stringstream get_chrome_pass(sqlite3* db)
{
    return stringstream(string(""));
}

#endif
