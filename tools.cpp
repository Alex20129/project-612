#include "tools.hpp"

string base64_decode(const string &in)
{
    string out;
    vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[b[i]] = i;

    int val=0, valb=-8;
    for(u_char c : in)
    {
        if(T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if(valb>=0)
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
    for(i=0; i<inData.cbData; i++)
    {
        result.append(1, inData.pbData[i]);
    }
    return result;
}

DATA_BLOB DecryptWithKey(DATA_BLOB *crData, unsigned char *key)
{
    DATA_BLOB result;
    result.pbData=nullptr;
    unsigned int bDataLen=crData->cbData-COOKIE_PREFIX_LENGTH-AES_GCM_IV_LENGTH-AES_GCM_TAG_LENGTH;
    if(crData->cbData>31)
    {
        unsigned char bIV[AES_GCM_IV_LENGTH];
        unsigned char bTag[AES_GCM_TAG_LENGTH];
        unsigned char bData[bDataLen];
        memcpy(bIV, &crData->pbData[COOKIE_PREFIX_LENGTH], AES_GCM_IV_LENGTH);
        memcpy(bTag, &crData->pbData[crData->cbData-AES_GCM_TAG_LENGTH], AES_GCM_TAG_LENGTH);
        memcpy(bData, &crData->pbData[COOKIE_PREFIX_LENGTH+AES_GCM_IV_LENGTH], bDataLen);
        result = aes_gcm_decrypt(key, bIV, bData, bDataLen, bTag);
    }
    return result;
}

DATA_BLOB DPAPIDecrypt(DATA_BLOB *crData)
{
    DATA_BLOB result;
    result.pbData=nullptr;
    CryptUnprotectData(crData, NULL, NULL, NULL, NULL, 0, &result);
    return result;
}

#include <iostream>

string EasyDecrypt(DATA_BLOB *crData, unsigned char *key)
{
    string result("");
    DATA_BLOB blobResult;
    if(memcmp(crData->pbData, "v10", 3)==0 ||
       memcmp(crData->pbData, "v11", 3)==0)
    {
        cout<<"[v10]cookie!"<<endl;
        blobResult=DecryptWithKey(crData, key);
    }
    else
    {
        cout<<"[old]cookie!"<<endl;
        blobResult=DPAPIDecrypt(crData);
    }
    if(blobResult.pbData!=nullptr)
    {
        result=cp_datablob_to_string(blobResult);
        delete [] blobResult.pbData;
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
 * Simple AES GCM test program
 */

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
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
    result.cbData=outlen;
    result.pbData=new unsigned char[outlen];
    memcpy(result.pbData, outbuf, outlen);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

DATA_BLOB aes_gcm_decrypt(unsigned char *gcm_key, unsigned char *gcm_iv, unsigned char *gcm_ct, unsigned int gcm_ct_len, unsigned char *gcm_tag)
{
    int outlen;
    unsigned char outbuf[1024];
    DATA_BLOB result;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher, key and IV */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, gcm_key, gcm_iv);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AES_GCM_IV_LENGTH, NULL);
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, gcm_ct_len);
    result.cbData=outlen;
    result.pbData=new unsigned char[outlen];
    memcpy(result.pbData, outbuf, outlen);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AES_GCM_TAG_LENGTH, (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
