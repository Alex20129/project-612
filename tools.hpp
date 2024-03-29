#ifndef TOOLS_HPP
#define TOOLS_HPP

#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "jansson.h"
#include "sqlite3.h"

using namespace std;

#if defined(__WIN64__)
    #include <windows.h>
    #include <Wincrypt.h>
    #include <tchar.h>
#elif defined(__linux__)
struct DATA_BLOB
{
    unsigned char *pbData;
    u_int64_t cbData;
    DATA_BLOB()
    {
        pbData=nullptr;
    };
};
#endif

#define COOKIE_PREFIX_LENGTH  3
#define AES_GCM_IV_LENGTH     12
#define AES_GCM_TAG_LENGTH    16

static const string b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64_decode(const string &in);
string cp_datablob_to_string(DATA_BLOB inData);
DATA_BLOB DecryptWithKey(DATA_BLOB *crData, unsigned char *key);
DATA_BLOB DPAPIDecrypt(DATA_BLOB *crData);
string EasyDecrypt(DATA_BLOB *crData, unsigned char *key);
DATA_BLOB aes_gcm_encrypt(unsigned char *gcm_key, unsigned char *gcm_iv, unsigned char *gcm_pt);
DATA_BLOB aes_gcm_decrypt(unsigned char *gcm_key, unsigned char *gcm_iv, unsigned char *gcm_ct, unsigned int gcm_ct_len, unsigned char *gcm_tag);

#endif //TOOLS_HPP
