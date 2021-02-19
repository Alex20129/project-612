#ifndef TOOLS_HPP
#define TOOLS_HPP

#include <sstream>
#include <string.h>
#include <iostream>
#include <vector>
#include "jansson.h"
#include "sqlite3.h"

#if defined(__WIN64__)
    #include <windows.h>
    #include <Wincrypt.h>
    #include <tchar.h>
    #include <sys/types.h>
#elif defined(__linux__)
#endif

static const std::string b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
using namespace std;

string base64_decode(const string &in);
DATA_BLOB DecryptWithKey(unsigned char *crData, unsigned int crDataLen, unsigned char *key);
DATA_BLOB DPAPIDecrypt(unsigned char *crData, unsigned int crDataLen);
string EasyDecrypt(string password, unsigned char *masterKey);
void aes_gcm_encrypt();
void aes_gcm_decrypt();

#endif //TOOLS_HPP
