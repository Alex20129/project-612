#include "cookie.hpp"

Cookie::Cookie()
{
    ExpDate=new string;
    Value=new string;
    Host=new string;
}

Cookie::~Cookie()
{
    delete ExpDate;
    delete Value;
    delete Host;
}
