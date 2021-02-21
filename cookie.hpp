#ifndef COOKIE_HPP
#define COOKIE_HPP

#include <string>

using namespace std;

class Cookie
{
public:
    Cookie();
    ~Cookie();
    string *ExpDate;
    string *Value;
    string *Host;
private:
};

#endif //COOKIE_HPP
