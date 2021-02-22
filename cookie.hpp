#ifndef COOKIE_HPP
#define COOKIE_HPP

#include <string>

using namespace std;

class Cookie
{
public:
    string Host;
    string Name;
    string Value;
    string Path;
    time_t CreDate;
    time_t ExpDate;
private:
};

#endif //COOKIE_HPP
