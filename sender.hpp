#ifndef SENDER_HPP
#define SENDER_HPP

#include <string>
#include "tgbot/tgbot.h"

using namespace std;
using namespace TgBot;

class Sender : public Bot
{
public:
    explicit Sender(string token);
    void send(int64_t chatId, const string &text);

private:
};

#endif //SENDER_HPP
