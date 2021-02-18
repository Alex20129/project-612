#include "sender.hpp"

Sender::Sender(string token) : Bot(token)
{
}

void Sender::send(int64_t chatId, const string &text)
{
    this->getApi().sendMessage(chatId, text);
}
