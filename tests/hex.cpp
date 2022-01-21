#include "hex.h"

#include <string>
#include <stdexcept>

unsigned char DSTUEngine::fromHex(char a)
{
    if (a >= '0' && a <= '9')
        return a - '0';
    if (a >= 'a' && a <= 'f')
        return a - 'a' + 10;
    if (a >= 'A' && a <= 'F')
        return a - 'A' + 10;
    throw std::runtime_error("fromHex: invalid hex char: '" + std::string(1, a) + "'");
}

unsigned char DSTUEngine::fromHex(char a, char b)
{
    return fromHex(a) * 16 + fromHex(b);
}
