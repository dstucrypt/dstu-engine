#include "block.h"

#include "hex.h"

#include <iostream>
#include <iomanip>
#include <stdexcept>

#include <cstdint>

std::vector<unsigned char> DSTUEngine::makeBlock(const std::string& hex)
{
    std::vector<unsigned char> res;
    for (size_t i = 0; i < hex.size();)
    {
        if (hex[i] == ' ')
        {
            ++i;
            continue;
        }
        res.push_back(fromHex(hex[i], hex[i + 1]));
        i += 2;
    }
    return res;
}

void DSTUEngine::checkBlock(const void* data, size_t size, const std::string& hexEtalon)
{
    size_t pos = 0;
    const auto* ptr = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < hexEtalon.size();)
    {
        if (i == hexEtalon.size() - 1)
            throw std::runtime_error("checkBlock: bad etalon, odd data at position #" + std::to_string(i));
        if (hexEtalon[i] == ' ')
        {
            ++i;
            continue;
        }
        if (pos >= size)
            throw std::runtime_error("checkBlock: etalon is bigger than the data. Data size: " + std::to_string(size));
        if (ptr[pos] != fromHex(hexEtalon[i], hexEtalon[i + 1]))
            throw std::runtime_error("checkBlock: bad data at position #" + std::to_string(pos));
        ++pos;
        i += 2;
    }
}

void DSTUEngine::printBlock(const void* data, size_t size)
{
    const auto* ptr = static_cast<const uint8_t*>(data);
    bool first = true;
    for (size_t i = 0; i < size; ++i)
    {
        if (first)
            first = false;
        else
            std::cout << " ";
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (unsigned)ptr[i];
    }
    std::cout << std::dec << "\n";
}
