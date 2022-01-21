#pragma once

#include <string>
#include <vector>

namespace DSTUEngine
{

std::vector<unsigned char> makeBlock(const std::string& hex);
void checkBlock(const void* data, size_t size, const std::string& hexEtalon);
void printBlock(const void* data, size_t size);

}
