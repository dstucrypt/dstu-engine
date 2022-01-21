#include "error.h"

#include <openssl/err.h>

#include <array>

std::string DSTUEngine::OPENSSLError() noexcept
{
    std::array<char, 256> buf{};
    ERR_error_string_n(ERR_get_error(), buf.data(), buf.size());
    return buf.data();
}
