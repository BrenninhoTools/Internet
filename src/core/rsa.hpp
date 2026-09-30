#pragma once

#include <cstddef>
#include <string>

namespace internet {

bool rsaVerifySha256(const std::string& modulus, const std::string& exponent, const std::string& signature, const std::string& message,
                     std::size_t minimumBits);
std::string rsaSignSha256(const std::string& modulus, const std::string& privateExponent, const std::string& message);

}
