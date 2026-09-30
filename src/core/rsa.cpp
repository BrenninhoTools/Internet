#include "rsa.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

#include "sha256.hpp"

namespace internet {

namespace {

using Big = std::vector<std::uint32_t>;

void trim(Big& value) {
    while (!value.empty() && value.back() == 0) value.pop_back();
}

Big fromBytes(const std::string& bytes) {
    Big value((bytes.size() + 3) / 4, 0);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        std::size_t place = bytes.size() - 1 - i;
        value[place / 4] |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[i])) << (8 * (place % 4));
    }
    trim(value);
    return value;
}

std::size_t bitLength(const Big& value) {
    if (value.empty()) return 0;
    std::uint32_t top = value.back();
    std::size_t bits = 0;
    while (top != 0) {
        ++bits;
        top >>= 1;
    }
    return (value.size() - 1) * 32 + bits;
}

bool bitAt(const Big& value, std::size_t index) {
    std::size_t limb = index / 32;
    return limb < value.size() && ((value[limb] >> (index % 32)) & 1u) != 0;
}

int compare(const Big& a, const Big& b) {
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    for (std::size_t i = a.size(); i-- > 0;) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

void subtract(Big& a, const Big& b) {
    std::int64_t borrow = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        std::int64_t difference = static_cast<std::int64_t>(a[i]) - borrow - (i < b.size() ? static_cast<std::int64_t>(b[i]) : 0);
        borrow = difference < 0 ? 1 : 0;
        if (difference < 0) difference += static_cast<std::int64_t>(1) << 32;
        a[i] = static_cast<std::uint32_t>(difference);
    }
    trim(a);
}

Big multiply(const Big& a, const Big& b) {
    if (a.empty() || b.empty()) return Big();
    Big product(a.size() + b.size(), 0);
    for (std::size_t i = 0; i < a.size(); ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < b.size(); ++j) {
            std::uint64_t current = static_cast<std::uint64_t>(a[i]) * b[j] + product[i + j] + carry;
            product[i + j] = static_cast<std::uint32_t>(current);
            carry = current >> 32;
        }
        std::size_t position = i + b.size();
        while (carry != 0) {
            std::uint64_t current = static_cast<std::uint64_t>(product[position]) + carry;
            product[position] = static_cast<std::uint32_t>(current);
            carry = current >> 32;
            ++position;
        }
    }
    trim(product);
    return product;
}

Big reduce(const Big& value, const Big& modulus) {
    Big remainder;
    std::size_t bits = bitLength(value);
    for (std::size_t i = bits; i-- > 0;) {
        std::uint32_t carry = bitAt(value, i) ? 1u : 0u;
        for (std::size_t limb = 0; limb < remainder.size(); ++limb) {
            std::uint32_t next = remainder[limb] >> 31;
            remainder[limb] = (remainder[limb] << 1) | carry;
            carry = next;
        }
        if (carry != 0) remainder.push_back(carry);
        if (compare(remainder, modulus) >= 0) subtract(remainder, modulus);
    }
    return remainder;
}

Big powerMod(const Big& base, const Big& exponent, const Big& modulus) {
    Big result{1};
    Big reduced = reduce(base, modulus);
    for (std::size_t i = bitLength(exponent); i-- > 0;) {
        result = reduce(multiply(result, result), modulus);
        if (bitAt(exponent, i)) result = reduce(multiply(result, reduced), modulus);
    }
    return result;
}

std::string toBytes(const Big& value, std::size_t length) {
    std::string bytes(length, '\0');
    for (std::size_t i = 0; i < length; ++i) {
        std::size_t limb = i / 4;
        if (limb >= value.size()) break;
        bytes[length - 1 - i] = static_cast<char>((value[limb] >> (8 * (i % 4))) & 0xFF);
    }
    return bytes;
}

std::string encodedMessage(const std::string& message, std::size_t length) {
    static const unsigned char prefix[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    std::string raw;
    fromHex(sha256Hex(message), raw);
    std::string info(reinterpret_cast<const char*>(prefix), sizeof prefix);
    info += raw;
    if (length < info.size() + 11) return std::string();
    std::string encoded;
    encoded += '\x00';
    encoded += '\x01';
    encoded.append(length - info.size() - 3, '\xFF');
    encoded += '\x00';
    encoded += info;
    return encoded;
}

}

bool rsaVerifySha256(const std::string& modulusBytes, const std::string& exponentBytes, const std::string& signature, const std::string& message,
                     std::size_t minimumBits) {
    Big modulus = fromBytes(modulusBytes);
    Big exponent = fromBytes(exponentBytes);
    if (modulus.empty()) return false;
    std::size_t bits = bitLength(modulus);
    if (bits < minimumBits || bits > 8192 || (modulus[0] & 1u) == 0) return false;
    if (exponent.empty() || bitLength(exponent) > 32 || (exponent[0] & 1u) == 0 || compare(exponent, Big{3}) < 0) return false;
    std::size_t length = (bits + 7) / 8;
    if (signature.size() != length) return false;
    Big value = fromBytes(signature);
    if (compare(value, modulus) >= 0) return false;
    std::string expected = encodedMessage(message, length);
    if (expected.empty()) return false;
    std::string actual = toBytes(powerMod(value, exponent, modulus), length);
    return constantTimeEquals(actual, expected);
}

std::string rsaSignSha256(const std::string& modulusBytes, const std::string& privateExponentBytes, const std::string& message) {
    Big modulus = fromBytes(modulusBytes);
    Big exponent = fromBytes(privateExponentBytes);
    std::size_t length = (bitLength(modulus) + 7) / 8;
    std::string encoded = encodedMessage(message, length);
    if (encoded.empty()) return std::string();
    return toBytes(powerMod(fromBytes(encoded), exponent, modulus), length);
}

}
