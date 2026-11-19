#include <gtest/gtest.h>

#include "core.hpp"
#include "common.hpp"

#include <array>
#include <string>
#include <span>
#include <stdexcept>

namespace
{

constexpr std::uint8_t hex_char_to_int(char c) 
{
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("Invalid hex character");
}

template <std::size_t N>
auto hex_to_bytes(std::string_view hex) 
    -> std::array<std::byte, N> 
{
    if (hex.size() != N * 2) 
    {
        throw std::invalid_argument("Invalid hex string length");
    }

    std::array<std::byte, N> bytes{};
    
    for (std::size_t i = 0; i < N; ++i) 
    {
        std::uint8_t high = hex_char_to_int(hex[i * 2]);
        std::uint8_t low  = hex_char_to_int(hex[i * 2 + 1]);
        
        bytes[i] = static_cast<std::byte>((high << 4) | low);
    }
    
    return bytes;
}

template <std::size_t N>
auto bytes_to_hex(
    const std::array<std::byte, N>& bytes
)
    -> std::string
{
    std::string hex;
    std::string_view digits { "0123456789abcdef" };
    for (auto b : bytes)
    {
        hex += digits[static_cast<std::uint8_t>((b >> 4) & std::byte{ 0xF })];
        hex += digits[static_cast<std::uint8_t>(b & std::byte{ 0xF })];
    }
    return hex;
}

} // namespace

namespace rndl::tests
{

TEST(SboxTest, Sbox)
{
    rndl::aes::Aes<> aes;
    EXPECT_EQ(cnst::sbox, aes.get_sbox());
}

TEST(SboxTest, InvSbox)
{
    rndl::aes::Aes<> aes;
    EXPECT_EQ(cnst::inv_sbox, aes.get_inv_sbox());
}

TEST(AesTest, Aes128_EncryptDecrypt_NIST_Vector)
{
    auto key { hex_to_bytes<16>("000102030405060708090a0b0c0d0e0f") };
    auto plaintext { hex_to_bytes<16>("00112233445566778899aabbccddeeff") };
    auto expected_ciphertext { hex_to_bytes<16>("69c4e0d86a7b0430d8cdb78070b4c55a") };

    rndl::aes::Aes<128, 128> aes;
    aes.set_key(key);

    auto state = plaintext;
    aes.encrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(expected_ciphertext)) 
        << "AES-128 Encryption failed";

    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "AES-128 Decryption failed";
}

TEST(AesTest, Aes192_EncryptDecrypt_NIST_Vector)
{
    auto key { hex_to_bytes<24>("000102030405060708090a0b0c0d0e0f1011121314151617") };
    auto plaintext { hex_to_bytes<16>("00112233445566778899aabbccddeeff") };
    auto expected_ciphertext { hex_to_bytes<16>("dda97ca4864cdfe06eaf70a0ec0d7191") };

    rndl::aes::Aes<192, 128> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(expected_ciphertext)) 
        << "AES-192 Encryption failed";
    
    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "AES-192 Decryption failed";
}

TEST(AesTest, Aes256_EncryptDecrypt_NIST_Vector)
{
    auto key { hex_to_bytes<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") };
    auto plaintext { hex_to_bytes<16>("00112233445566778899aabbccddeeff") };
    auto expected_ciphertext { hex_to_bytes<16>("8ea2b7ca516745bfeafc49904b496089") };

    rndl::aes::Aes<256, 128> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(expected_ciphertext)) 
        << "AES-256 Encryption failed";
    
    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "AES-256 Decryption failed";
}

TEST(RijndaelTest, Block192_Key128_Roundtrip)
{
    auto key { hex_to_bytes<16>("000102030405060708090a0b0c0d0e0f") };
    auto plaintext { hex_to_bytes<24>("00112233445566778899aabbccddeeff0011223344556677") };

    rndl::aes::Aes<128, 192> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    EXPECT_NE(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "Ciphertext should differ from plaintext";

    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "Rijndael (Block 192, Key 128) Roundtrip failed";
}

TEST(RijndaelTest, Block192_Key192_Roundtrip) {
    auto key { hex_to_bytes<24>("000102030405060708090a0b0c0d0e0f1011121314151617") };
    auto plaintext { hex_to_bytes<24>("00112233445566778899aabbccddeeff0011223344556677") };

    rndl::aes::Aes<192, 192> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "Rijndael (Block 192, Key 192) Roundtrip failed";
}

TEST(RijndaelTest, Block256_Key256_Roundtrip)
{
    auto key { hex_to_bytes<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") };
    auto plaintext { hex_to_bytes<32>("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") };

    rndl::aes::Aes<256, 256> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "Rijndael (Block 256, Key 256) Roundtrip failed";
}

TEST(RijndaelTest, Block256_Key128_Roundtrip)
{
    auto key { hex_to_bytes<16>("000102030405060708090a0b0c0d0e0f") };
    auto plaintext { hex_to_bytes<32>("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") };

    rndl::aes::Aes<128, 256> aes;
    aes.set_key(key);

    auto state { plaintext };
    aes.encrypt(state, state);
    aes.decrypt(state, state);
    EXPECT_EQ(bytes_to_hex(state), bytes_to_hex(plaintext)) 
        << "Rijndael (Block 256, Key 128) Roundtrip failed";
}

TEST(AesTest, InvalidKeySize_Throws)
{
    rndl::aes::Aes<128, 128> aes;
    
    auto wrong_key { hex_to_bytes<16>("000102030405060708090a0b0c0d0e0f") };
    std::array<std::byte, 24> wrong_key_192{};

    EXPECT_THROW(aes.set_key(wrong_key_192), std::invalid_argument);
}

TEST(AesTest, InvalidStateSize_Throws)
{
    rndl::aes::Aes<128, 128> aes;
    auto key { hex_to_bytes<16>("000102030405060708090a0b0c0d0e0f") };
    aes.set_key(key);

    std::array<std::byte, 24> wrong_state{};
    
    EXPECT_THROW(aes.encrypt(wrong_state, wrong_state), std::invalid_argument);
    EXPECT_THROW(aes.decrypt(wrong_state, wrong_state), std::invalid_argument);
}

} // namespace rndl::tests