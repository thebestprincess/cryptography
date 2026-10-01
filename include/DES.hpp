#pragma once

#include "FeistelNetwork.hpp"
#include "concepts.hpp"
#include "constants.hpp"
#include "shared.hpp"

#include <array>
#include <cstddef>
#include <stdexcept>

namespace shared
{


class DesRoundFunction final
{
public:
    static constexpr size_t BlockSize { constants::DES_BLOCK_SIZE };
    static constexpr size_t RoundsCount { 16uz };

    static_assert(BlockSize % 2 == 0);

private:
    static constexpr size_t HalfBlockSize { BlockSize / 2 };
    static constexpr size_t RoundKeySize { 6uz };

public:
    constexpr void encrypt(std::span<const std::byte> half_block,
        std::span<std::byte> out_half_block,
        std::span<const std::byte> round_key) const
    {
        if (half_block.size() != HalfBlockSize)
            throw std::invalid_argument("Invalid half block size.");
        if (out_half_block.size() != HalfBlockSize)
            throw std::invalid_argument("Invalid out half block size.");
        if (round_key.size() != RoundKeySize)
            throw std::invalid_argument("Invalid round key size.");

        std::array<std::byte, RoundKeySize> expand_block { permute_bits_to_array<RoundKeySize>(half_block, tables::E, BitOrder::MSB1) };

        for (auto&& [eb, rk] : std::views::zip(expand_block, round_key))
        {
            eb ^= rk;
        }

        uint64_t xor_48bit { 0 };
        for (const std::byte b : expand_block)
        {
            xor_48bit = (xor_48bit << 8) | std::to_integer<uint64_t>(b);
        }

        uint32_t sbox_output { 0 };
        for (size_t i { 0 }; i < 8; ++i)
        {
            const uint8_t s_input_6bit = (xor_48bit >> (42 - i * 6)) & 0x3F;

            const uint8_t row = ((s_input_6bit & 0x20) >> 4) | (s_input_6bit & 0x01);
            const uint8_t col = (s_input_6bit >> 1) & 0x0F;

            const uint8_t val = tables::S[i][row * 16 + col];

            sbox_output = (sbox_output << 4) | (val & 0x0F);
        }

        std::array<std::byte, HalfBlockSize> sbox_bytes{};
        for (size_t i { 0 }; i < 4; ++i)
        {
            sbox_bytes[i] = static_cast<std::byte>((sbox_output >> (24 - 8 * i)) & 0xFF);
        }

        permute_bits_to(sbox_bytes, tables::P, out_half_block, BitOrder::MSB1);
    }
};
static_assert(concepts::RoundFunction<DesRoundFunction>);



class DesKeyScheduler final 
{
    static constexpr size_t PermutedKeySize { 7uz };
    static constexpr size_t RoundKeySize { 6uz };
    static constexpr size_t RoundsCount { 16uz };
    static constexpr size_t MasterKeySize  { constants::DES_MASTER_KEY_SIZE };
    
public:
    using RoundKey = std::array<std::byte, RoundKeySize>;
    using KeyArray = std::array<RoundKey, RoundsCount>;

    [[nodiscard]] constexpr KeyArray expand(std::span<const std::byte> master_key) const
    {
        if (master_key.size() != MasterKeySize)
            throw std::invalid_argument("DES requires 8-byte key");

        KeyArray round_keys{};

        auto cidi { permute_bits_to_array<PermutedKeySize>(master_key, tables::PC_1, BitOrder::MSB1) };
        for (size_t round { 1 }; round <= RoundsCount; ++round)
        {
            des_key_shift(cidi, round);
            round_keys[round - 1] = permute_bits_to_array<RoundKeySize>(cidi, tables::PC_2, BitOrder::MSB1);
        }

        return round_keys;
    }

private:
    void des_key_shift(std::span<std::byte, PermutedKeySize> cidi, size_t round) const noexcept;
};
static_assert(concepts::KeyScheduler<DesKeyScheduler>);

class Des final
{
    FeistelNetwork<DesKeyScheduler, DesRoundFunction> fn_;

public:
    static constexpr size_t BlockSize { constants::DES_BLOCK_SIZE };
    static constexpr size_t MasterKeySize { constants::DES_MASTER_KEY_SIZE };

    constexpr explicit Des(DesKeyScheduler expander = {}, DesRoundFunction round_function = {}) noexcept
        : fn_(std::move(expander), std::move(round_function)) { }

    constexpr void set_key(std::span<const std::byte> key)
    {
        if (key.size() != MasterKeySize)
            throw std::invalid_argument("Invalid key size");

        fn_.set_key(key);
    }

    constexpr void encrypt(std::span<const std::byte> block,
                           std::span<std::byte> out_block) const
    {
        if (block.size() != BlockSize || out_block.size() != BlockSize)
            throw std::invalid_argument("Invalid block size.");

        const std::array<std::byte, BlockSize> ip_result { permute_bits_to_array<BlockSize>(block, tables::IP, BitOrder::MSB1) };

        std::array<std::byte, BlockSize> encrypt_result{};
        fn_.encrypt(ip_result, encrypt_result);

        permute_bits_to(encrypt_result, tables::IP_INV, out_block, BitOrder::MSB1);
    }

    constexpr void decrypt(std::span<const std::byte> block,
                           std::span<std::byte> out_block) const
    {
        if (block.size() != BlockSize || out_block.size() != BlockSize)
            throw std::invalid_argument("Invalid block size.");

        const std::array<std::byte, BlockSize> ip_result { permute_bits_to_array<BlockSize>(block, tables::IP, BitOrder::MSB1) };

        std::array<std::byte, BlockSize> decrypt_result{};
        fn_.decrypt(ip_result, decrypt_result);

        permute_bits_to(decrypt_result, tables::IP_INV, out_block, BitOrder::MSB1);
    }

};
static_assert(concepts::SymmetricCipher<Des>);

} // namespace shared
