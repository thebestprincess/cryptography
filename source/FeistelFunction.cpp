#include "FeistelFunction.hpp"
#include "constants.hpp"
#include "shared.hpp"

#include <cstring>
#include <ranges>
#include <cstdint>

namespace shared 
{

void FeistelFunction::encrypt(std::span<const std::byte, HalfBlockSize> block,
                              std::span<const std::byte, RoundKeySize> round_key,
                              std::span<std::byte, HalfBlockSize> out_block) const noexcept
{
    std::array<std::byte, 6> expand_block { permute_bits_to_array<6>(block, tables::E, BitOrder::MSB1) };

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

    permute_bits_to(sbox_bytes, tables::P, out_block, BitOrder::MSB1);
}

} // namespace shared
