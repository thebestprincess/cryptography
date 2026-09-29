#pragma once

#include "constants.hpp"
#include "shared.hpp"

#include <span>
#include <array>
#include <stdexcept>

namespace shared::detail
{
void des_key_shift(std::span<std::byte, 7> cidi, size_t round) noexcept;
} // namespace shared::detail

namespace shared
{

template <size_t RoundKeySize = 6uz, size_t RoundsCount = 16uz>
struct BaseKeyExpander
{
    static constexpr size_t MasterKeySize  { 8uz };
    static constexpr size_t PermtutedKeySize { 7uz };

    using RoundKey = std::array<std::byte, RoundKeySize>;
    using KeyArray = std::array<RoundKey, RoundsCount>;

    [[nodiscard]] constexpr KeyArray expand(std::span<const std::byte> master_key) const
    {
        if (master_key.size() != MasterKeySize)
            throw std::invalid_argument("Invalid key size");

        KeyArray round_keys{};

        auto cidi { shared::permute_bits_to_array<PermtutedKeySize>(master_key, tables::PC_1, shared::BitOrder::MSB1) };
        for (size_t round { 1 }; round <= RoundsCount; ++round)
        {
            detail::des_key_shift(cidi, round);

            round_keys[round - 1] = shared::permute_bits_to_array<RoundKeySize>(cidi, tables::PC_2, shared::BitOrder::MSB1);
        }

        return round_keys;
    }
};

using DesKeyExpander = BaseKeyExpander<6, 16>;

} // namespace shared
