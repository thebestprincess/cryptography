#pragma once

#include <span>
#include <cstddef>

namespace shared
{

struct FeistelFunction
{
    static constexpr size_t BlockSize { 8uz };
    static constexpr size_t HalfBlockSize { BlockSize / 2 };
    static constexpr size_t RoundKeySize { 6uz };
    static constexpr size_t RoundsCount { 16uz };

    void encrypt(std::span<const std::byte, HalfBlockSize> block,
                 std::span<const std::byte, RoundKeySize> round_key,
                 std::span<std::byte, HalfBlockSize> out_block) const noexcept;
};

using DesEncryptMethod = FeistelFunction;

} // namespace shared
