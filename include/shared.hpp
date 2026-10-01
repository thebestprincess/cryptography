#pragma once

#include <cstddef>
#include <span>
#include <cstdint>

namespace shared
{

enum class BitOrder : uint8_t { LSB0, LSB1, MSB0, MSB1 };

void permute_bits_to(
    std::span<const std::byte> input,
    std::span<const uint8_t> p_box,
    std::span<std::byte> output,
    BitOrder order
) noexcept;


template <size_t N>
[[nodiscard]] std::array<std::byte, N> permute_bits_to_array(
    std::span<const std::byte> input,
    std::span<const uint8_t> p_box,
    BitOrder order
) {
    std::array<std::byte, N> result{};
    permute_bits_to(input, p_box, result, order);
    return result;
}

} // namespace shared