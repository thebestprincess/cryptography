#include "shared.hpp"

#include <algorithm>
#include <cstddef>

namespace shared::detail
{

template<bool Msb>
constexpr void set_bit(
    std::span<std::byte> data,
    size_t bit_index
) noexcept {
    const size_t byte_idx { bit_index >> 3uz };
    const unsigned bit_idx { static_cast<unsigned>(bit_index & 0x07) };
    const unsigned shift { Msb ? (7u - bit_idx) : bit_idx };
    
    data[byte_idx] |= static_cast<std::byte>(1u << shift);
}

template<bool Msb>
constexpr bool bit_at(
    std::span<const std::byte> data,
    size_t bit_index
) noexcept {
    const size_t byte_idx { bit_index >> 3 };
    const unsigned bit_idx { static_cast<unsigned>(bit_index & 7) };
    const unsigned shift { Msb ? (7u - bit_idx) : bit_idx };
    
    const auto byte_val = std::to_integer<unsigned>(data[byte_idx]);
    return (byte_val & (1u << shift)) != 0;
}

template<bool Msb, bool OneIndexed>
void permute_bits_impl(
    std::span<const std::byte> input,
    std::span<const uint8_t> p_box,
    std::span<std::byte> output
) noexcept {
    std::ranges::fill(output, std::byte{0});

    const size_t p_box_size { p_box.size() };
    for (size_t i { 0 }; i < p_box_size; ++i)
    {
        const size_t src_idx { static_cast<size_t>(p_box[i]) - (OneIndexed ? 1uz : 0uz) };
        
        if (bit_at<Msb>(input, src_idx))
        {
            set_bit<Msb>(output, i);
        }
    }
}

} // namespace

void shared::permute_bits_to(
    std::span<const std::byte> input,
    std::span<const uint8_t> p_box,
    std::span<std::byte> output,
    shared::BitOrder order
) noexcept {
    switch (order)
    {
    case shared::BitOrder::LSB0:
        detail::permute_bits_impl<false, false>(input, p_box, output);
        break;
    case shared::BitOrder::LSB1:
        detail::permute_bits_impl<false, true>(input, p_box, output);
        break;
    case shared::BitOrder::MSB0:
        detail::permute_bits_impl<true, false>(input, p_box, output);
        break;
    case shared::BitOrder::MSB1:
        detail::permute_bits_impl<true, true>(input, p_box, output);
        break;
    }
}
