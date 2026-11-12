#pragma once

#include "common.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace rndl::gf
{

[[nodiscard]]
auto polynomial_factorization(BigInt polynomial)
    -> std::vector<std::pair<BigInt, std::size_t>>;


[[nodiscard]]
constexpr std::uint16_t get_remainder(
    std::uint16_t dividen,
    std::uint16_t divisor
) {
    if (divisor == 0)
    {
        throw std::invalid_argument("Division by zero in GF(2)");
    }

    auto bit_delta { std::bit_width(dividen) - std::bit_width(divisor) }; 
    while(bit_delta >= 0)
    {
        dividen ^= static_cast<std::uint16_t>(divisor << bit_delta);
        bit_delta = std::bit_width(dividen) - std::bit_width(divisor);
    }

    return dividen;
}

[[nodiscard]]
constexpr bool is_irreducible(
    std::uint8_t elem
) noexcept
{
    const std::uint16_t polynomial { static_cast<std::uint16_t>(0x100 ^ elem) };

    if ((polynomial & 1u) == 0u)
    {
        return false;
    }

    for (std::uint16_t i { 2u }; i < 32u; ++i)
    {
        if (get_remainder(polynomial, i) == 0u)
        {
            return false;
        }
    }

    return true;
}

[[nodiscard]]
constexpr auto get_all_irreducible_polynomials() noexcept
    -> std::array<std::uint8_t, 30>
{
    std::array<std::uint8_t, 30> result{};
    auto count { 0uz };

    for (auto tail { 1u }; tail < 256; tail += 2)
    {
        if (!is_irreducible(static_cast<std::uint16_t>(tail)))
        {
            continue;
        }

        result[count++] = static_cast<std::uint8_t>(tail);
    }

    return result;
}

[[nodiscard]]
constexpr auto add(
    std::uint8_t lhs,
    std::uint8_t rhs
) noexcept
    -> std::uint8_t
{
    return lhs ^ rhs;
}

[[nodiscard]]
constexpr auto multiply(
    std::uint8_t lhs,
    std::uint8_t rhs,
    std::uint8_t mod
)
    -> std::uint8_t
{
    if (!is_irreducible(mod))
    {
        throw std::invalid_argument("Polynomial is reducible over GF(2^8)");
    }
    std::uint16_t mod_ = 0x100 | mod;

    std::uint16_t result{};
    for (auto i { 0u }; i < 8; ++i)
    {
        if ((rhs >> i) & 1u)
        {
            result ^= static_cast<std::uint16_t>(lhs) << i;
        }
    }

    return get_remainder(result, mod_);
}

[[nodiscard]]
constexpr auto inverse(
    std::uint8_t elem,
    std::uint8_t mod
)
    -> std::uint8_t
{
    // In Rijndael (AES), consider the inverse of 0 to be 0.
    if (elem == 0u || elem == 1u) return elem; 

    std::uint8_t result { 1u };
    std::uint8_t power { 254u };
    while (power)
    {
        if ((power & 1u) == 1)
        {
            result = multiply(result, elem, mod);
        }

        power >>= 1;
        elem = multiply(elem, elem, mod);
    }

    return result;
}

} // rndl::gf