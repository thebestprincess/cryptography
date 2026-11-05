#include "galois_field.hpp"

#include <boost/multiprecision/detail/integer_ops.hpp>

namespace
{

using BigInt = boost::multiprecision::cpp_int; 
auto msb = [](const BigInt& value){ return boost::multiprecision::msb(value); };

[[nodiscard]]
BigInt poly_mul(
    const BigInt& lhs,
    const BigInt& rhs
) {
    if (lhs == 0 || rhs == 0)
    {
        return 0;
    }

    BigInt result { 0 };
    const auto length { msb(rhs) };

    for (auto i { 0u }; i <= length; ++i)
    {
        if (boost::multiprecision::bit_test(rhs, i))
        {
            result ^= (lhs << i);
        }
    }
    return result;
}


void poly_div_mod(
    BigInt dividend,
    const BigInt& divisor,
    BigInt& quotient,
    BigInt& remainder
) {
    quotient = 0;
    if (divisor == 0)
    {
        throw std::invalid_argument("Division by zero in GF(2)");
    }
    
    const auto bit_delta { msb(dividend) - msb(divisor) };
    while (dividend != 0 && bit_delta >= 0)
    {
        quotient ^= (BigInt{ 1 } << bit_delta);
        dividend ^= (divisor << bit_delta);
    }

    remainder = dividend;
}

} // namespace



namespace rndl::gf
{
auto polynomial_factorization(
    BigInt polynomial
)
    -> std::vector<std::pair<BigInt, std::size_t>>
{
    if (polynomial < 1)
    {
        throw std::invalid_argument("Polynomial is less than 1 in std::vector<...> polynomial_factorization()");
    }

    std::vector<std::pair<BigInt, std::size_t>> factors{};
    for (BigInt factor{ 2 }; msb(factor) * 2 <= polynomial; ++factor) 
    {
        std::size_t power { 0 };
        BigInt quotient{};
        BigInt remainder{};

        poly_div_mod(polynomial, factor, quotient, remainder);

        while (remainder == 0)
        {
            ++power;
            polynomial = quotient;
            poly_div_mod(polynomial, factor, quotient, remainder);
        }
        
        if (power != 0)
        {
            factors.emplace_back(factor, power);
        }
    }

    if (polynomial > 1)
    {
        factors.emplace_back(polynomial, 1);
    }

    return factors;
}

} // rndl::gf