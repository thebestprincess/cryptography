module;

#include <boost/multiprecision/cpp_int.hpp>

module rsa.prob_test;

import std;
import rsa.common;
import rsa.number_theory;

namespace crypto::ppt
{

/*
Check: a^{n - 1} == 1 (mod n)
*/
bool FermatPrimalityTest::test_one_round(
    const BigInt &base,
    const BigInt &number
) {
    if (nt::gcd_binary(base, number) != 1)
    {
        return false;
    }
    
    return nt::pow_mod(base, number - 1, number) == 1;
}

double FermatPrimalityTest::get_prob_round_error() noexcept
{
    return 0.5;
}


/*
Check: a^{(n - 2) / 2} == (a/n) (mod n)
(a/n) - Jacobi symbol
*/
bool SolovayStrassenPrimalityTest::test_one_round(
    const BigInt &base,
    const BigInt &number
) {
    if (nt::gcd_binary(base, number) != 1)
    {
        return false;
    }

    const auto jacoby_result { nt::jacobi_symbol(base, number) };
    const auto expr_result { nt::pow_mod(base, (number - 1) / 2, number) };

    const BigInt expected { (jacoby_result < 0) ? static_cast<BigInt>(jacoby_result) + number : jacoby_result };

    return expr_result == expected;
}

double SolovayStrassenPrimalityTest::get_prob_round_error() noexcept
{
    return 0.5;
}


/*
Check:
n - 1 = 2^s * d
a^d = 1 (mod n) || 0<=r<s: (a^d)^{2^r} = -1 (mod n)  
*/
bool MillerRabinPrimalityTest::test_one_round(
    const BigInt &base,
    const BigInt &number
) {
    if (nt::gcd_binary(base, number) != 1)
    {
        return false;
    }

    BigInt d { number - 1 };
    std::size_t s { 0 };
    while ((d & 1) == 0)
    {
        d >>= 1;
        ++s;
    }
    
    auto apowd { nt::pow_mod(base, d, number) };
    if (apowd == 1 || apowd == number - 1)
    {
        return true;
    }

    for (std::size_t r { 1 }; r < s; ++r)
    {
        apowd = (apowd * apowd) % number;

        if (apowd == number - 1)
        {
            return true;
        }

        if (apowd == 1)
        {
            return false;
        }
    }

    return false;
}

double MillerRabinPrimalityTest::get_prob_round_error() noexcept
{
    return 0.25;
}


} // namespace crypto::ppt