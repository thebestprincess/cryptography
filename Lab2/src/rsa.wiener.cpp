module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/integer.hpp>

module rsa.wiener;

import rsa.common;
import std;

namespace crypto::wnr::detail
{

auto create_continued_fraction(
    const ConvergentContinuedFraction& fraction
) -> std::vector<BigInt>
{
    if (fraction.denominator == 0)
    {
        throw std::invalid_argument("Invalid denominator in create_continued_fraction(...)");
    }

    BigInt numerator { fraction.numerator };
    BigInt denominator { fraction.denominator };

    std::vector<BigInt> result;
    while (denominator != 0)
    {
        result.emplace_back(numerator / denominator);

        const BigInt remainder { numerator % denominator };
        numerator = denominator;
        denominator = remainder;
    }

    return result;
}

auto create_convergents(
    const ConvergentContinuedFraction& fraction
) -> std::vector<ConvergentContinuedFraction>
{
    const auto decomposition { create_continued_fraction(fraction) };

    std::vector<ConvergentContinuedFraction> result;
    result.reserve(decomposition.size());

    BigInt p_prev_prev { 0 };
    BigInt p_prev { 1 };
    BigInt q_prev_prev { 1 };
    BigInt q_prev { 0 };

    for (std::size_t i { 0 }; i < decomposition.size(); ++i)
    {
        const BigInt p { decomposition[i] * p_prev + p_prev_prev };
        const BigInt q { decomposition[i] * q_prev + q_prev_prev };
        result.push_back({ .numerator = p, .denominator = q });

        p_prev_prev = p_prev;
        p_prev = p;
        q_prev_prev = q_prev;
        q_prev = q;
    }

    return result;
}

} // namespace


namespace crypto::wnr
{

auto WienerAttackService::attack(
    const PublicKey& public_key
) -> WienerAttackResult
{
    if (public_key.e <= 0 || public_key.N <= 1)
    {
        throw std::invalid_argument("invalid public_key in Wiener's attack");
    }

    auto mltpr_sqrt = [](const BigInt& number)
    {
        return boost::multiprecision::sqrt(number);
    };

    const auto convergents { detail::create_convergents({ .numerator = public_key.e, .denominator = public_key.N })};
    for (const auto& [k, d] : convergents)
    {
        if (k == 0)
        {
            continue;
        }

        if ((public_key.e * d - 1) % k != 0)
        {
            continue;
        }  

        const auto phi { (public_key.e * d - 1) / k };
        if (phi <= 0 || phi >= public_key.N)
        {
            continue;
        }        

        // x^2 - ((N - phi) + 1)x + n = 0;
        const BigInt sum_roots { public_key.N - phi + 1 };
        const auto discriminant { sum_roots * sum_roots - 4 * public_key.N };
        if (discriminant < 0)
        {
            continue;
        }
        
        const BigInt root { mltpr_sqrt(discriminant) };
        if (!(root * root == discriminant && ((sum_roots + root) & 1) == 0))
        {
            continue;
        }

        const BigInt factor1 { (sum_roots + root) >> 1 };
        const BigInt factor2 { (sum_roots - root) >> 1 };
        if (!(factor1 > 1 && factor2 > 1 && factor1 * factor2 == public_key.N))
        {
            continue;
        }

        return WienerAttackResult{
            .d = d,
            .phi = phi,
            .convergents = convergents   
        };
    }
    
    return WienerAttackResult{
        .d = std::nullopt,
        .phi = std::nullopt,
        .convergents = convergents   
    };
}



} // namespace crypto::wnr