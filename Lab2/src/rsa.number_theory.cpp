module;

#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/detail/default_ops.hpp>
#include <boost/multiprecision/fwd.hpp>

module rsa.number_theory;

import std;

namespace crypto::nt
{

namespace
{

std::vector<std::pair<BigInt, std::size_t>> factorization(BigInt number)
{
    if (number < 1)
    {
        throw std::invalid_argument("number is less than 1 in std::vector<...> factorization()");
    }

    std::vector<std::pair<BigInt, std::size_t>> factors{};
    for (BigInt factor { 2 }; factor * factor <= number; ++factor)
    {
        std::size_t power { 0 };

        while (number % factor == 0)
        {
            ++power;
            number /= factor;
        }
        
        if (power != 0)
        {
            factors.emplace_back(factor, power);
        }
    }

    if (number > 1)
    {
        factors.emplace_back(number, 1);
    }

    return factors;
}

BigInt binpow(BigInt base, std::size_t power)
{
    BigInt result { 1 };
    while (power)
    {
        if ((power & 1UZ) == 1)
        {
            result *= base;
        }

        power >>= 1UZ;
        base *= base;
    }

    return result;
}

} // namespace

std::int8_t legendre_symbol(const BigInt& number, const BigInt& odd_prime)
{
    if(odd_prime <= 2 || (odd_prime & 1) == 0)
    {
        throw std::invalid_argument("invalid odd_prime in std::int8_t legendre_symbol(...)");
    }

    BigInt result { pow_mod(number, (odd_prime - 1) >> 1, odd_prime) };
    if (result == 0)
    {
        return 0;
    }
    if (result == 1)
    {
        return 1;
    }
    if (result == odd_prime - 1)
    {
        return -1;
    }

    throw std::invalid_argument("odd_prime is not prime");
}

std::int8_t jacobi_symbol(BigInt number, BigInt odd_positive)
{
    if (odd_positive < 1 || odd_positive % 2 == 0)
    {
        throw std::invalid_argument("invalid odd_positive in std::int8_t jacobi_symbol(...)");
    }
    
    number %= odd_positive;
    if (number < 0)
    {
        number += odd_positive;
    }

    std::int8_t sign { 1 };
    while(number)
    {
        while((number & 1) == 0)
        {
            number >>= 1;

            if (const auto r = odd_positive & 7; r == 3 || r == 5)
            {
                sign = -sign;
            }
        }

        std::swap(number, odd_positive);

        if ((number & 3) == 3 && (odd_positive & 3) == 3)
        {
            sign = -sign;
        }

        number %= odd_positive;
    }

    return (odd_positive == 1) ? sign : 0;
}


BigInt pow_mod(BigInt base, BigInt power, const BigInt& mod)
{
    if (mod <= 0 || power < 0)
    {
        throw std::invalid_argument("invalid mod or power in BigInt pow_mod(...)");
    } 

    if (mod == 1)
    {
        return 0;
    }

    base %= mod;
    if (base < 0)
    {
        base += mod;
    }

    BigInt result = 1;
    while(power)
    {
        if ((power & 1) == 1)
        {
            result = result * base % mod;
        }

        power >>= 1;
        base = base * base % mod;
    }

    return result;
}


BigInt gcd_classic(BigInt lhs, BigInt rhs)
{
    if (lhs == 0 && rhs == 0)
    {
        throw std::invalid_argument("lhs and rhs are both zero in BigInt gcd_classic()");
    }

    if (lhs < 0)
    {
        lhs = -lhs;
    }
    if (rhs < 0)
    {
        rhs = -rhs;
    }

    while(rhs != 0)
    {
        lhs %= rhs;
        std::swap(lhs, rhs);
    }

    return lhs;
}

BigInt gcd_binary(BigInt lhs, BigInt rhs)
{
    if (lhs == 0 && rhs == 0)
    {
        throw std::invalid_argument("lhs and rhs are BOTH ZERO in BigInt gcd_binary(...)");
    }

    if (lhs < 0)
    {
        lhs = -lhs;
    }
    if (rhs < 0)
    {
        rhs = -rhs;
    }

    if (lhs == 0)
    {
        return rhs;
    }
    if (rhs == 0)
    {
        return lhs;
    }

    std::size_t shift { 0 };
    while (((rhs | lhs) & 1) == 0)
    {
        rhs >>= 1;
        lhs >>= 1;
        ++shift;
    }

    while ((lhs & 1) == 0)
    {
        lhs >>= 1;
    }

    do
    {
        while ((rhs & 1) == 0)
        {
            rhs >>= 1;
        }

        if (lhs > rhs)
        {
            std::swap(lhs, rhs);
        }

        rhs -= lhs;
    } while (rhs != 0);

    return lhs << shift;
}

GcdExtendedResult gcd_extended(const BigInt& lhs, const BigInt& rhs)
{
    if (lhs == 0 && rhs == 0)
    {
        throw std::invalid_argument("lhs and rhs are both zero in GcdExtendedResult gcd_extended()");
    }

    BigInt prev_r { lhs < 0 ? -lhs : lhs };
    BigInt prev_s { 1 };
    BigInt prev_t { 0 };

    BigInt r { rhs < 0 ? -rhs : rhs };
    BigInt s { 0 };
    BigInt t { 1 };
    
    while (r != 0)
    {
        BigInt q { prev_r / r };

        auto temp = r;
        r = prev_r - q * r;
        prev_r = temp;

        temp = s;
        s = prev_s - q * s;
        prev_s = temp;

        temp = t;
        t = prev_t - q * t;
        prev_t = temp;
    }

    if (lhs < 0)
    {
        prev_s = -prev_s;
    }
    if (rhs < 0)
    {
        prev_t = -prev_t;
    }

    return { .gcd = prev_r, .x = prev_s, .y = prev_t};
}


BigInt euler_func_definition(const BigInt& number)
{
    if (number < 1)
    {
        throw std::invalid_argument("wrong number for BigInt euler_func_definition(...)");
    }

    std::size_t count { 0 };
    for (BigInt i { 1 }; i < number; ++i)
    {
        if (gcd_binary(i, number) == 1)
        {
            ++count;
        }
    }

    return count;
}

BigInt euler_func_factorization(const BigInt& number)
{
    if (number < 1)
    {
        throw std::invalid_argument("wrong number for BigInt euler_func_factorizatoin(...)");
    }

    BigInt cnt { 1 };
    for (const auto& [prime, power] : factorization(number))
    {
        cnt *= (prime - 1) * binpow(prime, power - 1);
    }

    return cnt;
}

BigInt euler_func_dft(const BigInt& number)
{
    if (number < 1)
    {
        throw std::invalid_argument("wrong number for BigInt euler_func_dft(...)");
    }

    using float100_t = boost::multiprecision::cpp_dec_float_100;
    auto boost_cos = [&](float100_t res)
        {
            return boost::multiprecision::cos(res);
        };
    
    float100_t sum { 0 };
    const float100_t n { number.str() };
    const float100_t pi { boost::math::constants::pi<float100_t>() };

    for (BigInt i { 1 }; i <= number; ++i)
    {
        const float100_t k { i.str() };
        const float100_t gcd { gcd_binary(i, number) };
        const float100_t angle { boost_cos(float100_t{ 2 } * pi * k / n) };

        sum += gcd * angle;
    }

    const BigInt result { boost::multiprecision::round(sum).convert_to<BigInt>() };

    return result;
}


BigInt carmichael_func_factorization(const BigInt& number)
{
    if (number < 1)
    {
        throw std::invalid_argument("wrong number for BigInt carmichael_function_factorization(...)");
    }

    BigInt result { 1 };
    for (const auto& [prime, power] : factorization(number))
    {
        BigInt lambda{};

        if (prime == 2 && power > 2)
        {
            lambda = BigInt{ 1 } << (power - 2);
        }
        else
        {
            lambda = binpow(prime, power - 1) * (prime - 1);
        }

        const auto gcd { gcd_binary(result, lambda) };
        result = result * lambda / gcd;
    }

    return result;
}

} // namespace crypto::nt
