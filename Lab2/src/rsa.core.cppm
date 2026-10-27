module;

#include <boost/multiprecision/cpp_int.hpp>
#include <random>

export module rsa.core;

import std;
import rsa.common;
import rsa.prob_test;
import rsa.number_theory;

namespace crypto::core::detail
{
BigInt get_random_below(
    std::mt19937_64& engine,
    const BigInt& upper_bound
) {
    if (upper_bound <= 0)
    {
        throw std::invalid_argument("upper_bound has to be great than zero");
    }

    std::size_t bit_count { 0 };
    for (BigInt number { upper_bound - 1}; number > 0; number >>= 1)
    {
        ++bit_count;
    }

    while (true)
    {
        BigInt number { 0 };
        for (std::size_t bit { 0 }; bit < bit_count; ++bit)
        {
            if ((engine() & 1U) == 1)
            {
                number |= BigInt{ 1 } << bit;
            }
        }

        if (number < upper_bound)
        {
            return number;
        }
    }
}

/*
Base check within range: [2, n - 2].
Bases 0, 1 and n - 1 are trivial.
The first meaningful base is 2.
*/
BigInt get_random_base(
    const BigInt& number,
    std::mt19937_64& engine
) {
    return 2 + get_random_below(engine, number - 3);
}

template<concepts::primality_test T>
class ProbabilisticPrimalityTest final
{
public:
    [[nodiscard]]
    bool test(
        std::mt19937_64& engine,
        const BigInt& number,
        double min_probability
    ) const
    {
        if (min_probability - 1.0 >= 0.0
            || std::abs(min_probability - 0.5) < std::numeric_limits<double>::epsilon())
        {
            throw std::invalid_argument("min_probability has to be in [0.5, 1)");
        }

        if (number < 2 || (number & 1) == 0)
        {
            return false;
        }

        if (number == 2 || number == 3)
        {
            return true;
        }

        const auto round_probability_error { T::get_prob_round_error() };
        if (round_probability_error < 0.0 || round_probability_error > 1.0)
        {
            throw std::invalid_argument("per-round probability error has to be in (0; 1)");
        }

        const std::size_t rounds {
            static_cast<std::size_t>(std::ceil(std::log1p(-min_probability) / std::log(round_probability_error)))
        };

        for (std::size_t i { 0UZ }; i < std::max(rounds, std::size_t{ 1 }); ++i)
        {
            if (!T::test_one_round(get_random_base(number, engine), number))
            {
                return false;
            }
        }

        return true;
    }
};

BigInt generate_odd(
    std::mt19937_64& engine,
    std::size_t bit_length
) {
    BigInt result { 0 };
    for (std::size_t i { 0 }; i < bit_length; i += 64) {
        result |= BigInt{engine()} << i;
    }

    BigInt mask { (BigInt{1} << bit_length) - 1 };
    result &= mask;

    result |= BigInt{1} << (bit_length - 1);
    result |= 1;

    return result;
}

template <concepts::primality_test T>
BigInt generate_probably_prime(
    const ProbabilisticPrimalityTest<T>& test,
    std::mt19937_64& engine,
    std::size_t bit_length,
    double min_prob
) {
    while (true)
    {
        const BigInt generated_odd { generate_odd(engine, bit_length) };
        if (test.test(engine, generated_odd, min_prob))
        {
            return generated_odd;
        }
    }
}

} // namespace crypto::core::detail

export namespace crypto::core::policy
{

template <concepts::primality_test Test = ppt::MillerRabinPrimalityTest>
class SecureKeyGen final
{
private:
    [[no_unique_address]]
    detail::ProbabilisticPrimalityTest<Test> test_;
    std::mt19937_64 engine_ { std::random_device{}() };

public:
    /*
    n = p * q
    phi(n) = phi(n) * phi(q)
    gcd(e, phi) == 1
    d == e^(-1) (mod phi(n))
    */
    [[nodiscard]]
    KeyPair generate(std::size_t bit_length, double min_prob)
    {
        auto mltpr_sqrt = [](auto value){ return boost::multiprecision::sqrt(value); };

        while (true)
        {
            const BigInt e { 65537 };
            BigInt p { 0 };
            BigInt q { 0 };

            while (true)
            {
                p = detail::generate_probably_prime(test_, engine_, bit_length, min_prob);
                if (nt::gcd_binary(e, p - 1) == 1)
                {
                    break;
                }
            }

            while (true)
            {
                q = detail::generate_probably_prime(test_, engine_, bit_length, min_prob);
                if (nt::gcd_binary(e, q - 1) == 1)
                {
                    break;
                }
            }

            // Fermat's attack
            if (boost::multiprecision::abs(p - q) <= 2 * (bit_length >> 4))
            {
                continue;
            }

            const BigInt n { p * q };
            const BigInt phi_n { (p - 1) * (q - 1) };
            const auto gcd_ext_result { nt::gcd_extended(e, phi_n) };

            BigInt temp_d { gcd_ext_result.x % phi_n };
            const BigInt d { (temp_d < 0) ? temp_d + phi_n : temp_d }; 

            // Wiener's attack
            if (3 * d <= mltpr_sqrt(mltpr_sqrt(n)))
            {
                continue;
            }

            return KeyPair{
                .public_key = { .e = e, .N = n},
                .private_key = { .d = d, .N = n}
            };
        }
    }
};
static_assert(concepts::key_gen_policy<SecureKeyGen<>>);

template<concepts::primality_test Test = ppt::MillerRabinPrimalityTest>
class WienerVulnerableKeyGen final
{
private:
    [[no_unique_address]]
    detail::ProbabilisticPrimalityTest<Test> test_;
    std::mt19937_64 engine_ { std::random_device{}() };

public:
    [[nodiscard]] 
    KeyPair generate(std::size_t bit_length, double min_prob)
    {
        auto mltpr_sqrt = [](auto value){ return boost::multiprecision::sqrt(value); };

        while (true)
        {
            const BigInt p { detail::generate_probably_prime(test_, engine_, bit_length, min_prob) };
            const BigInt q { detail::generate_probably_prime(test_, engine_, bit_length, min_prob) };
            if (p == q)
            {
                continue;
            }

            const BigInt n { p * q };
            const BigInt phi_n { (p - 1) * (q - 1) };
            const BigInt d_ubound { mltpr_sqrt(mltpr_sqrt(n)) / 3 };
            bool flag { false };

            BigInt d { 3 }; 
            for (; d <= d_ubound; d += 2)
            {
                if (nt::gcd_binary(d, phi_n) == 1)
                {
                    flag = true;
                    break;
                }
            }
            if (!flag)
            {
                continue;
            }

            const auto gcd_ext_result { nt::gcd_extended(d, phi_n) };
            BigInt temp_e { gcd_ext_result.x % phi_n };
            const BigInt e { (temp_e < 0) ? temp_e + phi_n : temp_e }; 

            if ((e * d) % phi_n != 1)
            {
                continue;
            }

            return KeyPair{
                .public_key = { .e = e, .N = n },
                .private_key = { .d = d, .N = n }
            };
        }
    }
};
static_assert(concepts::key_gen_policy<WienerVulnerableKeyGen<>>);

} // namespace crypto::core::policy


export namespace crypto::core
{

template<
    concepts::primality_test Test = ppt::MillerRabinPrimalityTest,
    concepts::key_gen_policy Policy = policy::SecureKeyGen<Test>  
>
class RsaService final
{
private:
    [[no_unique_address]]
    Policy key_gen_;

    std::size_t bit_length_;
    double min_prob_;

public:
    explicit RsaService(
        double min_prob,
        std::size_t bit_length
    )
        : min_prob_(min_prob)
        , bit_length_(bit_length)
    {
        if (min_prob_ - 0.5 < -std::numeric_limits<double>::epsilon()
            || min_prob_ - 1.0 >= 0.0)
        {
            throw std::invalid_argument("min_prob has to be within [0.5, 1.0)");
        }

        if (bit_length_ < 2)
        {
            throw std::invalid_argument("bit_length has to be more than 2");
        }
    } 

    [[nodiscard]]
    KeyPair generate_keys()
    {
        return key_gen_.generate(bit_length_, min_prob_);
    }

    // c = p^e (mod N)
    BigInt encrypt(const BigInt& plain_text, const PublicKey& public_key)
    {
        if (public_key.e <= 1 ||  public_key.N <= 1)
        {
            throw std::invalid_argument("Invalid public key");
        }

        if (plain_text < 0 || plain_text >= public_key.N)
        {
            throw std::invalid_argument("Invalid plain_text, it has to be within [0, N)");
        }

        return nt::pow_mod(plain_text, public_key.e, public_key.N);
    }
    

    // p = c^d (mod N)
    BigInt decrypt(const BigInt& cipher_text, const PrivateKey& private_key)
    {
        if (private_key.d <= 0 ||  private_key.N <= 1)
        {
            throw std::invalid_argument("Invalid private key");
        }

        if (cipher_text < 0 || cipher_text >= private_key.N)
        {
            throw std::invalid_argument("Invalid cipher_text, it has to be within [0, N)");
        }

        return nt::pow_mod(cipher_text, private_key.d, private_key.N);
    }

};

} // namespace 