module;

#include <boost/multiprecision/cpp_int.hpp>

export module rsa.common;

import std;

export namespace crypto
{
using BigInt = boost::multiprecision::cpp_int;

struct PublicKey final
{
    BigInt e { 0 };
    BigInt N { 0 };
};

struct PrivateKey final
{
    BigInt d { 0 };
    BigInt N { 0 };
};

struct KeyPair final
{
    PublicKey public_key;
    PrivateKey private_key;
};

namespace concepts
{

template <typename T>
concept primality_test = requires(
    const BigInt& base,
    const BigInt& number
) {
    { T::test_one_round(base, number)  } -> std::same_as<bool>;
    { T::get_prob_round_error() } noexcept -> std::same_as<double>;
};

template <typename T>
concept key_gen_policy = requires(
    T policy,
    std::size_t bit_length,
    double min_prob
) {
    { policy.generate(bit_length, min_prob) } -> std::same_as<KeyPair>; 
};

} // namespace crypto::concepts
} // namepace crypto