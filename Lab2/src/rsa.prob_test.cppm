module;

#include <boost/multiprecision/cpp_int.hpp>

export module rsa.prob_test;

import std;
import rsa.common;

export namespace crypto::ppt
{

class FermatPrimalityTest final
{
public:
    [[nodiscard]]
    static bool test_one_round(
        const BigInt& base,
        const BigInt& number
    );

    [[nodiscard]]
    static double get_prob_round_error() noexcept;
};
static_assert(concepts::primality_test<FermatPrimalityTest>);

class SolovayStrassenPrimalityTest final
{
public:
    [[nodiscard]]
    static bool test_one_round(
        const BigInt& base,
        const BigInt& number
    );

    [[nodiscard]]
    static double get_prob_round_error()noexcept;
};
static_assert(concepts::primality_test<SolovayStrassenPrimalityTest>);

class MillerRabinPrimalityTest final
{
public:
    [[nodiscard]]
    static bool test_one_round(
        const BigInt& base,
        const BigInt& number
    );

    [[nodiscard]]
    static double get_prob_round_error() noexcept;
};
static_assert(concepts::primality_test<MillerRabinPrimalityTest>);

} //  namespace crypto::ppt
