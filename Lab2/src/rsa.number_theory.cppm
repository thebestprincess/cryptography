module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/fwd.hpp>

export module rsa.number_theory;

import std;
import rsa.common;

export namespace crypto::nt
{

std::int8_t legendre_symbol(const BigInt& number, const BigInt& odd_prime);
std::int8_t jacobi_symbol(const BigInt number, const BigInt odd_positive);

BigInt pow_mod(BigInt base, BigInt power, const BigInt& mod);

struct GcdExtendedResult
{
    BigInt gcd;
    BigInt x;
    BigInt y;
};

BigInt gcd_classic(BigInt lhs, BigInt rhs);
BigInt gcd_binary(BigInt lhs, BigInt rhs);
GcdExtendedResult gcd_extended(const BigInt& lhs, const BigInt& rhs);

BigInt euler_func_definition(const BigInt& number);
BigInt euler_func_factorization(const BigInt& number);
BigInt euler_func_dft(const BigInt& number);

BigInt carmichael_func_factorization(const BigInt& number);

} // namespace crypto::nt
