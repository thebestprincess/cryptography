#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>

import std;
import rsa.common;
import rsa.number_theory;
import rsa.prob_test;
import rsa.core;
import rsa.wiener;

namespace crypto::tests
{

class GcdTest : public ::testing::Test
{
protected:
    const BigInt cd { "9876543210111222333444555666777888999000" };
};


TEST_F(GcdTest, FindCommonDivisor)
{
    EXPECT_EQ(nt::gcd_classic(48, 52), 4);
    EXPECT_EQ(nt::gcd_binary(48, 52), 4);

    EXPECT_EQ(nt::gcd_classic(13, 17), 1);
    EXPECT_EQ(nt::gcd_binary(13, 17), 1);

    EXPECT_EQ(nt::gcd_classic(17, 17), 17);
    EXPECT_EQ(nt::gcd_classic(122, 61), 61);
}

TEST_F(GcdTest, ZeroArgument)
{
    EXPECT_EQ(nt::gcd_classic(0, 7), 7);
    EXPECT_EQ(nt::gcd_binary(7, 0), 7);
}

TEST_F(GcdTest, NonNegativeResultForNegativeArgument)
{
    EXPECT_EQ(nt::gcd_classic(2, -4), 2);
    EXPECT_EQ(nt::gcd_binary(-2, -4), 2);
}

TEST_F(GcdTest, TremendousCommonDivisor)
{
    EXPECT_EQ(nt::gcd_classic(cd * 13, cd * 7), cd);
    EXPECT_EQ(nt::gcd_binary(cd * 13, cd * 7), cd);
}

TEST_F(GcdTest, TwoZeros)
{
    EXPECT_THROW(nt::gcd_classic(0, 0), std::invalid_argument);
    EXPECT_THROW(nt::gcd_binary(0, 0), std::invalid_argument);
}

TEST_F(GcdTest, ExtendedGcdBezoutIdentity)
{
    // 39 * (-1) + 52 * 1 = 13
    const auto bezout = nt::gcd_extended(39, 52);
    EXPECT_EQ(bezout.gcd, 13);
    EXPECT_EQ(bezout.x, -1);
    EXPECT_EQ(bezout.y, 1);
    
    BigInt a = cd * 17;
    BigInt b = cd * 23;
    const auto bezout_big = nt::gcd_extended(a, b);
    EXPECT_EQ(bezout_big.gcd, cd);
    EXPECT_EQ(a * bezout_big.x + b * bezout_big.y, bezout_big.gcd);
}


TEST(NumberTheoryTest, LegendreSymbol)
{
    EXPECT_EQ(nt::legendre_symbol(52, 13), 0);
    EXPECT_EQ(nt::legendre_symbol(1, 3), 1);
    EXPECT_EQ(nt::legendre_symbol(3, 5), -1);

    EXPECT_THROW(nt::legendre_symbol(5, 4), std::invalid_argument);
}

TEST(NumberTheoryTest, JacobiSymbol)
{
    EXPECT_EQ(nt::jacobi_symbol(3, 15), 0);
    EXPECT_EQ(nt::jacobi_symbol(2, 15), 1);
    EXPECT_EQ(nt::jacobi_symbol(2, 5), -1);

    EXPECT_THROW(nt::jacobi_symbol(3, 14), std::invalid_argument);
}

TEST(NumberTheoryTest, PowMod)
{
    EXPECT_EQ(nt::pow_mod(13, 2, 52), 13); // 169 % 52 = 13
    EXPECT_EQ(nt::pow_mod(2, 10, 1000), 24); // 1024 % 1000 = 24
    
    EXPECT_EQ(nt::pow_mod(999, 123, 1), 0);

    EXPECT_THROW(nt::pow_mod(5, -2, 10), std::invalid_argument);
    EXPECT_THROW(nt::pow_mod(5, 2, 0), std::invalid_argument);
}


TEST(EulerCarmichaelTest, EulerFunctionsEquivalence)
{
    BigInt val = 30;
    EXPECT_EQ(nt::euler_func_definition(val), 8);
    EXPECT_EQ(nt::euler_func_factorization(val), 8);
    EXPECT_EQ(nt::euler_func_dft(val), 8);
}

TEST(EulerCarmichaelTest, CarmichaelFunction)
{
    EXPECT_EQ(nt::carmichael_func_factorization(32), 8);
    EXPECT_EQ(nt::carmichael_func_factorization(13), 12); // Result is p-1 for simple number
    EXPECT_EQ(nt::carmichael_func_factorization(15), 4);  // LCM(2, 4) = 4
}


TEST(PrimalityTest, KnownPrimesAndComposites)
{
    EXPECT_TRUE(ppt::FermatPrimalityTest::test_one_round(2, 13));
    EXPECT_TRUE(ppt::SolovayStrassenPrimalityTest::test_one_round(2, 13));
    EXPECT_TRUE(ppt::MillerRabinPrimalityTest::test_one_round(2, 13));

    EXPECT_FALSE(ppt::FermatPrimalityTest::test_one_round(2, 15));
    EXPECT_FALSE(ppt::SolovayStrassenPrimalityTest::test_one_round(2, 15));
    EXPECT_FALSE(ppt::MillerRabinPrimalityTest::test_one_round(2, 15));
}


class RsaIntegrationTest : public ::testing::Test
{
protected:
    static constexpr std::size_t kTestKeySize = 512;
    core::RsaService<ppt::MillerRabinPrimalityTest> rsa { 0.9, kTestKeySize >> 1 };
};

TEST_F(RsaIntegrationTest, EncryptDecryptSequence)
{
    const auto [public_key, private_key] = rsa.generate_keys();
    
    const BigInt msg { 123456789 };

    BigInt encrypted = rsa.encrypt(msg, public_key);
    BigInt decrypted = rsa.decrypt(encrypted, private_key);

    EXPECT_NE(msg, encrypted);
    EXPECT_EQ(msg, decrypted);
}

TEST_F(RsaIntegrationTest, InvalidMessageThrows)
{
    const auto [public_key, private_key] = rsa.generate_keys();
    
    const BigInt invalid_msg = public_key.N + 1;
    EXPECT_THROW(rsa.encrypt(invalid_msg, public_key), std::invalid_argument);
    
    EXPECT_THROW(rsa.encrypt(-5, public_key), std::invalid_argument);
}


TEST(WienerAttackTest, AttackSucceedsOnVulnerableKey)
{
    using MillerRabin = ppt::MillerRabinPrimalityTest;
    using VulnPolicy = core::policy::WienerVulnerableKeyGen<MillerRabin>;
    
    core::RsaService<MillerRabin, VulnPolicy> bad_key_gen(0.9, 256);
    
    const auto [public_key, private_key] = bad_key_gen.generate_keys();
    
    auto attack_result = wnr::WienerAttackService::attack(public_key);
    
    ASSERT_TRUE(attack_result.success());
    EXPECT_EQ(attack_result.d.value(), private_key.d);
}

TEST(WienerAttackTest, AttackFailsOnSecureKey)
{
    using MillerRabin = ppt::MillerRabinPrimalityTest;
    using SecurePolicy = core::policy::SecureKeyGen<MillerRabin>;
    
    core::RsaService<MillerRabin, SecurePolicy> secure_key_gen(0.9, 256);
    const auto [public_key, private_key] = secure_key_gen.generate_keys();
    
    auto attack_result = wnr::WienerAttackService::attack(public_key);
    
    EXPECT_FALSE(attack_result.success());
}

} // namespace crypto::tests