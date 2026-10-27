#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

#include <print>

import rsa.common;
import rsa.core;
import rsa.number_theory;
import rsa.prob_test;
import rsa.wiener;

int main()
{
    std::println(
        "Legendre symbol for 77 and 7 evaluates to: {} (expected 0)",
        static_cast<int>(crypto::nt::legendre_symbol(77, 7))
    );
    std::println(
        "Legendre symbol for 14 and 11 evaluates to: {} (expected 1)",
        static_cast<int>(crypto::nt::legendre_symbol(14, 11))
    );
    std::println(
        "Legendre symbol for 10 and 17 evaluates to: {} (expected -1)\n",
        static_cast<int>(crypto::nt::legendre_symbol(10, 17))
    );

    std::println(
        "Jacobi symbol for 35 and 15 evaluates to: {} (expected 0)",
        static_cast<int>(crypto::nt::jacobi_symbol(35, 15))
    );
    std::println(
        "Jacobi symbol for 22 and 21 evaluates to: {} (expected 1)",
        static_cast<int>(crypto::nt::jacobi_symbol(22, 21))
    );
    std::println("Jacobi symbol for 11 and 15 evaluates to: {} (expected -1)\n",
        static_cast<int>(crypto::nt::jacobi_symbol(11, 15))
    );


    std::println(
        "Classic Euclid GCD for 105 and 231 yields {} (expected 21)",
        crypto::nt::gcd_classic(105, 231).str()
    );
    std::println(
        "Binary Euclid GCD for 105 and 231 yields {} (expected 21)",
        crypto::nt::gcd_binary(105, 231).str()
    );
    const auto ext_gcd = crypto::nt::gcd_extended(105, 231);
    std::println(
        "Extended GCD formulation: 105 * {} + 231 * {} = {} (expected 105 * (-2) + 231 * 1 = 21)\n",
        ext_gcd.x.str(), ext_gcd.y.str(), ext_gcd.gcd.str()
    );


    std::println(
        "Modular exponentiation for 5 and 3 mod 13 yields {} (expected 8)\n",
        crypto::nt::pow_mod(5, 3, 13).str()
    );


    std::println(
        "Euler's totient function (definition) for 42 yields {} (expected 12)",
        crypto::nt::euler_func_definition(42).str()
    );
    std::println(
        "Euler's totient function (factorization) for 42 yields {} (expected 12)",
        crypto::nt::euler_func_factorization(42).str()
    );
    std::println(
        "Euler's totient function (DFT) for 42 yields {} (expected 12)\n",
        crypto::nt::euler_func_dft(42).str()
    );


    std::println(
        "Carmichael function for 45 yields {} (expected 12)",
        crypto::nt::carmichael_func_factorization(45).str()
    );
    std::println(
        "Carmichael function for 56 yields {} (expected 6)\n",
        crypto::nt::carmichael_func_factorization(56).str()
    );


    constexpr std::size_t kKeySize { 1024UZ };
    crypto::core::RsaService<crypto::ppt::FermatPrimalityTest> rsa_fermat(0.95, kKeySize >> 1);
    crypto::core::RsaService<crypto::ppt::SolovayStrassenPrimalityTest> rsa_solovay(0.95, kKeySize >> 1);
    crypto::core::RsaService rsa_miller(0.95, kKeySize >> 1);

    const auto [pub_fermat, priv_fermat] { rsa_fermat.generate_keys() };
    const auto [pub_solovay, priv_solovay] { rsa_solovay.generate_keys() };
    const auto [pub_miller, priv_miller] { rsa_miller.generate_keys() };

    const crypto::BigInt payload { 123456789 };
    crypto::BigInt enc_data { 0 };
    crypto::BigInt dec_data { 0 };

    enc_data = rsa_fermat.encrypt(payload, pub_fermat);
    dec_data = rsa_fermat.decrypt(enc_data, priv_fermat);
    std::println("Payload: {} -> Fermat Decrypted: {}", payload.str(), dec_data.str());

    enc_data = rsa_solovay.encrypt(payload, pub_solovay);
    dec_data = rsa_solovay.decrypt(enc_data, priv_solovay);
    std::println("Payload: {} -> Solovay-Strassen Decrypted: {}", payload.str(), dec_data.str());

    enc_data = rsa_miller.encrypt(payload, pub_miller);
    dec_data = rsa_miller.decrypt(enc_data, priv_miller);
    std::println("Payload: {} -> Miller-Rabin Decrypted: {}\n", payload.str(), dec_data.str());

    using FermatTestType = crypto::ppt::FermatPrimalityTest;
    using VulnFermat = crypto::core::policy::WienerVulnerableKeyGen<FermatTestType>;
    crypto::core::RsaService<
        FermatTestType,
        VulnFermat
    > vuln_gen1(0.95, kKeySize >> 1);

    using SolovayTestType = crypto::ppt::SolovayStrassenPrimalityTest;
    using VulnSolovay = crypto::core::policy::WienerVulnerableKeyGen<SolovayTestType>;
    crypto::core::RsaService<
        SolovayTestType,
        VulnSolovay
    > vuln_gen2(0.95, kKeySize >> 1);

    using MillerTestType = crypto::ppt::MillerRabinPrimalityTest;
    using VulnMiller = crypto::core::policy::WienerVulnerableKeyGen<MillerTestType>;
    crypto::core::RsaService<
        MillerTestType,
        VulnMiller
    > vuln_gen3(0.95, kKeySize >> 1);

    const auto [vuln_pub1, vuln_priv1] { vuln_gen1.generate_keys() };
    const auto [vuln_pub2, vuln_priv2] { vuln_gen2.generate_keys() };
    const auto [vuln_pub3, vuln_priv3] { vuln_gen3.generate_keys() };

    std::println(
        "Target 1 public (N, e):\nN: {}\ne: {}",
        vuln_pub1.N.str(),
        vuln_pub1.e.str()
    );
    std::println(
        "Target 1 private (N, d):\nN: {}\nd: {}",
        vuln_priv1.N.str(),
        vuln_priv1.d.str()
    );
    const auto successful_attack1 = crypto::wnr::WienerAttackService::attack(vuln_pub1);
    std::println(
        "Wiener attack extracted (phi, d):\nphi: {}\nd: {}\n",
        successful_attack1.phi.value().str(),
        successful_attack1.d.value().str()
    );

    std::println(
        "Target 2 public (N, e):\nN: {}\ne: {}",
        vuln_pub2.N.str(),
        vuln_pub2.e.str()
    );
    std::println(
        "Target 2 private (N, d):\nN: {}\nd: {}",
        vuln_priv2.N.str(),
        vuln_priv2.d.str()
    );
    const auto successful_attack2 = crypto::wnr::WienerAttackService::attack(vuln_pub2);
    std::println(
        "Wiener attack extracted (phi, d):\nphi: {}\nd: {}\n",
        successful_attack2.phi.value().str(),
        successful_attack2.d.value().str()
    );

    std::println(
        "Target 3 public (N, e):\nN: {}\ne: {}",
        vuln_pub3.N.str(),
        vuln_pub3.e.str()
    );
    std::println(
        "Target 3 private (N, d):\nN: {}\nd: {}",
        vuln_priv3.N.str(),
        vuln_priv3.d.str()
    );
    const auto successful_attack3 = crypto::wnr::WienerAttackService::attack(vuln_pub3);
    std::println(
        "Wiener attack extracted (phi, d):\nphi: {}\nd: {}\n",
        successful_attack3.phi.value().str(),
        successful_attack3.d.value().str()
    );

    return 0;
}