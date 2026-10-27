export module rsa.wiener;

import std;
import rsa.common;
import rsa.core;

export namespace crypto::wnr
{

struct ConvergentContinuedFraction
{
    BigInt numerator { 0 };
    BigInt denominator { 0 };
};

struct WienerAttackResult
{
    std::optional<BigInt> d;
    std::optional<BigInt> phi;
    std::vector<ConvergentContinuedFraction> convergents;

    [[nodiscard]]
    bool success() const noexcept
    {
        return d.has_value() && phi.has_value();
    }
};

class WienerAttackService final
{
public:
    static auto attack(const PublicKey& public_key) -> WienerAttackResult;
};

} // crypto::wnr