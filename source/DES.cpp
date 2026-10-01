#include "DES.hpp"

namespace shared 
{

void DesKeyScheduler::des_key_shift(std::span<std::byte, PermutedKeySize> cidi, size_t round) const noexcept
{
    const unsigned shift { (round == 1 || round == 2 || round == 9 || round == 16) ? 1u : 2u };

    uint64_t raw { 0 };
    for (size_t i { 0 }; i < 7; ++i)
    {
        raw = (raw << 8) | std::to_integer<uint64_t>(cidi[i]);
    }

    uint32_t c { static_cast<uint32_t>((raw >> 28) & 0x0FFFFFFF) };
    uint32_t d { static_cast<uint32_t>(raw & 0x0FFFFFFF) };

    c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
    d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;

    const uint64_t shifted_raw { (static_cast<uint64_t>(c) << 28) | d };

    for (size_t i { 0 }; i < 7; ++i)
    {
        const uint8_t byte_val { static_cast<uint8_t>((shifted_raw >> (8 * (6 - i))) & 0xFF) };
        cidi[i] = static_cast<std::byte>(byte_val);
    }
}

} // namespace shared