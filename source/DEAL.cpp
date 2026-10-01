#include "DEAL.hpp"

#include <algorithm>
#include <array>

namespace shared
{

DealKeyScheduler::KeyTuple DealKeyScheduler::get_input_keys(
    std::span<const std::byte> key) const noexcept
{
    std::array<std::byte, RoundKeySize> K1{};
    std::array<std::byte, RoundKeySize> K2{};
    
    std::ranges::copy(key.first<RoundKeySize>(), K1.begin());
    std::ranges::copy(key.last<RoundKeySize>(), K2.begin());
    
    return {K1, K2};
}

DealKeyScheduler::KeyArray DealKeyScheduler::get_key_schedule(
    std::span<const std::byte> K1,
    std::span<const std::byte> K2) const
{
    static constexpr const std::array<std::byte, 8> fixed_key { 
        std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67}, 
        std::byte{0x89}, std::byte{0xab}, std::byte{0xcd}, std::byte{0xef} 
    };
    static constexpr const std::array<std::byte, RoundsCount> round_const { 
        std::byte{ 0 }, std::byte{ 0 }, std::byte{ 1 }, 
        std::byte{ 2 }, std::byte{ 4 }, std::byte{ 8 }
    };

    Des des{};
    des.set_key(fixed_key);

    KeyArray round_keys{};
    std::span<std::byte> prev_round_key { round_keys[0] };

    for (size_t i { 0 }; i < RoundsCount; ++i)
    {
        std::span<const std::byte> curr_key { (i % 2 == 0) ? K1 : K2 };
        
        std::array<std::byte, RoundKeySize> xored_key{};
        std::ranges::transform(curr_key, prev_round_key, xored_key.begin(), std::bit_xor<>());
        xored_key[0] ^= round_const[i];

        des.encrypt(xored_key, round_keys[i]);

        prev_round_key = round_keys[i];
    }

    return round_keys;
}


}