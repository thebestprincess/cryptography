#pragma once

#include "concepts.hpp"
#include "DES.hpp"
#include "FeistelNetwork.hpp"
#include "constants.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>

namespace shared
{

class DealRoundFunction final
{
public:
    static constexpr size_t BlockSize { constants::DEAL_BLOCK_SIZE };
    static constexpr size_t RoundsCount { constants::DEAL_ROUNDS_COUNT };

    constexpr void encrypt(
        std::span<const std::byte> half_block,
        std::span<std::byte> out_half_block,
        std::span<const std::byte> round_key
    ) const {
        Des des{};
        des.set_key(round_key);
        des.encrypt(half_block, out_half_block);
    }
};
static_assert(concepts::RoundFunction<DealRoundFunction>);

class DealKeyScheduler final
{
    static constexpr size_t MasterKeySize { constants::DEAL_MASTER_KEY_SIZE };
    static constexpr size_t RoundKeySize { MasterKeySize / 2 };
    static constexpr size_t RoundsCount { constants::DEAL_ROUNDS_COUNT };

    using KeyTuple = std::tuple<std::array<std::byte, RoundKeySize>, std::array<std::byte, RoundKeySize>>;
    
public:
    using RoundKey = std::array<std::byte, RoundKeySize>;
    using KeyArray = std::array<RoundKey, RoundsCount>;
    
    [[nodiscard]]
    KeyArray expand(std::span<const std::byte> master_key) const
    {
        if (master_key.size() != MasterKeySize)
            throw std::invalid_argument("DEAL-128 requires 16-byte key");

        const auto [K1, K2] { get_input_keys(master_key) };
        KeyArray round_keys { get_key_schedule(K1, K2) };

        return round_keys;
    }
    
private:
    KeyTuple get_input_keys(std::span<const std::byte> key) const noexcept;
    KeyArray get_key_schedule(std::span<const std::byte> K1, std::span<const std::byte> K2) const;
};

using Deal = FeistelNetwork<DealKeyScheduler, DealRoundFunction>;
static_assert(concepts::SymmetricCipher<Deal>);

} // namespace shared