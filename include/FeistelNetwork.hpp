#pragma once

#include "concepts.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <ranges>
#include <tuple>

namespace shared
{

template<concepts::KeyScheduler KE, concepts::RoundFunction RF>
class FeistelNetwork final
{
    KE expander_{};
    RF method_{};

public:
    using KeyArray = typename KE::KeyArray;
    static constexpr size_t RoundsCount { std::tuple_size_v<KeyArray> };

    static constexpr size_t BlockSize{ RF::BlockSize };
    static constexpr size_t HalfBlockSize { BlockSize / 2 };

    constexpr explicit FeistelNetwork(
        KE expander = {},
        RF method = {}
    ) noexcept
    : expander_{ std::move(expander) }, method_{ std::move(method) } {}

    constexpr void set_key(std::span<const std::byte> key)
    {
        round_keys_ = expander_.expand(key);
    }

    constexpr void encrypt(
        std::span<const std::byte> block,
        std::span<std::byte> out_block
    ) const {
        process_network(block, out_block, std::views::iota(0uz, RoundsCount));
    }

    constexpr void decrypt(
        std::span<const std::byte> block,
        std::span<std::byte> out_block
    ) const {
        process_network(block, out_block, std::views::iota(0uz, RoundsCount) | std::views::reverse);
    }

private:
    KeyArray round_keys_{};

private:
    template<typename RoundRange>
    constexpr void process_network(
        std::span<const std::byte> block,
        std::span<std::byte> out_block,
        RoundRange&& round_range
    ) const {
        std::array<std::byte, HalfBlockSize> left_block{};
        std::array<std::byte, HalfBlockSize> right_block{};

        std::ranges::copy(block.first<HalfBlockSize>(), left_block.begin());
        std::ranges::copy(block.last<HalfBlockSize>(), right_block.begin());

        std::array<std::byte, HalfBlockSize> feistel_result{};
        for (size_t round_idx : round_range)
        {
            const auto temp {left_block};
            left_block = right_block;
            
            method_.encrypt(right_block, feistel_result, round_keys_[round_idx]);

            std::ranges::transform(temp, feistel_result, right_block.begin(), std::bit_xor<>());
        }

        std::ranges::copy(right_block, out_block.first<HalfBlockSize>().begin());
        std::ranges::copy(left_block,  out_block.last<HalfBlockSize>().begin());
    }        
};

} // namespace shared
