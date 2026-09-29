#pragma once

#include "concepts.hpp"
#include "constants.hpp"
#include "shared.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <ranges>
#include <stdexcept>

namespace shared
{

template<concepts::KeyExpander ExpanderType, concepts::EncryptMethod MethodType>
class DES final
{
public:
    static constexpr size_t MasterKeySize { ExpanderType::MasterKeySize };
    static constexpr size_t BlockSize { MethodType::BlockSize };
    static constexpr size_t HalfBlockSize { MethodType::HalfBlockSize };
    static constexpr size_t RoundKeySize { MethodType::RoundKeySize };
    static constexpr size_t RoundsCount { MethodType::RoundsCount };

    constexpr explicit DES(ExpanderType expander = {}, MethodType method = {}) noexcept
        : expander_{ std::move(expander) }, method_{ std::move(method) } {}

    constexpr void set_key(std::span<const std::byte> key)
    {
        if (key.size() != MasterKeySize)
            throw std::invalid_argument("Invalid key size");

        std::ranges::copy(key, master_key_.begin());
        round_keys_ = expander_.expand(key);
    }

    constexpr void encrypt(std::span<const std::byte, BlockSize> block,
                           std::span<std::byte, BlockSize> out_block) const
    {
        process_network(block, out_block, std::views::iota(0uz, RoundsCount));
    }

    constexpr void decrypt(std::span<const std::byte, BlockSize> block,
                           std::span<std::byte, BlockSize> out_block) const
    {
        process_network(block, out_block, std::views::iota(0uz, RoundsCount) | std::views::reverse);
    }

private:
    ExpanderType expander_{};
    MethodType method_{};

    std::array<std::byte, MasterKeySize> master_key_{};
    typename ExpanderType::KeyArray round_keys_{};

    template<typename RoundRange>
    constexpr void process_network(std::span<const std::byte, BlockSize> block,
                                   std::span<std::byte, BlockSize> out_block,
                                   RoundRange&& round_range) const
    {
        const std::array<std::byte, BlockSize> ip_block { permute_bits_to_array<BlockSize>(block, tables::IP, BitOrder::MSB1) };

        std::span<const std::byte> ip_block_span { ip_block };
        std::array<std::byte, HalfBlockSize> left_block{};
        std::array<std::byte, HalfBlockSize> right_block{};

        std::ranges::copy(ip_block_span.template first<HalfBlockSize>(), left_block.begin());
        std::ranges::copy(ip_block_span.template last<HalfBlockSize>(), right_block.begin());

        std::array<std::byte, HalfBlockSize> feistel_result{};
        for (size_t round_idx : round_range)
        {
            const auto temp {left_block};
            left_block = right_block;
            
            method_.encrypt(right_block, round_keys_[round_idx], feistel_result);

            std::ranges::transform(temp, feistel_result, right_block.begin(), std::bit_xor<>());
        }

        std::array<std::byte, BlockSize> ip_inv_block{};
        auto out_span = std::span<std::byte, BlockSize>(ip_inv_block);

        std::ranges::copy(right_block, out_span.template first<HalfBlockSize>().begin());
        std::ranges::copy(left_block,  out_span.template last<HalfBlockSize>().begin());

        permute_bits_to(ip_inv_block, tables::IP_INV, out_block, BitOrder::MSB1);
    }        

};

} // namespace shared
