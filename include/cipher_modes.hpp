#pragma once

#include "concepts.hpp"

#include <algorithm>
#include <cstdint>
#include <execution>
#include <ranges>
#include <span>
#include <array>

namespace shared
{

enum class CipherMode : uint8_t { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };

} // namespace shared

namespace shared::mode
{

template<concepts::SymmetricCipher Cipher>
class ECB final
{
    Cipher cipher_{};

public:
    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst,
        [[maybe_unused]] std::span<const std::byte> iv = {})
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and destination must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const size_t num_blocks { (src.size() + BlockSize - 1) / BlockSize };

        auto indices = std::views::iota(0uz, num_blocks);
        std::for_each(
            std::execution::par_unseq, 
            indices.begin(),
            indices.end(), 
            [this, src, dst](size_t i)
            {
                auto curr_src { src.subspan(i * BlockSize, BlockSize).first<BlockSize>() };
                auto curr_dst { dst.subspan(i * BlockSize, BlockSize).first<BlockSize>() };
            
                cipher_.encrypt(curr_src,  curr_dst);
            });
    }

    void decrypt_blocks(
        std::span<const std::byte> src,
        std::span<std::byte> dst,
        [[maybe_unused]] std::span<const std::byte> iv = {})
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and dst must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        auto src_blocks { src | std::views::chunk(BlockSize) };
        auto dst_blocks { dst | std::views::chunk(BlockSize) };

        auto src_dst_blocks { std::views::zip(src_blocks, dst_blocks) };

        std::for_each(
            std::execution::par_unseq,
            src_dst_blocks.begin(),
            src_dst_blocks.end(),
            [this](auto src_dst_chunks)
            {
                auto&& [src_chunk, dst_chunk] { src_dst_chunks }; 

                std::span<const std::byte, BlockSize> src_span { src_chunk.data(), BlockSize };
                std::span<std::byte, BlockSize> dst_span { dst_chunk.data(), BlockSize };

                cipher_.decrypt(src_span,  dst_span);
            });
    }
};

template<concepts::SymmetricCipher Cipher>
class CBC final
{
    Cipher cipher_{};

public:
    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and dst must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        auto src_blocks { src | std::views::chunk(BlockSize) };
        auto dst_blocks { dst | std::views::chunk(BlockSize) };

        std::span<const std::byte> prev_ct { iv };
        
        for (auto&& [src_chunk, dst_chunk] : std::views::zip(src_blocks, dst_blocks))
        {
            std::span<const std::byte, BlockSize> src_span { src_chunk.data(), BlockSize };
            std::span<std::byte, BlockSize> dst_span { dst_chunk.data(), BlockSize };

            std::ranges::transform(prev_ct, src_span, dst_span.begin(), std::bit_xor<>());
            cipher_.encrypt(dst_span, dst_span);

            prev_ct = dst_span;
        }
    }

    void decrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and dst must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const size_t num_blocks { (src.size() + BlockSize - 1) / BlockSize };

        auto indices = std::views::iota(0uz, num_blocks);
        std::for_each(
            std::execution::par_unseq, 
            indices.begin(),
            indices.end(), 
        [this, src, dst, iv](size_t i)
        {
            std::span<const std::byte, BlockSize> prev_cipher_text { (i == 0) ? iv : src.subspan((i - 1) * BlockSize, BlockSize).first<BlockSize>() };

            auto curr_src { src.subspan(i * BlockSize, BlockSize).first<BlockSize>() };
            auto curr_dst { dst.subspan(i * BlockSize, BlockSize).first<BlockSize>() };
        
            cipher_.decrypt(curr_src, curr_dst);

            std::ranges::transform(curr_dst, prev_cipher_text, curr_dst.begin(), std::bit_xor<>{});
        });
    }
};

template<concepts::SymmetricCipher Cipher>
class PCBC final
{
    Cipher cipher_{};

public:
    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and dst must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        auto src_blocks { src | std::views::chunk(BlockSize) };
        auto dst_blocks { dst | std::views::chunk(BlockSize) };

        std::array<std::byte, BlockSize> prev_xor{};
        std::ranges::copy(iv, prev_xor.begin());
        std::span prev_xor_span { prev_xor };

        for (auto&& [src_chunk, dst_chunk] : std::views::zip(src_blocks, dst_blocks))
        {
            std::span<const std::byte, BlockSize> src_span{ src_chunk.data(), BlockSize };
            std::span<std::byte, BlockSize> dst_span{ dst_chunk.data(), BlockSize };

            std::array<std::byte, BlockSize> curr_plaintext{};
            std::ranges::copy(src_span, curr_plaintext.begin());

            std::ranges::transform(prev_xor_span, curr_plaintext, dst_span.begin(), std::bit_xor<>());
            cipher_.encrypt(dst_span, dst_span);
            
            std::ranges::transform(dst_span, curr_plaintext, prev_xor_span.begin(), std::bit_xor<>());
        }
    }

    void decrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (src.size() % BlockSize != 0 || dst.size() < src.size())
            throw std::invalid_argument("Size must be a multiple of BlockSize and dst must be large enough");
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");
        
        const auto src_blocks { src | std::views::chunk(BlockSize) };
        const auto dst_blocks { dst | std::views::chunk(BlockSize) };
    
        std::array<std::byte, BlockSize> prev_xor{};
        std::ranges::copy(iv, prev_xor.begin());
        std::span prev_xor_span { prev_xor };

        for (auto&& [src_chunk, dst_chunk] : std::views::zip(src_blocks, dst_blocks))
        {
            std::span<const std::byte, BlockSize> src_span{ src_chunk.data(), BlockSize };
            std::span<std::byte, BlockSize> dst_span{ dst_chunk.data(), BlockSize };

            cipher_.decrypt(src_span, dst_span);
            std::ranges::transform(dst_span, prev_xor_span, dst_span.begin(), std::bit_xor<>());
            std::ranges::transform(dst_span, src_span, prev_xor_span.begin(), std::bit_xor<>());
        }    
    }
};

template<concepts::SymmetricCipher Cipher>
class CFB final
{
    Cipher cipher_{};

public:
    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const auto src_blocks { src | std::views::chunk(BlockSize) };
        auto dst_blocks { dst | std::views::chunk(BlockSize) };
    
        std::array<std::byte, BlockSize> prev_ct{};
        std::ranges::copy(iv, prev_ct.begin());
        std::span prev_cipher_text{ prev_ct };
        for (auto&& [src_chunk, dst_chunk] : std::views::zip(src_blocks, dst_blocks))
        {
            cipher_.encrypt(prev_cipher_text, prev_cipher_text);
            std::ranges::transform(src_chunk, prev_cipher_text, dst_chunk.begin(), std::bit_xor<>());

            std::ranges::copy(dst_chunk, prev_cipher_text.begin());
        }
    }

    void decrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const size_t num_blocks { (src.size() + BlockSize - 1) / BlockSize };

        auto indices = std::views::iota(0uz, num_blocks);
        std::for_each(
            std::execution::par_unseq, 
            indices.begin(),
            indices.end(), 
            [this, src, dst, iv](size_t i)
            {
                std::span<const std::byte, BlockSize> prev_ct { (i == 0) ? iv : src.subspan((i - 1) * BlockSize, BlockSize).first<BlockSize>() };

                const size_t curr_bs { std::min<size_t>(BlockSize, src.size() - i * BlockSize) };
                auto curr_src { src.subspan(i * BlockSize, curr_bs) };
                auto curr_dst { dst.subspan(i * BlockSize, curr_bs) };

                std::array<std::byte, BlockSize> curr_cipher_key{};
                cipher_.encrypt(prev_ct, curr_cipher_key);

                std::ranges::transform(curr_src, curr_cipher_key, curr_dst.begin(), std::bit_xor<>());
            });
    }
};

template<concepts::SymmetricCipher Cipher>
class OFB final
{
    Cipher cipher_{};

public:
    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const auto src_blocks { src | std::views::chunk(BlockSize) };
        auto dst_blocks { dst | std::views::chunk(BlockSize) };
    
        std::array<std::byte, BlockSize> prev_iv{};
        std::ranges::copy(iv, prev_iv.begin());
        std::span prev_iv_span { prev_iv };

        for (auto&& [src_chunk, dst_chunk] : std::views::zip(src_blocks, dst_blocks))
        {
            cipher_.encrypt(prev_iv_span, prev_iv_span);
            std::ranges::transform(src_chunk, prev_iv_span, dst_chunk.begin(), std::bit_xor<>());
        }
    }

    void decrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        encrypt_blocks(src, dst, iv);
    }
};

template<concepts::SymmetricCipher Cipher>
class CTR final
{
    Cipher cipher_{};
    const size_t delta_;

public:
    explicit CTR(size_t delta = 1uz) : delta_(delta) {}    

    static constexpr size_t BlockSize { Cipher::BlockSize };

    void set_key(std::span<const std::byte> key)
    {
        cipher_.set_key(key);
    }

    void encrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        if (iv.size() != BlockSize)
            throw std::invalid_argument("Invalid IV size");

        const uint64_t num_blocks { (src.size() + BlockSize - 1) / BlockSize };
        
        auto indices = std::views::iota(uint64_t{0}, num_blocks);
        std::for_each(
            std::execution::par_unseq,
            indices.begin(),
            indices.end(), 
            [this, src, dst, iv](uint64_t index)
            {
                uint64_t block_index { index * delta_ };
                std::array<std::byte, BlockSize> counter { make_counter(iv, block_index) };

                std::array<std::byte, BlockSize> encrypted_counter{};
                cipher_.encrypt(counter,  encrypted_counter);

                const size_t offset { index * BlockSize };
                const size_t current_block_size { std::min<size_t>(BlockSize, src.size() - offset) };
                auto curr_src { src.subspan(offset, current_block_size) };
                auto curr_dst { dst.subspan(offset, current_block_size) };
                
                std::ranges::transform(curr_src, encrypted_counter, curr_dst.begin(), std::bit_xor<>());
            });
    }

    void decrypt_blocks(
        std::span<const std::byte> src, 
        std::span<std::byte> dst, 
        std::span<const std::byte> iv)
    {
        encrypt_blocks(src, dst, iv);
    }

private:
    [[nodiscard]] std::array<std::byte, BlockSize> make_counter(
        std::span<const std::byte> iv, 
        uint64_t block_index) 
    {
        std::array<std::byte, BlockSize> counter;
        std::ranges::copy(iv, counter.begin());

        uint64_t carry { block_index };
        for (size_t i : std::views::iota(0uz, BlockSize) | std::views::reverse)
        {
            uint16_t sum = static_cast<uint8_t>(counter[i]) + (carry & 0xFF);
            counter[i] = static_cast<std::byte>(sum & 0xFF);
            carry = (carry >> 8) + (sum >> 8);
            if (!carry) break;
        }

        return counter;
    }
};

template<concepts::SymmetricCipher Cipher>
using RandomDelta = CTR<Cipher>;

} // namespace::mode