#pragma once

#include "common.hpp"
#include "galois_field.hpp"
#include "concepts.hpp"

#include <array>
#include <algorithm>
#include <functional>
#include <span>
#include <cstdint>
#include <ranges>

namespace rndl::aes
{

template <
    std::size_t KeyBitLength = 128UZ,
    std::size_t BlockBitLength = 128UZ,
    std::uint8_t Mod = 0x1B
>
class Aes final
{
    static_assert(KeyBitLength == 128UZ || KeyBitLength == 192UZ || KeyBitLength == 256UZ,
                  "KeyBitLength must be 128, 192, or 256");
    static_assert(BlockBitLength == 128UZ || BlockBitLength == 192UZ || BlockBitLength == 256UZ,
                  "BlockBitLength must be 128, 192, or 256");

    static constexpr std::size_t n_block_words_ { BlockBitLength / 32UZ };
    static constexpr std::size_t n_key_words_ { KeyBitLength / 32UZ };
    static constexpr std::size_t n_rounds_ { std::max(n_key_words_, n_block_words_) + 6UZ };

    static constexpr std::size_t round_key_size_bytes_ { BlockBitLength / 8UZ };
    static constexpr std::size_t num_round_keys_ { n_rounds_ + 1UZ };

    using RoundKey = std::array<std::uint8_t, round_key_size_bytes_>;
    using RoundKeys = std::array<RoundKey, num_round_keys_>;

    RoundKeys round_keys_{};
    static constexpr std::uint8_t mod_{ Mod };

    std::array<std::uint8_t, 256> sbox_{};
    std::array<std::uint8_t, 256> inv_sbox_{};
    bool sboxes_initialized_ = false;

public:
    static constexpr std::size_t BlockSize { BlockBitLength / 8UZ };

    constexpr Aes()
    {
        init_sboxes();
    }

    constexpr auto set_key(
        std::span<const std::byte> key
    )
        -> void
    {
        if (key.size() != KeyBitLength / 8UZ )
        {
            throw std::invalid_argument("Invalid key size");
        }

        expand_key(as_u8_span(key));
    }

    constexpr void encrypt(
        std::span<const std::byte> src, 
        std::span<std::byte> dst
    ) 
    {
        if (src.size() != dst.size()) throw std::invalid_argument("Size mismatch");
        
        std::ranges::copy(src, dst.begin());
        
        encrypt_impl(as_u8_span(dst));
    }

    constexpr void decrypt(
        std::span<const std::byte> src, 
        std::span<std::byte> dst
    ) 
    {
        if (src.size() != dst.size()) throw std::invalid_argument("Size mismatch");

        std::ranges::copy(src, dst.begin());
        
        decrypt_impl(as_u8_span(dst));
    }

    auto get_sbox() noexcept
        -> std::array<std::uint8_t, 256>
    {
        return sbox_;
    }

    auto get_inv_sbox() noexcept
        -> std::array<std::uint8_t, 256>
    {
        return inv_sbox_;
    }

private:
    // in-place state incryption
    constexpr auto encrypt_impl(
        std::span<std::uint8_t> state 
    ) 
        -> void
    {
        if (state.size() != round_key_size_bytes_)
        {
            throw std::invalid_argument("State size != 16");
        }

        add_round_key(state, 0UZ);
        
        for (std::size_t i : std::views::iota(1UZ, n_rounds_))
        {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, i);
        }
        
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, n_rounds_);
    }

    // in-place state decryption
    constexpr auto decrypt_impl(
        std::span<std::uint8_t> state 
    )
        -> void
    {
        if (state.size() != round_key_size_bytes_)
        {
            throw std::invalid_argument("State size != 16");
        }

        add_round_key(state, n_rounds_);
        
        for (std::size_t i : std::views::iota(1UZ, n_rounds_) | std::views::reverse)
        {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, i);
            inv_mix_columns(state);
        }
        
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0UZ);
    }

    constexpr void init_sboxes() noexcept
    {
        if (sboxes_initialized_) return;

        for (auto i : std::views::iota(0uz, 256uz))
        {
            std::uint8_t inv { gf::inverse(static_cast<std::uint8_t>(i), mod_) };

            sbox_[i] = inv ^ ((inv << 1u) | (inv >> 7u)) 
                           ^ ((inv << 2u) | (inv >> 6u))
                           ^ ((inv << 3u) | (inv >> 5u))
                           ^ ((inv << 4u) | (inv >> 4u))
                           ^ 0x63;
        }

        for (auto i : std::views::iota(0uz, 256uz))
        {
            std::uint8_t inv = ((i << 1u) | (i >> 7u))
                               ^ ((i << 3u) | (i >> 5u))
                               ^ ((i << 6u) | (i >> 2u))
                               ^ 0x05; 

            inv_sbox_[i] = gf::inverse(inv, mod_);
        }

        sboxes_initialized_ = true;
    }

    constexpr void expand_key(
        std::span<const std::uint8_t> key
    ) noexcept
    {
        std::span<std::uint8_t> flat_keys(
            reinterpret_cast<std::uint8_t*>(round_keys_.data()),
            round_keys_.size() * round_key_size_bytes_
        );

        std::ranges::copy(key, flat_keys.begin());

        constexpr std::size_t total_words { n_block_words_ * num_round_keys_ };
        for (auto i : std::views::iota(n_key_words_, total_words))
        {
            auto curr_word { std::span(flat_keys).subspan(i * 4, 4) };
            auto prev_word { std::span(flat_keys).subspan((i - 1) * 4, 4) };

            std::ranges::copy(prev_word, curr_word.begin());

            if (i % n_key_words_ == 0) 
            {
                std::rotate(curr_word.begin(), curr_word.begin() + 1, curr_word.end());
                for (auto& val : curr_word)
                {
                    val = sbox_[val];
                }
                curr_word[0] ^= cnst::Rcon[(i / n_key_words_) - 1];
            } 
            else if (n_key_words_ == 8 && i % n_key_words_ == 4) 
            {
                for (auto& val : curr_word)
                {
                    val = sbox_[val];
                }
            }

            auto nk_back_word { std::span(flat_keys).subspan((i - n_key_words_) * 4, 4) };
            for (std::size_t j = 0; j < 4; ++j) 
            {
                curr_word[j] ^= nk_back_word[j];
            }
        }
    }

    constexpr void sub_bytes(
        std::span<std::uint8_t> state
    ) noexcept
    {
        for (auto& value : state)
        {
            value = sbox_[value];
        }
    }

    constexpr void inv_sub_bytes(
        std::span<std::uint8_t> state
    ) noexcept
    {
        for (auto& value : state)
        {
            value = inv_sbox_[value];
        }
    }

    constexpr void shift_rows(
        std::span<std::uint8_t> state
    ) noexcept
    {
        std::array<std::size_t, 4> shifts { 0, 1, 2, 3 };
        if (BlockBitLength == 256UZ)
        {
            shifts[2] = 3;
            shifts[3] = 4;
        }

        for (auto [idx_row, shift] : shifts | std::views::enumerate)
        {
            std::array<std::uint8_t, n_block_words_> row{};
            auto row_view { state.subspan(idx_row) | std::views::stride(4) };

            std::size_t i { 0UZ };
            for (auto val : row_view)
            {
                row[i++] = val;
            }
            std::rotate(row.begin(), row.begin() + shift, row.end());

            i = 0;
            for (auto&& val : row_view)
            {
                val = row[i++];
            }
        }
    }

    constexpr void inv_shift_rows(
        std::span<std::uint8_t> state
    ) noexcept
    {
        std::array<std::size_t, 4> shifts { 0, 1, 2, 3 };
        if (BlockBitLength == 256UZ)
        {
            shifts[2] = 3;
            shifts[3] = 4;
        }

        for (auto [idx_row, shift] : shifts | std::views::enumerate)
        {
            std::array<std::uint8_t, n_block_words_> row{};
            auto row_view { state.subspan(idx_row) | std::views::stride(4) };

            std::size_t i { 0UZ };
            for (auto val : row_view)
            {
                row[i++] = val;
            }

            std::rotate(row.begin(), row.begin() + n_block_words_ - shift, row.end());

            i = 0;
            for (auto&& val : row_view)
            {
                val = row[i++];
            }
        }
    }

    /*
        (03x^3 + 01x^2 + 01x + 02) * (s3 * x^3 + s2 * x^2 + s1 * x + s0) (mod x^4 + 1)

        / 02 03 01 01 \      / s0 \
        | 01 02 03 01 |  \/  | s1 |
        | 01 01 02 03 |  /\  | s2 |
        \ 03 01 01 02 /      \ s3 /
    */
    constexpr void mix_columns(
        std::span<std::uint8_t> state
    ) noexcept
    {
        for (auto chunk : state | std::views::chunk(4))
        {
            const std::uint8_t s0 = chunk[0];
            const std::uint8_t s1 = chunk[1];
            const std::uint8_t s2 = chunk[2];
            const std::uint8_t s3 = chunk[3];

            chunk[0] = gf::multiply(0x02, s0, mod_) ^ gf::multiply(0x03, s1, mod_) ^ s2 ^ s3;
            chunk[1] = s0 ^ gf::multiply(0x02, s1, mod_) ^ gf::multiply(0x03, s2, mod_) ^ s3;
            chunk[2] = s0 ^ s1 ^ gf::multiply(0x02, s2, mod_) ^ gf::multiply(0x03, s3, mod_);
            chunk[3] = gf::multiply(0x03, s0, mod_) ^ s1 ^ s2 ^ gf::multiply(0x02, s3, mod_);
        }
    }
    
    /*
        (0Bx^3 + 0Dx^2 + 09x + 0E) * (s3 * x^3 + s2 * x^2 + s1 * x + s0) (mod x^4 + 1)

        / 0E 0B 0D 09 \      / s0 \
        | 09 0E 0B 0D |  \/  | s1 |
        | 0D 09 0E 0B |  /\  | s2 |
        \ 0B 0D 09 0E /      \ s3 /
    */
    constexpr void inv_mix_columns(
        std::span<std::uint8_t> state
    ) {
        for (auto chunk : state | std::views::chunk(4))
        {
            const std::uint8_t s0 = chunk[0];
            const std::uint8_t s1 = chunk[1];
            const std::uint8_t s2 = chunk[2];
            const std::uint8_t s3 = chunk[3];

            chunk[0] = gf::multiply(0x0E, s0, mod_)
                     ^ gf::multiply(0x0B, s1, mod_) 
                     ^ gf::multiply(0x0D, s2, mod_) 
                     ^ gf::multiply(0x09, s3, mod_);

            chunk[1] = gf::multiply(0x09, s0, mod_)
                     ^ gf::multiply(0x0E, s1, mod_) 
                     ^ gf::multiply(0x0B, s2, mod_) 
                     ^ gf::multiply(0x0D, s3, mod_);

            chunk[2] = gf::multiply(0x0D, s0, mod_)
                     ^ gf::multiply(0x09, s1, mod_) 
                     ^ gf::multiply(0x0E, s2, mod_) 
                     ^ gf::multiply(0x0B, s3, mod_);

            chunk[3] = gf::multiply(0x0B, s0, mod_)
                     ^ gf::multiply(0x0D, s1, mod_) 
                     ^ gf::multiply(0x09, s2, mod_) 
                     ^ gf::multiply(0x0E, s3, mod_);
        }
    }

    constexpr void add_round_key(
        std::span<std::uint8_t> state,
        std::size_t round
    ) noexcept
    {
        std::ranges::transform(
            round_keys_[round],
            state,
            state.begin(),
            std::bit_xor<>()
        );
    }

private:
    inline auto as_u8_span(
        std::span<const std::byte> sp
    )
        -> std::span<const std::uint8_t>
    {
        return { reinterpret_cast<const std::uint8_t*>(sp.data()), sp.size() };
    }

    inline auto as_u8_span(
        std::span<std::byte> sp
    )
        -> std::span<std::uint8_t>
    {
        return { reinterpret_cast<std::uint8_t*>(sp.data()), sp.size() };
    }
};
static_assert(concepts::SymmetricCipher<Aes<>>);

} // namespace rndl::aes