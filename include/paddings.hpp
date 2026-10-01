#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <random>
#include <span>
#include <string_view>
#include <utility>

namespace shared::padding
{

enum class CipherPadding : uint8_t { Zeros, ANSI_X923, PKCS7, ISO_10126 };
enum class PaddingError : uint8_t { InvalidPadding };

std::string_view get_padding_name(CipherPadding padding_type);

template<size_t BlockSize = 8uz>
constexpr void add_padding(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    CipherPadding padding_type) noexcept
{
    const size_t pad_len { BlockSize - input.size() % BlockSize };
    if (!pad_len) return;

    if (input.data() != output.data())
    {
        std::ranges::copy(input, output.begin());
    }
    
    std::span pad_range { output.subspan(input.size()) };

    switch (padding_type)
    {
        case CipherPadding::Zeros:
            std::ranges::fill(pad_range, static_cast<std::byte>(0x00));
            break;
        case CipherPadding::ANSI_X923:
            std::ranges::fill(pad_range, static_cast<std::byte>(0x00));
            output.back() = static_cast<std::byte>(pad_len);
            break;
        case CipherPadding::PKCS7:
            std::ranges::fill(pad_range, static_cast<std::byte>(pad_len));
            break;
        case CipherPadding::ISO_10126:
            std::mt19937_64 engine{std::random_device{}()};
            std::uniform_int_distribution<unsigned short> dist(0, 255);
            for (size_t i { 0 }; i < pad_len - 1; ++i)
            {
                pad_range[i] = static_cast<std::byte>(dist(engine));
            }
            output.back() = static_cast<std::byte>(pad_len);
            break;
    }
}

template<size_t BlockSize = 8uz>
constexpr std::expected<std::span<const std::byte>, PaddingError> remove_padding(
    std::span<const std::byte> block,
    CipherPadding padding_type) noexcept
{
    size_t pad_len { 0 };

    switch(padding_type)
    {
        case CipherPadding::Zeros:
        {
            if (block[BlockSize - 1] != static_cast<std::byte>(0x00))
                return std::unexpected(PaddingError::InvalidPadding);
            size_t i { BlockSize };
            while (i > 0 && block[i - 1] == static_cast<std::byte>(0x00)) --i;

            pad_len = BlockSize - i;
            break;
        }
        case CipherPadding::ANSI_X923:
        {
            pad_len = std::to_integer<size_t>(block.back());
            if (pad_len > BlockSize || !pad_len) return std::unexpected(PaddingError::InvalidPadding);

            const auto pad_range { block.last(pad_len) };
            for (size_t i { 0 }; i < pad_len - 1; ++i)
            {
                if (pad_range[i] != static_cast<std::byte>(0x00))
                {
                    return std::unexpected(PaddingError::InvalidPadding);
                }
            }

            break;
        }
        case CipherPadding::ISO_10126:
        {
            pad_len = std::to_integer<size_t>(block.back());
            break;
        }
        case CipherPadding::PKCS7:
        {
            pad_len = std::to_integer<size_t>(block.back());
            if (pad_len > BlockSize || !pad_len) return std::unexpected(PaddingError::InvalidPadding);

            const auto pad_range { block.last(pad_len) };
            for (size_t i { 0 }; i < pad_len - 1; ++i)
            {
                if (pad_range[i] != pad_range[pad_len - 1])
                {
                    return std::unexpected(PaddingError::InvalidPadding);
                }
            }

            break;
        }
        default: std::unreachable();
    }

    if (pad_len > BlockSize) return std::unexpected(PaddingError::InvalidPadding);
    return block.first(BlockSize - pad_len);
}

} // namespace shared