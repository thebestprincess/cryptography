#pragma once

#include <concepts>
#include <ranges>
#include <span>
#include <cstddef>

namespace concepts {

template<typename T>
concept KeyScheduler = requires (
    const T& expander,
    std::span<const std::byte> key) 
{
    { expander.expand(key) } -> std::ranges::input_range;
};

template <typename T>
concept RoundFunction = requires (
    const T& method,
    std::span<const std::byte> half_block,
    std::span<std::byte> out_half_block,
    std::span<const std::byte> round_key)
{
    { method.encrypt(half_block, out_half_block, round_key) } -> std::same_as<void>;
};


template <typename T>
concept SymmetricCipher = requires (
    T& cipher, 
    std::span<const std::byte> block,
    std::span<const std::byte> key,
    std::span<std::byte> out_block)
{
    { T::BlockSize } -> std::convertible_to<size_t>;
    
    { cipher.set_key(key) } -> std::same_as<void>;
    { cipher.encrypt(block, out_block) } -> std::same_as<void>;
    { cipher.decrypt(block, out_block) } -> std::same_as<void>;
};

template<typename T>
concept CipherMode = requires (
    T& mode,
    std::span<const std::byte> src,
    std::span<std::byte> dst,
    std::span<const std::byte> key,
    std::span<const std::byte> iv)
{
    { T::BlockSize } -> std::convertible_to<size_t>;

    { T::string() } -> std::convertible_to<std::string_view>;
    { mode.set_key(key) };
    { mode.encrypt_blocks(src, dst, iv) };
    { mode.decrypt_blocks(src, dst, iv) };
};

} // namespace concepts