#pragma once

#include <concepts>
#include <span>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <concepts>

namespace concepts {

template <typename T>
concept SymmetricCipher = requires (
    T& cipher, 
    std::span<const std::byte> src,
    std::span<std::byte> dst,
    std::span<const std::byte> key
) {
    { T::BlockSize } -> std::convertible_to<size_t>;

    { cipher.set_key(key) } -> std::same_as<void>;
    { cipher.encrypt(src, dst) } -> std::same_as<void>;
    { cipher.decrypt(src, dst) } -> std::same_as<void>;
};

template<typename T>
concept CipherMode = requires (
    T& mode,
    std::span<const std::byte> src,
    std::span<std::byte> dst,
    std::span<const std::byte> key,
    std::span<const std::byte> iv
) {
    { T::BlockSize } -> std::convertible_to<size_t>;

    { T::string() } -> std::convertible_to<std::string_view>;
    { mode.set_key(key) };
    { mode.encrypt_blocks(src, dst, iv) };
    { mode.decrypt_blocks(src, dst, iv) };
};

} // namespace concepts