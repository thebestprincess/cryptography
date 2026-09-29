#pragma once

#include <concepts>
#include <span>
#include <cstddef>
#include <cstdint>

namespace concepts {

template<typename T>
concept KeyExpander = requires (
    const T& expander,
    std::span<const std::byte, T::MasterKeySize> key) 
{
    typename T::RoundKey;
    typename T::KeyArray;
    
    requires std::same_as<decltype(T::MasterKeySize), const size_t>;

    { expander.expand(key) } -> std::same_as<typename T::KeyArray>;
};

template <typename T>
concept EncryptMethod = requires (
    const T& method,
    std::span<const std::byte, T::HalfBlockSize> block,
    std::span<const std::byte, T::RoundKeySize> round_key,
    std::span<std::byte, T::HalfBlockSize> out_block)
{
    requires std::same_as<decltype(T::BlockSize), const size_t>;
    requires std::same_as<decltype(T::RoundKeySize), const size_t>;
    requires std::same_as<decltype(T::HalfBlockSize), const size_t>;

    { method.encrypt(block, round_key, out_block) };
};


template <typename T>
concept SymmetricCipher = requires (
    T& cipher, 
    std::span<const std::byte, T::BlockSize> block,
    std::span<const std::byte, T::MasterKeySize> key,
    std::span<std::byte, T::BlockSize> out_block)
{
    requires std::same_as<decltype(T::MasterKeySize), const size_t>;
    requires std::same_as<decltype(T::BlockSize), const size_t>;
    
    { cipher.set_key(key) };
    { cipher.encrypt(block, out_block) };
    { cipher.decrypt(block, out_block) };
};

template<typename T>
concept CipherMode = requires (
    T& mode,
    std::span<const std::byte> key,
    std::span<const std::byte> src,
    std::span<std::byte> dst,
    std::span<const std::byte> iv)
{
    requires std::same_as<decltype(T::BlockSize), const size_t>;

    { mode.set_key(key) };
    { mode.encrypt_blocks(src, dst, iv) };
    { mode.decrypt_blocks(src, dst, iv) };
};
    
template <typename T>
concept ByteGenerator = requires (T& g)
{
    { g.next_byte() } -> std::same_as<uint8_t>;
};

} // namespace concepts