#pragma once

#include "concepts.hpp"
#include "paddings.hpp"
#include "constants.hpp"

#include <filesystem>
#include <fstream>
#include <future>
#include <ios>
#include <span>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace shared
{
enum class CryptoOp: uint8_t { Encrypt, Decrypt };

template<concepts::CipherMode Mode>
class CipherContext final
{
    Mode mode_{};
    shared::padding::CipherPadding padding_type_;
    std::vector<std::byte> iv_;

public:
    explicit CipherContext(
        std::span<const std::byte> key,
        shared::padding::CipherPadding padding_type,
        std::span<const std::byte> iv = {})
        : padding_type_(padding_type)
    {
        mode_.set_key(key);
        if (!iv.empty()) iv_.assign_range(iv);
    }


    [[nodiscard]] std::future<void> process_file_async(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        CryptoOp op)
    {
        return std::async(
            std::launch::async,
            [this, input_path, output_path, op]
        {
            process_file(input_path, output_path, op);
        });
    }

    [[nodiscard]] std::future<size_t> async_encrypt(
        std::span<const std::byte> input,
        std::span<std::byte> output)
    {
        return std::async(
            std::launch::async,
            [this, input, output]
        {
            return encrypt_span(input, output);
        });
    }

    [[nodiscard]] std::future<size_t> async_decrypt(
        std::span<const std::byte> input,
        std::span<std::byte> output)
    {
        return std::async(
            std::launch::async,
            [this, input, output]
        {
            return decrypt_span(input, output);
        });
    }
    

private:
    static constexpr size_t buffer_size { constants::BUFFER_SIZE };
    static constexpr size_t block_size  { Mode::BlockSize };
    static_assert(buffer_size % block_size == 0);


    static std::ifstream open_input(const std::filesystem::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error(std::format("Failed to open input file: {}", path.string()));
        }
        return file;
    }

    static std::ofstream open_output(const std::filesystem::path& path)
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            throw std::runtime_error(std::format("Failed to open output file: {}", path.string()));
        }
        return file;
    }

    static size_t read_chunk(std::ifstream& in, std::span<std::byte> buffer)
    {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        return static_cast<size_t>(in.gcount());
    }

    static void write_chunk(std::ofstream& out, std::span<const std::byte> data)
    {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out)
        {
            throw std::runtime_error("Failed to write to output file");
        }
    }

    static bool at_eof(std::ifstream& in)
    {
        return in.peek() == std::char_traits<char>::eof();
    }

    static void check_ciphertext_size(size_t size)
    {
        if (size % block_size != 0)
        {
            throw std::runtime_error("Corrupted ciphertext: size is not a multiple of block size");
        }
    }

    size_t pad_last_chunk(std::span<std::byte> buffer, size_t data_size)
    {
        const size_t pad_len { block_size - (data_size % block_size) };
        padding::add_padding<block_size>(buffer.first(data_size), buffer.first(data_size + pad_len), padding_type_);
        return data_size + pad_len;
    }

    void encrypt_chunk(std::span<const std::byte> src, std::span<std::byte> dst,
                       std::vector<std::byte>& iv, bool is_last)
    {
        mode_.encrypt_blocks(src, dst, iv);
        if (!is_last && !iv.empty())
        {
            std::ranges::copy(dst.last(block_size), iv.begin());
        }
    }

    void decrypt_chunk(std::span<const std::byte> src, std::span<std::byte> dst,
                       std::vector<std::byte>& iv, bool is_last)
    {
        std::vector<std::byte> next_iv;
        if (!is_last && !iv.empty())
        {
            next_iv.assign_range(src.last(block_size));
        }

        mode_.decrypt_blocks(src, dst, iv);

        if (!is_last)
        {
            iv = std::move(next_iv);
        }
    }

    std::span<std::byte> unpad_last_chunk(std::span<std::byte> decrypted)
    {
        if (decrypted.size() < block_size) 
            throw std::runtime_error("Corrupted ciphertext: too short");

        auto last_block { decrypted.last(block_size) };

        auto result { padding::remove_padding<block_size>(last_block, padding_type_) };
        if (!result)
        {
            throw std::runtime_error("Corrupted ciphertext: Invalid padding");
        }

        const size_t pad_len { block_size - result->size() };

        return decrypted.first(decrypted.size() - pad_len);
    }

    void encrypt_stream(std::ifstream& in, std::ofstream& out)
    {
        std::vector<std::byte> input(buffer_size + block_size);
        std::vector<std::byte> output(buffer_size + block_size);
        std::vector<std::byte> iv { iv_ };

        while (in)
        {
            size_t size { read_chunk(in, std::span<std::byte>{input}.first(buffer_size)) };
            if (size == 0) break;

            const bool is_last { at_eof(in) };
            if (is_last)
            {
                size = pad_last_chunk(input, size);
            }

            auto dst { std::span<std::byte>{output}.first(size) };
            encrypt_chunk(std::span<const std::byte>{input}.first(size), dst, iv, is_last);
            write_chunk(out, dst);
        }
    }

    void decrypt_stream(std::ifstream& in, std::ofstream& out)
    {
        std::vector<std::byte> input(buffer_size);
        std::vector<std::byte> output(buffer_size);
        std::vector<std::byte> iv { iv_ };

        while (in)
        {
            const size_t size { read_chunk(in, input) };
            if (size == 0) break;

            check_ciphertext_size(size);
            const bool is_last { at_eof(in) };

            auto dst { std::span<std::byte>{output}.first(size) };
            decrypt_chunk(std::span<const std::byte>{input}.first(size), dst, iv, is_last);

            if (is_last)
            {
                dst = unpad_last_chunk(dst);
            }
            write_chunk(out, dst);
        }
    }

    void process_file(const std::filesystem::path& input_path,
                      const std::filesystem::path& output_path,
                      CryptoOp op)
    {
        auto in  { open_input(input_path) };
        auto out { open_output(output_path) };

        if (op == CryptoOp::Encrypt) encrypt_stream(in, out);
        else decrypt_stream(in, out);

        if (in.bad())
        {
            throw std::runtime_error(std::format("Read error: {}", input_path.string()));
        }
        
        out.flush();
        if (!out)
        {
            throw std::runtime_error(std::format("Failed to flush output file: {}", output_path.string()));
        }
    }

    size_t encrypt_span(std::span<const std::byte> input, std::span<std::byte> output)
    {
        if (input.empty()) return 0;

        const size_t pad_len { block_size - (input.size() % block_size) };
        const size_t required { input.size() + pad_len };

        if (output.size() < required)
        {
            throw std::length_error(std::format("Output buffer too small: need {}, got {}",
                                                required, output.size()));
        }

        std::ranges::copy(input, output.begin());

        padding::add_padding<block_size>(output.first(input.size()), output.first(required), padding_type_);

        mode_.encrypt_blocks(output.first(required), output.first(required), iv_);

        return required;
    }

    size_t decrypt_span(std::span<const std::byte> input, std::span<std::byte> output)
    {
        if (input.empty()) return 0;
        check_ciphertext_size(input.size());

        if (output.size() < input.size())
        {
            throw std::length_error(std::format("Output buffer too small: need {}, got {}",
                                                input.size(), output.size()));
        }

        mode_.decrypt_blocks(input, output.first(input.size()), iv_);

        auto valid_data { unpad_last_chunk(output.first(input.size())) };
        return valid_data.size();
    }
};


} // namespace shared