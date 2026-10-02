#include "CipherContext.hpp"
#include "DES.hpp"
#include "cipher_modes.hpp"
#include "constants.hpp"
#include "paddings.hpp"
#include "DEAL.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <random>
#include <ranges>
#include <span>
#include <string_view>
#include <vector>


namespace test_utils 
{

[[nodiscard]]
std::vector<std::byte> generate_random_bytes(size_t size)
{
    std::mt19937_64 engine{std::random_device{}()};
    std::uniform_int_distribution<unsigned short> dist(0, 255);
    
    std::vector<std::byte> buffer(size);
    for (auto& b : buffer)
    {
        b = static_cast<std::byte>(dist(engine));
    }
    return buffer;
}

[[nodiscard]]
bool compare_files(
    const std::filesystem::path& file1, 
    const std::filesystem::path& file2
) {
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1 || !f2) return false;

    const size_t buffer_size { constants::BUFFER_SIZE };
    std::vector<std::byte> buff1(buffer_size); 
    std::vector<std::byte> buff2(buffer_size); 

    while (f1 && f2)
    {
        f1.read(reinterpret_cast<char*>(buff1.data()), buffer_size);
        f2.read(reinterpret_cast<char*>(buff2.data()), buffer_size);

        if (f1.gcount() != f2.gcount()) return false;

        size_t count { static_cast<size_t>(f1.gcount()) };
        if (!std::ranges::equal(std::span{buff1}.first(count), std::span{buff2}.first(count)))
        {
            return false;
        }
    }

    return true;
} 

void print_vec(
    std::ranges::sized_range auto& vec,
    std::string_view vec_name
) {
    std::print("{}: [", vec_name);

    const size_t size { vec.size() };
    for (size_t i { 0 }; i < size - 1; ++i)
    {
        std::print("{}, ", static_cast<int>(vec[i]));
    }
    std::println("{}]", static_cast<int>(vec[size - 1]));
}

} // namespace test_utils


namespace tests 
{

template<typename Mode>
void test_in_memory(
    std::span<const std::byte> key, 
    std::span<const std::byte> iv, 
    shared::padding::CipherPadding padding
) {
    auto plaintext { test_utils::generate_random_bytes(9) };
    std::vector<std::byte> ciphertext(16);
    std::vector<std::byte> decrypted(16);

    shared::CipherContext<Mode> context(key, padding, iv);

    size_t enc_size { context.async_encrypt(plaintext, ciphertext).get() };
    ciphertext.resize(enc_size);

    size_t dec_size { context.async_decrypt(ciphertext, decrypted).get() };
    decrypted.resize(dec_size);

    std::println("Mode: {}", Mode::string());

    if (std::ranges::equal(plaintext, decrypted))
    {
        std::println("In-memory test: SUCCESS");
    }
    else
    {
        std::println(stderr, "In-memory test: FAILED");
        std::println("Additional info about error: ");
        test_utils::print_vec(plaintext, "plaintext");
        test_utils::print_vec(ciphertext, "ciphertext");
        test_utils::print_vec(decrypted, "decrypted");
        std::println("Padding type: {}", shared::padding::get_padding_name(padding));
    }
}

template<typename Mode>
void test_file_io(
    const std::filesystem::path& input_path,
    std::span<const std::byte> key, 
    std::span<const std::byte> iv, 
    shared::padding::CipherPadding padding,
    std::string_view cipher
) {
    auto encrypted_path { input_path };
    encrypted_path.replace_extension(std::format(".enc", cipher));

    auto decrypted_path { input_path };
    decrypted_path.replace_extension(std::format(".dec", cipher));

    shared::CipherContext<Mode> context(key, padding, iv);

    context.process_file_async(input_path, encrypted_path, shared::CryptoOp::Encrypt).get();
    context.process_file_async(encrypted_path, decrypted_path, shared::CryptoOp::Decrypt).get();

    if (test_utils::compare_files(input_path, decrypted_path))
        std::println("File test {}: SUCCESS", input_path.string());
    else
        std::println(stderr, "File test {}: FAILED", input_path.string());
    
    if (std::filesystem::exists(encrypted_path))
    {
        std::filesystem::remove(encrypted_path);
    }
    if (std::filesystem::exists(decrypted_path))
    {
        std::filesystem::remove(decrypted_path);
    }
}

} // namespace tests


int main()
{
    using namespace shared;
    try 
    {
        const auto master_key { test_utils::generate_random_bytes(8) };
        const auto iv { test_utils::generate_random_bytes(8) };

        std::println("In-memory tests:");
        tests::test_in_memory<mode::ECB<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::ECB<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);

        tests::test_in_memory<mode::ECB<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::ECB<Des>>(master_key, iv, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::CBC<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CBC<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CBC<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CBC<Des>>(master_key, iv, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::PCBC<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::PCBC<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::PCBC<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::PCBC<Des>>(master_key, iv, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::OFB<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::OFB<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::OFB<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::OFB<Des>>(master_key, iv, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::CFB<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CFB<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CFB<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CFB<Des>>(master_key, iv, padding::CipherPadding::PKCS7);
        
        tests::test_in_memory<mode::CTR<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CTR<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CTR<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CTR<Des>>(master_key, iv, padding::CipherPadding::PKCS7);
        
        tests::test_in_memory<mode::RandomDelta<Des>>(master_key, iv, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::RandomDelta<Des>>(master_key, iv, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::RandomDelta<Des>>(master_key, iv, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::RandomDelta<Des>>(master_key, iv, padding::CipherPadding::PKCS7);


        const auto master_key_deal { test_utils::generate_random_bytes(16) };
        const auto iv_deal { test_utils::generate_random_bytes(16) };
        
        tests::test_in_memory<mode::ECB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::ECB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);

        tests::test_in_memory<mode::ECB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::ECB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::CBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::PCBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::PCBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::PCBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::PCBC<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::OFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::OFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::OFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::OFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::CFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CFB<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::CTR<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::CTR<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::CTR<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::CTR<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);

        tests::test_in_memory<mode::RandomDelta<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::Zeros);
        tests::test_in_memory<mode::RandomDelta<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ANSI_X923);
        tests::test_in_memory<mode::RandomDelta<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::ISO_10126);
        tests::test_in_memory<mode::RandomDelta<Deal>>(master_key_deal, iv_deal, padding::CipherPadding::PKCS7);


        std::vector<std::filesystem::path> test_files {
            "./test_data/tests.txt",
            "../test_data/animegirl.jpg",
            "./test_data/amogus.mp3",
            "./test_data/screencast.mp4"
        };

        for (const auto& file : test_files) 
        {
            if (!std::filesystem::exists(file))
            {
                std::println(stderr, "File {} doesn't exist. Skip...", file.string());
                continue;
            }

            tests::test_file_io<mode::CTR<Des>>(
                file, master_key, iv, padding::CipherPadding::PKCS7, "des");
            tests::test_file_io<mode::CTR<Deal>>(
                file, master_key_deal, iv_deal, padding::CipherPadding::PKCS7, "deal");
        }
    }
    catch (const std::exception& e) 
    {
        std::println(stderr, "Critical error: {}", e.what());
        return 1;
    }

    return 0;
}

