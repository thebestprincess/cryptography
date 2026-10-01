#include "DES.hpp"
#include "constants.hpp"
#include "shared.hpp"
#include "cipher_modes.hpp"
#include "paddings.hpp"
#include "DEAL.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <ranges>
#include <vector>

namespace test::utils
{

class RandomByteGenerator
{
    std::mt19937_64 engine_;
    uint32_t seed_;

public:
    using result_type = uint8_t;    

    explicit RandomByteGenerator(uint32_t seed = std::random_device{}())
        : engine_(seed), seed_(seed) {}

    void reseed(uint32_t seed)
    {
        seed_ = seed;
        engine_.seed(seed);
    }

    [[nodiscard]] uint32_t seed() const { return seed_; }

    template<std::ranges::output_range<std::byte> R>
    void fill(R&& range)
    {
        std::uniform_int_distribution<unsigned short> dist(0, 255);
        std::ranges::generate(
            range,
            [this, &dist]()
            {
                return static_cast<std::byte>(dist(engine_));
            });
    }

    [[nodiscard]] std::vector<std::byte> make_vector(std::size_t size)
    {
        std::vector<std::byte> buffer(size);
        fill(buffer);
        return buffer;
    }
};


[[nodiscard]] bool compare_files(
    const std::filesystem::path& file1, 
    const std::filesystem::path& file2)
{
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


} // namespace test::utils



namespace test
{

TEST(BitPermutationTest, DeterministicMSB1)
{
    std::array<std::byte, 1> input { std::byte{0x80} };
    std::array<uint8_t, 8> pbox { 8, 8, 8, 8, 8, 8, 8, 1 }; 
    
    auto result = shared::permute_bits_to_array<1>(input, pbox, shared::BitOrder::MSB1);
    
    EXPECT_EQ(result[0], std::byte{0x01});
}

TEST(BitPermutationTest, DeterministicMSB0)
{
    std::array<std::byte, 1> input { std::byte{0x80} };
    std::array<uint8_t, 8> pbox { 7, 7, 7, 7, 7, 7, 7, 0 }; 
    
    auto result = shared::permute_bits_to_array<1>(input, pbox, shared::BitOrder::MSB0);
    
    EXPECT_EQ(result[0], std::byte{0x01});
}

TEST(BitPermutationTest, DeterministicLSB1)
{
    std::array<std::byte, 1> input { std::byte{0xF1} };
    std::array<uint8_t, 8> pbox { 5, 6, 8, 7, 1, 2, 3, 4 }; 
    
    auto result = shared::permute_bits_to_array<1>(input, pbox, shared::BitOrder::LSB1);
    
    EXPECT_EQ(result[0], std::byte{0x1F});
}

TEST(BitPermutationTest, DeterministicLSB0)
{
    std::array<std::byte, 1> input { std::byte{0xF1} };
    std::array<uint8_t, 8> pbox { 0, 4, 5, 6, 7, 1, 2, 3 }; 
    
    auto result = shared::permute_bits_to_array<1>(input, pbox, shared::BitOrder::LSB0);
    
    EXPECT_EQ(result[0], std::byte{0x1F});
}




TEST(PaddingTest, PKCS7_AddAndRemove)
{
    std::vector<std::byte> original { std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC} };
    std::vector<std::byte> buffer(8);
    
    shared::padding::add_padding<8>(original, buffer, shared::padding::CipherPadding::PKCS7);
    
    for (size_t i = 3; i < 8; ++i)
    {
        EXPECT_EQ(buffer[i], std::byte{0x05});
    }

    auto unpadded_result = shared::padding::remove_padding<8>(buffer, shared::padding::CipherPadding::PKCS7);
    
    ASSERT_TRUE(unpadded_result.has_value()) << "Padding removal failed (unexpected error)";
    auto unpadded_span = unpadded_result.value();
    
    EXPECT_TRUE(std::ranges::equal(original, unpadded_span));
}

TEST(PaddingTest, PKCS7_InvalidPaddingRejection)
{
    std::vector<std::byte> corrupted
    { 
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, 
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04}, std::byte{0x03}
    };

    auto unpadded_result = shared::padding::remove_padding<8>(corrupted, shared::padding::CipherPadding::PKCS7);
    EXPECT_FALSE(unpadded_result.has_value());
    EXPECT_EQ(unpadded_result.error(), shared::padding::PaddingError::InvalidPadding);
}

TEST(PaddingTest, ANSI_X923_AddAndRemove)
{
    std::vector<std::byte> original { std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC} };
    std::vector<std::byte> buffer(8);
    
    shared::padding::add_padding<8>(original, buffer, shared::padding::CipherPadding::ANSI_X923);
    
    for (size_t i = 3; i < 7; ++i)
    {
        EXPECT_EQ(buffer[i], std::byte{0x00});
    }
    EXPECT_EQ(buffer[7], std::byte{5});

    auto unpadded_result = shared::padding::remove_padding<8>(buffer, shared::padding::CipherPadding::ANSI_X923);
    
    ASSERT_TRUE(unpadded_result.has_value()) << "Padding removal failed (unexpected error)";
    auto unpadded_span = unpadded_result.value();
    
    EXPECT_TRUE(std::ranges::equal(original, unpadded_span));
}

TEST(PaddingTest, ANSI_X923_InvalidPaddingRejection)
{
    std::vector<std::byte> corrupted
    { 
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0x00}, 
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04}, std::byte{0x05}
    };

    auto unpadded_result = shared::padding::remove_padding<8>(corrupted, shared::padding::CipherPadding::ANSI_X923);
    EXPECT_FALSE(unpadded_result.has_value());
    EXPECT_EQ(unpadded_result.error(), shared::padding::PaddingError::InvalidPadding);
}

TEST(PaddingTest, Zeros_AddAndRemove)
{
    std::vector<std::byte> original { std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC} };
    std::vector<std::byte> buffer(8);
    
    shared::padding::add_padding<8>(original, buffer, shared::padding::CipherPadding::Zeros);
    
    for (size_t i = 3; i < 8; ++i)
    {
        EXPECT_EQ(buffer[i], std::byte{0x00});
    }

    auto unpadded_result = shared::padding::remove_padding<8>(buffer, shared::padding::CipherPadding::Zeros);
    
    ASSERT_TRUE(unpadded_result.has_value()) << "Padding removal failed (unexpected error)";
    auto unpadded_span = unpadded_result.value();
    
    EXPECT_TRUE(std::ranges::equal(original, unpadded_span));
}

TEST(PaddingTest, Zeros_InvalidPaddingRejection)
{
    std::vector<std::byte> corrupted1
    { 
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0x00}, 
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}
    };

    auto unpadded_result1 = shared::padding::remove_padding<8>(corrupted1, shared::padding::CipherPadding::Zeros);
    EXPECT_FALSE(unpadded_result1.has_value());
    EXPECT_EQ(unpadded_result1.error(), shared::padding::PaddingError::InvalidPadding);
}

TEST(PaddingTest, ISO_10126_AddAndRemove)
{
    std::vector<std::byte> original { std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC} };
    std::vector<std::byte> buffer(8);
    
    shared::padding::add_padding<8>(original, buffer, shared::padding::CipherPadding::ISO_10126);
    
    EXPECT_EQ(buffer[7], std::byte{0x05});

    auto unpadded_result = shared::padding::remove_padding<8>(buffer, shared::padding::CipherPadding::ISO_10126);
    
    ASSERT_TRUE(unpadded_result.has_value()) << "Padding removal failed (unexpected error)";
    auto unpadded_span = unpadded_result.value();
    
    EXPECT_TRUE(std::ranges::equal(original, unpadded_span));
}

TEST(PaddingTest, ISO_10126_Randomness)
{
    std::vector<std::byte> original { std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC} };

    std::vector<std::byte> buffer1(8);
    shared::padding::add_padding<8>(original, buffer1, shared::padding::CipherPadding::ISO_10126);
    
    std::vector<std::byte> buffer2(8);
    shared::padding::add_padding<8>(original, buffer2, shared::padding::CipherPadding::ISO_10126);

    for (size_t i { 0 }; i < 3; ++i) EXPECT_EQ(buffer1[i], buffer2[i]);
    for (size_t i { 3 }; i < 7; ++i) EXPECT_NE(buffer1[i], buffer2[i]);
    EXPECT_EQ(buffer1[7], buffer2[7]);
}

class CustomDesTest : public ::testing::Test
{
protected:
    utils::RandomByteGenerator rng;

    void SetUp() override
    {
        uint32_t test_seed = static_cast<uint32_t>(::testing::UnitTest::GetInstance()->random_seed());
        if (test_seed == 0) test_seed = std::random_device{}();
        rng.reseed(test_seed);
        RecordProperty("random_seed", test_seed);
    }

    template<typename Mode>
    void test_mode_symmetry(size_t blocks_count = 100)
    {
        const size_t data_size = blocks_count * shared::Des::BlockSize;
        auto key = rng.make_vector(shared::Des::MasterKeySize);
        auto iv = rng.make_vector(shared::Des::BlockSize);
        auto plaintext = rng.make_vector(data_size);
        
        std::vector<std::byte> ciphertext(data_size);
        std::vector<std::byte> decrypted(data_size);

        Mode mode;
        mode.set_key(std::span{key}.first<shared::Des::MasterKeySize>());

        ASSERT_NO_THROW({ mode.encrypt_blocks(plaintext, ciphertext, iv); });

        EXPECT_FALSE(std::ranges::equal(plaintext, ciphertext));

        ASSERT_NO_THROW({ mode.decrypt_blocks(ciphertext, decrypted, iv); });

        EXPECT_TRUE(std::ranges::equal(plaintext, decrypted)) 
            << "Decrypted data does not match original plaintext!";
    }
};

TEST_F(CustomDesTest, BasicBlockSymmetry)
{
    shared::Des des;
    auto key = rng.make_vector(shared::Des::MasterKeySize);

    auto plaintext = rng.make_vector(shared::Des::BlockSize);
    std::array<std::byte, shared::Des::BlockSize> ciphertext{};
    std::array<std::byte, shared::Des::BlockSize> decrypted{};

    des.set_key(std::span{key}.first<shared::Des::MasterKeySize>());
    des.encrypt(std::span{plaintext}.first<shared::Des::BlockSize>(), ciphertext);
    des.decrypt(ciphertext, decrypted);

    EXPECT_TRUE(std::ranges::equal(plaintext, decrypted));
}

TEST_F(CustomDesTest, EcbModeTest)
{
    test_mode_symmetry<shared::mode::ECB<shared::Des>>();
}

TEST_F(CustomDesTest, CbcModeTest)
{
    test_mode_symmetry<shared::mode::CBC<shared::Des>>();
}

TEST_F(CustomDesTest, PcbcModeTest)
{
    test_mode_symmetry<shared::mode::PCBC<shared::Des>>();
}

TEST_F(CustomDesTest, CfbModeTest)
{
    test_mode_symmetry<shared::mode::CFB<shared::Des>>();
}

TEST_F(CustomDesTest, OfbModeTest)
{
    test_mode_symmetry<shared::mode::OFB<shared::Des>>();
}

TEST_F(CustomDesTest, CtrModeTest)
{
    test_mode_symmetry<shared::mode::CTR<shared::Des>>();
}

TEST_F(CustomDesTest, RandomDeltaModeTest)
{
    test_mode_symmetry<shared::mode::RandomDelta<shared::Des, 13>>();
}


class CustomDealTest : public ::testing::Test
{
protected:
    utils::RandomByteGenerator rng;

    void SetUp() override
    {
        uint32_t test_seed = static_cast<uint32_t>(::testing::UnitTest::GetInstance()->random_seed());
        if (test_seed == 0) test_seed = std::random_device{}();
        rng.reseed(test_seed);
        RecordProperty("random_seed", test_seed);
    }

    template<typename Mode>
    void test_mode_symmetry(size_t blocks_count = 100)
    {
        const size_t MasterKeySize { constants::DEAL_MASTER_KEY_SIZE };

        const size_t data_size = blocks_count * shared::Deal::BlockSize;
        auto key = rng.make_vector(MasterKeySize);
        auto iv  = rng.make_vector(shared::Deal::BlockSize);
        auto plaintext = rng.make_vector(data_size);
        
        std::vector<std::byte> ciphertext(data_size);
        std::vector<std::byte> decrypted(data_size);

        Mode mode;
        mode.set_key(std::span{key}.first<MasterKeySize>());

        ASSERT_NO_THROW({ mode.encrypt_blocks(plaintext, ciphertext, iv); });

        EXPECT_FALSE(std::ranges::equal(plaintext, ciphertext));

        ASSERT_NO_THROW({ mode.decrypt_blocks(ciphertext, decrypted, iv); });

        EXPECT_TRUE(std::ranges::equal(plaintext, decrypted)) 
            << "Decrypted data does not match original plaintext!";
    }
};

TEST_F(CustomDealTest, EcbModeTest)
{
    test_mode_symmetry<shared::mode::ECB<shared::Deal>>();
}

TEST_F(CustomDealTest, CbcModeTest)
{
    test_mode_symmetry<shared::mode::CBC<shared::Deal>>();
}

TEST_F(CustomDealTest, PcbcModeTest)
{
    test_mode_symmetry<shared::mode::PCBC<shared::Deal>>();
}

TEST_F(CustomDealTest, CfbModeTest)
{
    test_mode_symmetry<shared::mode::CFB<shared::Deal>>();
}

TEST_F(CustomDealTest, OfbModeTest)
{
    test_mode_symmetry<shared::mode::OFB<shared::Deal>>();
}

TEST_F(CustomDealTest, CtrModeTest)
{
    test_mode_symmetry<shared::mode::CTR<shared::Deal>>();
}

TEST_F(CustomDealTest, RandomDeltaModeTest)
{
    test_mode_symmetry<shared::mode::RandomDelta<shared::Deal, 13>>();
}


}