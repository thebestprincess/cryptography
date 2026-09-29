#include "DES.hpp"
#include "KeyExpander.hpp"
#include "FeistelFunction.hpp"
#include "shared.hpp"
#include "cipher_modes.hpp"
#include "paddings.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <random>
#include <ranges>
#include <vector>
#include <array>

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


TEST(BitPermutationTest, DeterministicMSB1)
{
    std::array<std::byte, 1> input { std::byte{0x80} };
    std::array<uint8_t, 8> pbox { 8, 8, 8, 8, 8, 8, 8, 1 }; 
    
    auto result = shared::permute_bits_to_array<1>(input, pbox, shared::BitOrder::MSB1);
    
    EXPECT_EQ(result[0], std::byte{0x01});
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



class CustomDesTest : public ::testing::Test
{
protected:
    RandomByteGenerator rng;
    using DesCipher = shared::DES<shared::DesKeyExpander, shared::DesEncryptMethod>;

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
        const size_t data_size = blocks_count * DesCipher::BlockSize;
        auto key = rng.make_vector(DesCipher::MasterKeySize);
        auto iv  = rng.make_vector(DesCipher::BlockSize);
        auto plaintext = rng.make_vector(data_size);
        
        std::vector<std::byte> ciphertext(data_size);
        std::vector<std::byte> decrypted(data_size);

        Mode mode;
        mode.set_key(std::span{key}.first<DesCipher::MasterKeySize>());

        ASSERT_NO_THROW({ mode.encrypt_blocks(plaintext, ciphertext, iv); });

        EXPECT_FALSE(std::ranges::equal(plaintext, ciphertext));

        ASSERT_NO_THROW({ mode.decrypt_blocks(ciphertext, decrypted, iv); });

        EXPECT_TRUE(std::ranges::equal(plaintext, decrypted)) 
            << "Decrypted data does not match original plaintext!";
    }
};

TEST_F(CustomDesTest, BasicBlockSymmetry)
{
    DesCipher des;
    auto key = rng.make_vector(DesCipher::MasterKeySize);

    auto plaintext = rng.make_vector(DesCipher::BlockSize);
    std::array<std::byte, DesCipher::BlockSize> ciphertext{};
    std::array<std::byte, DesCipher::BlockSize> decrypted{};

    des.set_key(std::span{key}.first<DesCipher::MasterKeySize>());
    des.encrypt(std::span{plaintext}.first<DesCipher::BlockSize>(), ciphertext);
    des.decrypt(ciphertext, decrypted);

    EXPECT_TRUE(std::ranges::equal(plaintext, decrypted));
}

TEST_F(CustomDesTest, EcbModeTest)
{
    test_mode_symmetry<shared::mode::ECB<DesCipher>>();
}

TEST_F(CustomDesTest, CbcModeTest)
{
    test_mode_symmetry<shared::mode::CBC<DesCipher>>();
}

TEST_F(CustomDesTest, PcbcModeTest)
{
    test_mode_symmetry<shared::mode::PCBC<DesCipher>>();
}

TEST_F(CustomDesTest, CfbModeTest)
{
    test_mode_symmetry<shared::mode::CFB<DesCipher>>();
}

TEST_F(CustomDesTest, OfbModeTest)
{
    test_mode_symmetry<shared::mode::OFB<DesCipher>>();
}

TEST_F(CustomDesTest, CtrModeTest)
{
    test_mode_symmetry<shared::mode::CTR<DesCipher>>();
}