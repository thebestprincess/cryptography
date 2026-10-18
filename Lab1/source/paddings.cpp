#include "paddings.hpp"

#include <string_view>

namespace shared::padding
{

std::string_view get_padding_name(CipherPadding padding_type)
{
    switch (padding_type)
    {
        case CipherPadding::Zeros: return "Zeros";
        case CipherPadding::ANSI_X923: return "ANSI_X923";
        case CipherPadding::PKCS7: return "PKCS7";
        case CipherPadding::ISO_10126: return "ISO_10126";
        default: return "Unknown";
    }
}

} // namespace shared::padding