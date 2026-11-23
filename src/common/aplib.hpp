#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pdv {

struct DepackResult {
    std::vector<std::uint8_t> out;
    std::size_t consumed = 0;  // packed bytes read, including the end marker
};

// Standard aPLib decompression (the variant Themida's stage 0 inlines). Throws std::runtime_error on
// a read past the input, a match offset before the start of the output, or output above max_out.
DepackResult aplib_depack(std::span<const std::uint8_t> src, std::size_t max_out);

}  // namespace pdv
