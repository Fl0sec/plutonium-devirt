#pragma once
#include <cstdint>
#include <span>
#include <string>

namespace pdv {

// Plain FIPS 180-4 SHA-256, used only to identify the input file and the depacked region.
std::string sha256_hex(std::span<const std::uint8_t> data);

}  // namespace pdv
