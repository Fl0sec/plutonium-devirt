#pragma once
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pdv {

struct Section {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
};

// Minimal PE32 view: headers and section table, nothing is mapped or executed.
struct PeFile {
    std::vector<std::uint8_t> raw;
    std::uint32_t image_base = 0;
    std::uint32_t entry_rva = 0;
    std::uint32_t reloc_dir_size = 0;
    std::vector<Section> sections;

    const Section& section(std::string_view name) const;
    std::span<const std::uint8_t> raw_data(const Section& s) const;
};

PeFile load_pe(const std::filesystem::path& path);

template <class T>
T load_le(std::span<const std::uint8_t> buf, std::size_t off) {
    T v{};
    if (off + sizeof(T) > buf.size()) throw std::out_of_range("load_le past end");
    std::memcpy(&v, buf.data() + off, sizeof(T));
    return v;  // x86/x64 host: little-endian
}

}  // namespace pdv
