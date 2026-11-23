#include "pe.hpp"

#include <fstream>
#include <stdexcept>

namespace pdv {

const Section& PeFile::section(std::string_view name) const {
    for (const auto& s : sections)
        if (s.name == name) return s;
    throw std::runtime_error("section not found: " + std::string(name));
}

std::span<const std::uint8_t> PeFile::raw_data(const Section& s) const {
    if (std::size_t{s.raw_offset} + s.raw_size > raw.size()) throw std::runtime_error("section past end of file");
    return {raw.data() + s.raw_offset, s.raw_size};
}

PeFile load_pe(const std::filesystem::path& path) {
    PeFile pe;
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open input file");
    pe.raw.assign(std::istreambuf_iterator<char>(f), {});
    const std::span<const std::uint8_t> b(pe.raw);

    if (load_le<std::uint16_t>(b, 0) != 0x5A4D) throw std::runtime_error("no MZ header");
    const std::uint32_t nt = load_le<std::uint32_t>(b, 0x3C);
    if (load_le<std::uint32_t>(b, nt) != 0x00004550) throw std::runtime_error("no PE signature");
    const std::uint16_t nsec = load_le<std::uint16_t>(b, nt + 6);
    const std::uint16_t opt_size = load_le<std::uint16_t>(b, nt + 20);
    const std::uint32_t opt = nt + 24;
    if (load_le<std::uint16_t>(b, opt) != 0x10B) throw std::runtime_error("not a PE32 image");
    pe.entry_rva = load_le<std::uint32_t>(b, opt + 16);
    pe.image_base = load_le<std::uint32_t>(b, opt + 28);
    pe.reloc_dir_size = load_le<std::uint32_t>(b, opt + 96 + 5 * 8 + 4);  // data directory 5 (base relocations)

    std::uint32_t sh = opt + opt_size;
    for (std::uint16_t i = 0; i < nsec; ++i, sh += 40) {
        Section s;
        const char* n = reinterpret_cast<const char*>(pe.raw.data() + sh);
        s.name.assign(n, strnlen(n, 8));
        s.virtual_size = load_le<std::uint32_t>(b, sh + 8);
        s.rva = load_le<std::uint32_t>(b, sh + 12);
        s.raw_size = load_le<std::uint32_t>(b, sh + 16);
        s.raw_offset = load_le<std::uint32_t>(b, sh + 20);
        s.characteristics = load_le<std::uint32_t>(b, sh + 36);
        pe.sections.push_back(std::move(s));
    }
    return pe;
}

}  // namespace pdv
