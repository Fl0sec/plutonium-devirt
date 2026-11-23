#include "image.hpp"

#include <cstdio>
#include <stdexcept>

#include "aplib.hpp"
#include "sha256.hpp"

namespace pdv {

std::string hex32(std::uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", v);
    return buf;
}

ProtectedImage open_image(const std::filesystem::path& exe) {
    ProtectedImage img;
    img.pe = load_pe(exe);
    img.input_sha256 = sha256_hex(img.pe.raw);

    const auto& pe = img.pe;
    if (pe.image_base + pe.entry_rva != kEntryVa)
        throw std::runtime_error("entry point is " + hex32(pe.image_base + pe.entry_rva) + ", expected " +
                                 hex32(kEntryVa) + " (not r5354?)");
    const Section& boot = pe.section(".boot");
    const Section& themida = pe.section(".themida");
    if (themida.raw_size != 0) throw std::runtime_error(".themida unexpectedly has file data");
    img.themida_va = img.va(themida);

    // Stage 0 depacks from inside .boot into the (file-less) .themida region.
    img.packed_va = kEntryVa + kPackedOffset;
    const auto boot_raw = pe.raw_data(boot);
    const std::size_t start = img.packed_va - img.va(boot);
    auto res = aplib_depack(boot_raw.subspan(start), themida.virtual_size);
    img.packed_consumed = res.consumed;
    img.depacked_length = res.out.size();
    img.themida = std::move(res.out);
    img.themida.resize(themida.virtual_size, 0);  // the loader maps the region zero-filled
    if (img.u32(img.themida_va + kStage1EntryOffset) == 0)
        throw std::runtime_error("stage-1 guard dword is zero after depacking");
    return img;
}

namespace {
template <class T>
T read_va(const ProtectedImage& img, std::uint32_t va) {
    if (img.in_themida(va)) return load_le<T>(img.themida, va - img.themida_va);
    for (const auto& s : img.pe.sections) {
        const std::uint32_t base = img.pe.image_base + s.rva;
        if (va >= base && va - base + sizeof(T) <= s.raw_size) return load_le<T>(img.pe.raw_data(s), va - base);
    }
    throw std::out_of_range("unmapped VA " + hex32(va));
}
}  // namespace

std::uint8_t ProtectedImage::u8(std::uint32_t v) const { return read_va<std::uint8_t>(*this, v); }
std::uint16_t ProtectedImage::u16(std::uint32_t v) const { return read_va<std::uint16_t>(*this, v); }
std::uint32_t ProtectedImage::u32(std::uint32_t v) const { return read_va<std::uint32_t>(*this, v); }

}  // namespace pdv
