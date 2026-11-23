#pragma once
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "pe.hpp"

namespace pdv {

// Constants of plutonium-bootstrapper-win32.exe r5354.
inline constexpr char kInputSha256[] = "6c405bec03a89b8d954d8ae5edea1bed89b4147f53e4dbe68ced6ef5a815a96b";
inline constexpr char kStage1Sha256[] = "826d7af65dcb00ba160cd06abfa0503f84b51638479523af7c528cfb80e3f9f2";
inline constexpr std::uint32_t kEntryVa = 0x140D9058;     // PE entry, in .boot
inline constexpr std::uint32_t kPackedOffset = 0x197;     // packed blob = entry + 5 + 0x192 (call/pop delta)
inline constexpr std::uint32_t kStage1EntryOffset = 0xCCA4C2;  // stage-0 jumps to .themida + this

// Static view of the image as stage 0 leaves it: every section from the file, .themida replaced by
// the aPLib-depacked bytes. Nothing is loaded or executed.
struct ProtectedImage {
    PeFile pe;
    std::string input_sha256;
    std::uint32_t themida_va = 0;
    std::uint32_t packed_va = 0;
    std::size_t packed_consumed = 0;
    std::size_t depacked_length = 0;
    std::vector<std::uint8_t> themida;  // full .themida virtual region (depacked data + zero tail)

    std::uint32_t va(const Section& s) const { return pe.image_base + s.rva; }
    bool in_themida(std::uint32_t va) const { return va >= themida_va && va - themida_va < themida.size(); }
    std::uint8_t u8(std::uint32_t va) const;
    std::uint16_t u16(std::uint32_t va) const;
    std::uint32_t u32(std::uint32_t va) const;
};

// Throws std::runtime_error if the file is not the expected sample layout.
ProtectedImage open_image(const std::filesystem::path& exe);

std::string hex32(std::uint32_t v);

}  // namespace pdv
