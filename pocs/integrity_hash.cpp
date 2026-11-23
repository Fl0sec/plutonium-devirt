// integrity_hash: recompute the protector's .main self-checksum statically and compare it with the
// value stage 0 depacks into .themida.
//
// At run time a protector routine (0x132B2E5F) allocates 0x623000 bytes, copies .main into it, folds it
// dword by dword with h = rol32(h + d, 16) ^ d starting from h = 0, frees the buffer and hands h to a
// VM-C compare against the dword at 0x13B949BB. That dword is written only by the stage-0 depacker.
//
// usage: integrity_hash <plutonium-bootstrapper-win32.exe> [--dump-stage1 <out.bin>]

#include <bit>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <span>
#include <vector>

#include "image.hpp"
#include "sha256.hpp"

namespace {

constexpr std::uint32_t kStoredChecksumVa = 0x13B949BB;  // packed expected value, inside .themida
constexpr std::uint32_t kHashedBytes = 0x623000;         // VirtualAlloc size and memcpy length

std::uint32_t main_checksum(std::span<const std::uint8_t> buf) {
    std::uint32_t h = 0;
    for (std::size_t i = 0; i + 4 <= buf.size(); i += 4) {
        std::uint32_t d;
        std::memcpy(&d, buf.data() + i, 4);
        h = std::rotl(h + d, 16) ^ d;
    }
    return h;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: integrity_hash <plutonium-bootstrapper-win32.exe> [--dump-stage1 <out.bin>]\n");
        return 2;
    }
    try {
        const std::filesystem::path exe = argv[1];
        const pdv::ProtectedImage img = pdv::open_image(exe);
        const bool known = img.input_sha256 == pdv::kInputSha256;
        std::printf("input            %s\n", exe.filename().string().c_str());
        std::printf("input sha256     %s (%s)\n", img.input_sha256.c_str(), known ? "r5354" : "UNKNOWN BUILD");

        // Stage 0, reproduced: aPLib-depack the blob in .boot into the .themida region.
        const std::string depacked_sha = pdv::sha256_hex(img.themida);
        std::printf("stage-0 blob     %s in .boot, %zu packed bytes consumed\n", pdv::hex32(img.packed_va).c_str(),
                    img.packed_consumed);
        std::printf("depacked         %zu bytes -> .themida %s (virtual size 0x%zX)\n", img.depacked_length,
                    pdv::hex32(img.themida_va).c_str(), img.themida.size());
        std::printf(".themida sha256  %s (%s)\n", depacked_sha.c_str(),
                    depacked_sha == pdv::kStage1Sha256 ? "matches the Python reference unpacker" : "DIFFERS");
        if (argc >= 4 && std::strcmp(argv[2], "--dump-stage1") == 0) {
            std::ofstream(argv[3], std::ios::binary)
                .write(reinterpret_cast<const char*>(img.themida.data()), static_cast<std::streamsize>(img.themida.size()));
            std::printf("dumped           .themida region to %s\n", std::filesystem::path(argv[3]).filename().string().c_str());
        }

        // The expected value lives in depacked protector data.
        const std::uint32_t stored = img.u32(kStoredChecksumVa);
        std::printf("\nstored checksum  [%s] = %s\n", pdv::hex32(kStoredChecksumVa).c_str(), pdv::hex32(stored).c_str());

        // The hashed bytes: .main as the loader maps it. The image has no relocation directory and
        // .main's raw size equals the copy length, so the file bytes are exactly the mapped bytes.
        const pdv::Section& main_sec = img.pe.section(".main");
        std::printf("hashed range     .main %s, 0x%X bytes (file offset 0x%X, raw size 0x%X, virtual size 0x%X, "
                    "relocations: %s)\n",
                    pdv::hex32(img.va(main_sec)).c_str(), kHashedBytes, main_sec.raw_offset, main_sec.raw_size,
                    main_sec.virtual_size, img.pe.reloc_dir_size ? "present" : "none");
        if (main_sec.raw_size < kHashedBytes) throw std::runtime_error(".main raw data shorter than the hashed range");
        const auto main_bytes = img.pe.raw_data(main_sec).first(kHashedBytes);

        const std::uint32_t h = main_checksum(main_bytes);
        std::printf("computed         %s   h = rol32(h + d, 16) ^ d over %u dwords, h0 = 0\n", pdv::hex32(h).c_str(),
                    kHashedBytes / 4);
        std::printf("result           %s\n", h == stored ? "MATCH" : "MISMATCH");

        // Tamper demo on an in-memory copy; the input file is never written.
        std::printf("\none-bit changes in a private copy of .main (file untouched):\n");
        std::vector<std::uint8_t> copy(main_bytes.begin(), main_bytes.end());
        for (const std::uint32_t off : {0x0u, 0x1000u, 0x31B7A2u, kHashedBytes - 1}) {
            copy[off] ^= 0x01;
            const std::uint32_t h2 = main_checksum(copy);
            copy[off] ^= 0x01;
            std::printf("  .main+0x%06X ^= 0x01  -> %s  %s\n", off, pdv::hex32(h2).c_str(),
                        h2 == stored ? "MATCH" : "MISMATCH");
        }
        std::printf("  restored copy          -> %s  %s\n", pdv::hex32(main_checksum(copy)).c_str(),
                    main_checksum(copy) == stored ? "MATCH" : "MISMATCH");
        return h == stored ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
}
