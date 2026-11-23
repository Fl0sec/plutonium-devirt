// handler_stats: count the handlers of the four Themida VMs statically.
//
// Each handler table is an array of RVAs (the protector adds the image base at run time). Every entry
// points to an E9 jmp thunk in .themida, and the thunk jumps to the handler body. Walking a table until
// the first entry that is not such a thunk gives the handler count without running anything.
//
// usage: handler_stats <plutonium-bootstrapper-win32.exe>

#include <cstdio>
#include <exception>
#include <set>

#include "image.hpp"

namespace {

struct Machine {
    char name;
    std::uint32_t context;
    std::uint32_t table;
    std::uint32_t expected;  // count from the run-time table relocation pass
};

constexpr Machine kMachines[] = {
    {'A', 0x12FBF0E0, 0x1302A7E0, 847},
    {'B', 0x130483F3, 0x132671D4, 1494},
    {'C', 0x1326C1AB, 0x134075E7, 1322},
    {'D', 0x13239763, 0x1344F7C8, 498},
};

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: handler_stats <plutonium-bootstrapper-win32.exe>\n");
        return 2;
    }
    try {
        const pdv::ProtectedImage img = pdv::open_image(argv[1]);
        std::printf("input sha256  %s (%s)\n\n", img.input_sha256.c_str(),
                    img.input_sha256 == pdv::kInputSha256 ? "r5354" : "UNKNOWN BUILD");
        std::printf("VM  context     table       handlers  distinct bodies  expected  result\n");
        bool all = true;
        for (const auto& m : kMachines) {
            std::uint32_t n = 0;
            std::set<std::uint32_t> bodies;
            for (;; ++n) {
                const std::uint32_t thunk = img.u32(m.table + 4 * n) + img.pe.image_base;
                if (!img.in_themida(thunk) || img.u8(thunk) != 0xE9) break;
                bodies.insert(thunk + 5 + img.u32(thunk + 1));
            }
            const bool ok = n == m.expected;
            all = all && ok;
            std::printf("%c   %s  %s  %8u  %15zu  %8u  %s\n", m.name, pdv::hex32(m.context).c_str(),
                        pdv::hex32(m.table).c_str(), n, bodies.size(), m.expected, ok ? "MATCH" : "MISMATCH");
        }
        return all ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
}
