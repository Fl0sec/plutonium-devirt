// main_prefix: the devirtualized prefix of plutonium::main (VM-A outer ops 51-484) as plain C++.
//
// Lifted from the VM and proved equal with z3 on the rebased definitions:
//     t = _time64(NULL); tick = GetTickCount(); pid = GetCurrentProcessId();
//     srand((uint32_t)t ^ ~(tick * pid));
//     q1 = rand() / 426315782;  q2 = rand() / 412255378;      // quotients unused afterwards
// The two divisions are opaque constants: rand() never exceeds 0x7FFF, both divisors are far above it.
//
// usage: main_prefix [main_prefix_natives.txt]

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>

namespace {

// MSVC CRT rand()/srand(): per-thread LCG, 15-bit output. Spelled out so the replay is reproducible
// on any compiler and C library.
struct MsvcRand {
    std::uint32_t holdrand = 1;
    void srand(std::uint32_t seed) { holdrand = seed; }
    int rand() {
        holdrand = holdrand * 214013u + 2531011u;
        return static_cast<int>((holdrand >> 16) & 0x7FFF);
    }
};

constexpr int kDivisor1 = 426315782;  // op 354
constexpr int kDivisor2 = 412255378;  // op 484
constexpr int kRandMax = 0x7FFF;

struct Prefix {
    std::uint32_t seed;
    int r1, q1, r2, q2;
};

Prefix main_prefix(std::int64_t t, std::uint32_t tick, std::uint32_t pid) {
    Prefix p{};
    p.seed = static_cast<std::uint32_t>(t) ^ ~(tick * pid);
    MsvcRand crt;
    crt.srand(p.seed);
    p.r1 = crt.rand();
    p.q1 = p.r1 / kDivisor1;  // signed division (cdq; idiv)
    p.r2 = crt.rand();
    p.q2 = p.r2 / kDivisor2;
    return p;
}

std::map<std::string, std::uint32_t> load_natives(const std::filesystem::path& p) {
    std::ifstream f(p);
    if (!f) throw std::runtime_error("cannot open " + p.filename().string());
    std::map<std::string, std::uint32_t> v;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string k, x;
        ss >> k >> x;
        v[k] = static_cast<std::uint32_t>(std::stoul(x, nullptr, 16));
    }
    return v;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::filesystem::path path = argc >= 2 ? std::filesystem::path(argv[1])
                                                     : std::filesystem::path(PDV_DATA_DIR) / "main_prefix_natives.txt";
        auto n = load_natives(path);
        const Prefix p = main_prefix(n.at("time64"), n.at("tick"), n.at("pid"));
        const std::uint32_t mix = ~(n.at("tick") * n.at("pid"));

        std::printf("replay with recorded native results (%s)\n", path.filename().string().c_str());
        std::printf("  _time64             0x%08X\n", n.at("time64"));
        std::printf("  GetTickCount        0x%08X\n", n.at("tick"));
        std::printf("  GetCurrentProcessId 0x%08X\n", n.at("pid"));
        std::printf("  ~(tick * pid)       0x%08X\n", mix);
        const bool seed_ok = p.seed == n.at("srand_seed");
        const bool r_ok = static_cast<std::uint32_t>(p.r1) == n.at("rand1") && static_cast<std::uint32_t>(p.r2) == n.at("rand2");
        std::printf("  srand seed          0x%08X  recorded 0x%08X  %s\n", p.seed, n.at("srand_seed"),
                    seed_ok ? "MATCH" : "MISMATCH");
        std::printf("  rand() #1           0x%04X      recorded 0x%04X      %s\n", p.r1, n.at("rand1"),
                    static_cast<std::uint32_t>(p.r1) == n.at("rand1") ? "MATCH" : "MISMATCH");
        std::printf("  q1 = r1 / %d  = %d\n", kDivisor1, p.q1);
        std::printf("  rand() #2           0x%04X      recorded 0x%04X      %s\n", p.r2, n.at("rand2"),
                    static_cast<std::uint32_t>(p.r2) == n.at("rand2") ? "MATCH" : "MISMATCH");
        std::printf("  q2 = r2 / %d  = %d\n", kDivisor2, p.q2);

        // Opaque predicate: the quotient is 0 for every seed.
        std::printf("\nwhy q1 = q2 = 0 always: 0 <= rand() <= 0x%X = %d, divisors 0x%08X and 0x%08X (%dx and %dx "
                    "larger)\n",
                    kRandMax, kRandMax, kDivisor1, kDivisor2, kDivisor1 / kRandMax, kDivisor2 / kRandMax);

        std::mt19937_64 gen(5354);
        std::uint64_t nonzero = 0;
        int max_r = 0;
        for (int i = 0; i < 1'000'000; ++i) {
            const auto x = gen();
            const Prefix s = main_prefix(static_cast<std::int64_t>(x), static_cast<std::uint32_t>(x >> 32),
                                         static_cast<std::uint32_t>(x >> 17));
            nonzero += (s.q1 != 0) + (s.q2 != 0);
            max_r = std::max({max_r, s.r1, s.r2});
        }
        std::printf("random inputs (t, tick, pid) x 1,000,000: nonzero quotients %llu, max rand() 0x%X\n",
                    static_cast<unsigned long long>(nonzero), max_r);

        // Every 32-bit seed, which covers every (t, tick, pid) since only the seed reaches rand().
        std::uint64_t nonzero_all = 0;
        int max_all = 0;
        for (std::uint64_t s = 0; s <= 0xFFFFFFFFull; ++s) {
            MsvcRand crt;
            crt.srand(static_cast<std::uint32_t>(s));
            const int a = crt.rand(), b = crt.rand();
            nonzero_all += (a / kDivisor1 != 0) + (b / kDivisor2 != 0);
            max_all = std::max({max_all, a, b});
        }
        std::printf("all 2^32 seeds:                         nonzero quotients %llu, max rand() 0x%X\n",
                    static_cast<unsigned long long>(nonzero_all), max_all);

        const bool ok = seed_ok && r_ok && p.q1 == 0 && p.q2 == 0 && nonzero == 0 && nonzero_all == 0;
        std::printf("\nresult  %s\n", ok ? "MATCH, quotients constant 0" : "MISMATCH");
        return ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
}
