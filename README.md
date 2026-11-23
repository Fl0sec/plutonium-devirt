# plutonium-devirt

Companion code for [Inside the Plutonium Bootstrapper: Four Themida VMs and a Silent Integrity Check](https://www.fl0sec.com/research/plutonium-bootstrapper-themida), a write-up on the Themida-protected Plutonium bootstrapper r5354.
Each program turns one finding into a small check you can run yourself. Everything is static parsing of the
file or replay of recorded numbers; nothing loads, runs or attaches to the target.

## Input

Bring your own `plutonium-bootstrapper-win32.exe`, build r5354:

```
SHA-256  6c405bec03a89b8d954d8ae5edea1bed89b4147f53e4dbe68ced6ef5a815a96b
```

The programs print the hash of the file they read and say when it is not r5354. No binary is included here.

## Build

C++20, CMake 3.25+. Tested with MSVC (Visual Studio 2026, x64), `/W4` clean.

```
cmake -S . -B build
cmake --build build --config Release
```

## Programs

| Program | Run | Shows |
|---|---|---|
| `integrity_hash` | `integrity_hash <exe>` | the protector's `.main` self-checksum, recomputed from the file |
| `vjcc_vmd` | `vjcc_vmd <exe>` | VM-D's virtual conditional jump, checked against 496,110 recorded executions |
| `main_prefix` | `main_prefix` | the devirtualized start of `plutonium::main`, replayed, and its opaque predicate |
| `handler_stats` | `handler_stats <exe>` | handler counts of the four VMs, read from their tables |

Captured output of each run is in `docs/outputs/`.

### integrity_hash

Reproduces stage 0 in C++: the aPLib blob at `0x140D91EF` in `.boot` depacks into the 0x1162000-byte `.themida`
region. The result is byte-identical to the Python reference unpacker, which itself agrees with an emulation of the
stage-0 code (`docs/outputs/stage0_crosscheck.txt`).

At run time a protector routine copies `.main` into a fresh 0x623000-byte buffer and folds it:

```c
for (h = 0, i = 0; i < 0x623000 / 4; i++) h = rol32(h + p[i], 16) ^ p[i];
```

The expected value sits at `0x13B949BB` in the depacked `.themida`. The image has no relocations and `.main`'s raw size
equals the copy length, so the file bytes are exactly what gets hashed. Result: `0x8A6116A2` computed, `0x8A6116A2`
stored, MATCH. Flipping one bit in a private copy changes the hash; the file is never written.

### vjcc_vmd

VM-D handler `vmd_078` reads an operand at VIP, tests a condition code against a flags word in a context slot, writes
the outcome to context `+0xBF` and moves VIP to one of two successors. The program implements the 16-entry condition map
and the handler, reads every operand from the reader's own depacked `.themida`, and replays `data/vmd_vjcc_observed.csv`.

Result over 496,110 executions at 241 VIPs: operand fields, both successor VIPs, the taken outcome and the next VIP all
match, 0 mismatches. The map also agrees with x86 Jcc semantics on all 32 flag combinations. Only je, jne, jae, jb and jbe
occur in the recorded run; the other eleven codes come from the handler disassembly alone.

### main_prefix

The first lifted lines of `plutonium::main`:

```c
srand((uint32_t)_time64(NULL) ^ ~(GetTickCount() * GetCurrentProcessId()));
q1 = rand() / 426315782;
q2 = rand() / 412255378;
```

With the recorded native results (`data/main_prefix_natives.txt`) the explicit MSVC LCG gives seed `0x9B0F4539` and
`rand()` values `0xD06`, `0xAEC`, as recorded. Both quotients are 0 for every input: `rand()` never exceeds 0x7FFF and
both divisors are above 4 * 10^8. The program checks 1,000,000 random inputs and all 2^32 seeds.

### handler_stats

Each handler table is an array of RVAs to `E9` thunks. Walking a table until the first entry that is not a thunk gives
A 847, B 1494, C 1322, D 498, the same counts as the run-time relocation pass.

## Data

- `data/vmd_vjcc_observed.csv`: 321 unique `(vip, flags, taken)` rows with counts, reduced from one offline emulator run
  of stage 1 by `tools/derive_vjcc_dataset.py`. The raw trace is not included.
- `data/main_prefix_natives.txt`: the six recorded values used by `main_prefix`.

Not included: the target binary, databases, dumps, raw traces, and anything about the application's own checks beyond
the protector mechanics above.
