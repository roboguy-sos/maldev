# maldev

Malware-development research repository: a growing collection of experimental projects, notes, and proof-of-concept code used for study in isolated, authorized lab environments.

> **Status:** work in progress. Descriptions marked `TODO` are intentionally unverified placeholders — nothing here should be read as a claim about behavior or completeness.

---

## Structure

The layout is flat: each research topic gets its own top-level folder containing one solution/project, and folders are added over time. New directories are appended to [Folders](#folders) as they appear.

```
maldev/
├── advanced_module_stomping/          # Makefile + src/
├── APCinjection/                      # .slnx + project/
├── asm/                               # .slnx + project/ (MASM + C++)
├── callbackcodeexecution/
├── EarlybirdAPCinjection/
├── findandhijackthread/
├── IAT_Hiding_Obfuscation/            # + helper .py scripts
├── Local Function Stomping Injection/
├── Local Mapping Injection/
├── ntfunctions/
├── Parsing PE Headers/
├── pinjection/
├── Process Argument Spoofing (1)/
├── regkey/
├── Remote Function Stomping Injection/
├── Remote Mapping Injection/
├── remotethreadhijacking/
├── Spoofing PPID/
├── SystemInformatoin/
├── .clangd
├── .gitignore
└── README.md
```

Conventions and notes:

- One top-level directory per topic, holding its own solution/project files and sources.
- `advanced_module_stomping/` is Makefile-based (MinGW-w64); the rest are MSVC solutions (`.slnx` / `.vcxproj`).
- **Build output is not tracked.** `.gitignore` excludes `.vs/`, `x64/`, `x86/`, `Debug/`, `Release/`, `*.exe`, `*.dll`, `*.sys`, `*.pdb`, `*.obj`, `*.ilk`, `*.idb`, `*.tlog` and related MSVC artifacts.
- Local archives (`*.zip`) are ignored and never published.
- `.clangd` configures tooling for the MinGW-w64 cross target used by the Makefile project.
- Folder names are kept as they were authored, including the `(1)` suffix and the `SystemInformatoin` spelling, so paths stay reproducible.

## Folders

| Folder | Type | Entry point(s) |
| --- | --- | --- |
| `advanced_module_stomping/` | Makefile (MinGW-w64) | `src/main.cpp`, `src/help.h` |
| `APCinjection/` | MSVC solution | `APCinjection/main.cpp` |
| `asm/` | MSVC solution (MASM + C++) | `asm/main.cpp`, `asm/add.asm` |
| `callbackcodeexecution/` | MSVC solution | `callbackcodeexecution/main.cpp` |
| `EarlybirdAPCinjection/` | MSVC solution | `EarlybirdAPCinjection/main.cpp` |
| `findandhijackthread/` | MSVC solution | `findandhijackthread/main.cpp`, `Source.cpp` |
| `IAT_Hiding_Obfuscation/` | MSVC solution (+ Python helpers) | `IAT_Hiding_Obfuscation/main.cpp`, `encrypt_payload.py`, `hashgen.py` |
| `Local Function Stomping Injection/` | MSVC solution | `Local Function Stomping Injection/main.cpp` |
| `Local Mapping Injection/` | MSVC solution | `Local Mapping Injection/main.cpp` |
| `ntfunctions/` | MSVC solution | `ntfunctions/ntfunctions.cpp` |
| `Parsing PE Headers/` | MSVC solution | `Parsing PE Headers/main.cpp` |
| `pinjection/` | MSVC solution | `pinjection/pinjection.cpp` |
| `Process Argument Spoofing (1)/` | MSVC solution | `Process Argument Spoofing (1)/main.cpp` |
| `regkey/` | MSVC solution | `regkey/regkey.cpp` |
| `Remote Function Stomping Injection/` | MSVC solution | `Remote Function Stomping Injection/main.cpp` |
| `Remote Mapping Injection/` | MSVC solution | `Remote Mapping Injection/main.cpp` |
| `remotethreadhijacking/` | MSVC solution | `remotethreadhijacking/hijack.cpp` |
| `Spoofing PPID/` | MSVC solution | `Spoofing PPID/main.cpp` |
| `SystemInformatoin/` | MSVC solution | `SystemInformatoin/sysinfo.cpp` |

Per-project notes and behavior descriptions are **TODO** — this table records only what each folder contains.

## Usage

TODO: build and run instructions are not documented yet. Do not assume any project is safe to build, run, or point at a target outside a disposable lab VM.

Placeholder workflow once documented:

1. TODO — toolchain (MSVC / Windows SDK for the `.slnx` projects; MinGW-w64 for `advanced_module_stomping`).
2. TODO — per-project build command.
3. TODO — how to run and what to observe.

## Contributing / maintaining

- Add a new top-level folder per topic.
- Update the **Structure** tree and **Folders** table in the same commit.
- Never commit credentials, keys, `.env` files, build output, or archives.

## Disclaimer

This repository is for **educational and security-research purposes only**. All code, notes, and experiments are intended exclusively for systems and environments you own or have explicit written authorization to test. Do not use anything here against systems without permission; doing so may be illegal. The author(s) accept no liability for misuse or damage.

No secrets, tokens, or personal data are stored in this repository.
