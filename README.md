# maldev

Malware-development research repository: a growing collection of experimental projects, notes, and proof-of-concept code used for study in isolated, authorized lab environments.

> **Status:** early / work in progress. Descriptions marked `TODO` are intentionally unverified placeholders — nothing here should be read as a claim about behavior or completeness.

---

## Structure

The layout is intentionally flat: each research topic gets its own top-level folder, and folders are added over time. New directories are appended to the table in [Folders](#folders) as they appear.

```
maldev/
├── advanced_module_stomping/
│   ├── Makefile
│   └── src/
│       ├── help.h
│       └── main.cpp
├── .clangd
├── .gitignore
└── README.md
```

Notes on the layout:

- One top-level directory per topic; keep tooling and build files inside that topic.
- Build artifacts (`dist/`, `build/`, `*.exe`, `*.o`, `*.obj`, …) are ignored — only sources are tracked.
- `.clangd` configures tooling for the MinGW-w64 cross target used by these projects.

## Folders

| Folder | Description | Status |
| --- | --- | --- |
| `advanced_module_stomping/` | TODO: describe the technique/experiment covered here. | In progress |

_This table grows as folders are added._

## Usage

TODO: build and run instructions per folder. Nothing documented yet — do not assume any Makefile target or binary is safe to run outside a lab.

Placeholder workflow once documented:

1. TODO — prerequisites / toolchain.
2. TODO — build command per folder.
3. TODO — how to run and what to observe.

## Contributing / maintaining

- Add a new top-level folder per topic.
- Update the **Structure** tree and **Folders** table in the same commit.
- Never commit credentials, keys, `.env` files, or build output.

## Disclaimer

This repository is for **educational and security-research purposes only**. All code, notes, and experiments are intended exclusively for systems and environments you own or have explicit written authorization to test. Do not use anything here against systems without permission; doing so may be illegal. The author(s) accept no liability for misuse or damage.

No secrets, tokens, or personal data are stored in this repository.
