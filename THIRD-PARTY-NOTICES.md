# Third-party notices

Carthago Watchdog is built from the source in this repository plus the third-party parts
listed here. This file covers what the **Carthago Oracle analyst** runs on. Neither part is
stored in this repository or shipped inside a Carthago binary: `tools/carthago-oracle-fetch.sh`
and `tools/carthago-oracle-fetch.ps1` download both to a folder on the gateway host, pinned to
the versions and SHA-256 hashes below. The fonts embedded in the dashboard and the Go and Rust
libraries the binaries link are listed in `README.md` ("Third-party licences") and in
`backend/go.mod` and `client/Cargo.lock`.

Carthago wrote the Oracle: the behaviour model and its trainer, the case file, the prompts,
the checks on the answer and the runtime control. Carthago did **not** write llama.cpp and did
**not** train the language model below. A studio that later tunes that model on its own
reviewed cases owns the tuned weights it produces, and the base model's licence still applies
to them.

## llama.cpp (inference runtime)

- Project: <https://github.com/ggml-org/llama.cpp>
- Release: `b12360`
- Files fetched:
  - Linux x86-64: `llama-b12360-bin-ubuntu-x64.tar.gz`,
    SHA-256 `b60dc211e4ba206bb04bbc9eb06294364c43d0aab8fc308c44a361477466ba4c`
  - Windows x86-64 (CPU): `llama-b12360-bin-win-cpu-x64.zip`,
    SHA-256 `eae1726047e0eaa707b1302929d196c999b96c2f243b21aea6e93bcebacc4e17`
- Use: the gateway starts its `llama-server` program as a child process on loopback and stops
  it when idle. Unmodified.
- Licence: MIT

```
MIT License

Copyright (c) 2023-2026 The ggml authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The Windows archive also contains the **LLVM OpenMP runtime** (`libomp.dll`), under the Apache
License 2.0 with LLVM Exceptions. Its licence text is the file `LICENSE-LLVM-OpenMP` in the
archive, which the fetch script unpacks next to the program. The Windows archive carries no
copy of the MIT text above; this file is that copy.

## Qwen2.5-1.5B-Instruct, 4-bit GGUF (the analyst's default language model)

- Publisher: Alibaba Cloud (the Qwen team). Copyright 2024 Alibaba Cloud.
- Source: <https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF>, revision
  `91cad51170dc346986eccefdc2dd33a9da36ead9`
- File fetched: `qwen2.5-1.5b-instruct-q4_k_m.gguf`, 1,117,320,736 bytes,
  SHA-256 `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`
- Use: unmodified weights, read by llama.cpp on the gateway host. Never sent to a client.
- Licence: Apache License 2.0, as stated by the publisher for this exact repository and file
  (the `license: apache-2.0` field of its model card and the `LICENSE` file at the revision
  above). The licence allows commercial use. Full text:
  <https://www.apache.org/licenses/LICENSE-2.0>, and the `LICENSE` file in the source
  repository.
- Note: the licence differs between sizes of this model family. Qwen2.5-3B-Instruct is under a
  research licence that does not allow commercial use and was left out for that reason. Check
  the licence of the exact repository, size and file before pointing a bundle at another model.

## Models that were only measured

The analyst benchmark in `docs/oracle.md` also ran these files. They are not fetched, shipped
or needed. They are listed so the measurement can be repeated.

| Model file | Source repository and revision | Licence |
| --- | --- | --- |
| `qwen2.5-0.5b-instruct-q4_k_m.gguf` | `Qwen/Qwen2.5-0.5B-Instruct-GGUF` @ `9217f5db79a29953eb74d5343926648285ec7e67` | Apache-2.0 |
| `granite-3.3-2b-instruct-Q4_K_M.gguf` | `ibm-granite/granite-3.3-2b-instruct-GGUF` @ `7cdf86ccd1f1bb3491c9b7017b033f2e51367397` | Apache-2.0 |
| `Phi-3.5-mini-instruct-Q4_K_M.gguf` | `bartowski/Phi-3.5-mini-instruct-GGUF` @ `6d70da17e749a471ccb62ade694486011a75cda3` (base `microsoft/Phi-3.5-mini-instruct`) | MIT |
| `Phi-4-mini-instruct-Q4_K_M.gguf` | `unsloth/Phi-4-mini-instruct-GGUF` @ `78eb92a46fc37e6b524df991ed9aca9bc6aa7b80` (base `microsoft/Phi-4-mini-instruct`) | MIT |
| `Qwen3-4B-Q4_K_M.gguf` | `Qwen/Qwen3-4B-GGUF` @ `bc640142c66e1fdd12af0bd68f40445458f3869b` | Apache-2.0 |
