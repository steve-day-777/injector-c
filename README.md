# linjector-cpp

Android AArch64 library injector written in C++20.  
C++ port of [linjector-rs](https://github.com/erfur/linjector-rs), which is itself an Android port of [linux_injector](https://github.com/namazso/linux_injector).

Injects a shared library (`.so`) into a running Android process **without ptrace**, using `/proc/<pid>/mem` for all memory reads and writes.

> **Only AArch64 (arm64-v8a) is supported.** The stage-1 shellcode is hand-encoded AArch64 machine code.

---

## How it works

Injection happens in two stages, both driven entirely through `/proc/<pid>/mem`:

### Stage 1 — hijack a function prologue

A short shellcode is written over the first N bytes of a chosen target function (default: `libc::malloc`).  When any thread in the target process next calls that function the shellcode:

1. Spins on a watched variable (`libc::timezone` by default) using `LDXRB`/`STXRB` to acquire a single-entry lock.
2. Saves all 31 general-purpose registers onto the stack (`STP` pairs).
3. Calls `mmap(NULL, stage2_len, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)` via `SVC`.
4. Writes a self-jump (`B #0`) to the first word of the new page (so the injector can detect it).
5. Stores `(mmap_addr | 1)` into the watched variable — the low bit is the *ready* signal.
6. Clears the low bit and jumps to the new page.

The injector polls the watched variable every 10 ms until bit 0 is set.

### Stage 2 — run on the new page

The injector writes the stage-2 payload onto the mmap'd page while the target thread spins there.  Three modes are available:

| Mode | Description |
|------|-------------|
| `raw-dlopen` | Calls `dlopen(path, RTLD_NOW)` with the path of the `.so` on the device filesystem, restores all registers, and jumps back to the original function. |
| `memfd-dlopen` | Creates an anonymous file with `memfd_create`, writes the `.so` bytes into it, then calls `dlopen("/proc/self/fd/<n>", RTLD_NOW)`. The library never needs to be present on the filesystem. |
| `raw-shellcode` | *(not yet implemented)* Executes arbitrary shellcode. |

After writing stage 2, the injector:
- Restores the original function prologue (tail-first to minimise visible window).
- Restores the original value of the watched variable.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Rooted Android device | `/proc/<pid>/mem` write access requires root |
| AArch64 (arm64-v8a) | The shellcode is hand-encoded AArch64 |
| Android API ≥ 26 | `std::filesystem` and `memfd_create` |
| NDK r23+ | For full C++20 support with `libc++` |

---

## Building

### ndk-build (recommended for Android deployment)

```bash
# From the inject_c/ directory:
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

# Output:
#   libs/arm64-v8a/linjector-cli   (stripped executable)
#   obj/local/arm64-v8a/…          (unstripped objects)
```

The `Application.mk` configures:
- `APP_ABI=arm64-v8a`
- `APP_STL=c++_static` (self-contained binary, no extra `.so` needed)
- `APP_PLATFORM=android-26`
- `APP_OPTIM=release` with `--strip-all`

### CMake (for development / host testing)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

For cross-compilation with the NDK:

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

---

## Deploying and running

```bash
adb push libs/arm64-v8a/linjector-cli /data/local/tmp/
adb push your_library.so             /data/local/tmp/

adb shell
su
/data/local/tmp/linjector-cli --pid <PID> --file /data/local/tmp/your_library.so
```

---

## Usage

```
linjector-cli --file <FILE> [options]

Options:
  -p, --pid <PID>
      PID of the target process.

  -a, --app-package-name <NAME>
      Force-stop and re-launch the app, then inject once it starts.
      Cannot be combined with --pid.

  -f, --file <FILE>
      Local path to the .so (or raw shellcode) to inject.

  -i, --injection-type <TYPE>
      raw-dlopen    (default) – dlopen the file from the filesystem.
      memfd-dlopen  – embed the file in a memfd, no filesystem trace.
      raw-shellcode – inject raw shellcode (not yet implemented).

      --func-sym <lib.so!symbol>
      Override the function to hijack (default: libc.so!malloc).

      --var-sym <lib.so!symbol>
      Override the watched variable (default: libc.so!timezone).

  -d, --debug
      Enable DEBUG-level log output.

      --logcat
      Also forward logs to Android logcat (tag: linjector).

  -h, --help
      Print this help.
```

### Examples

```bash
# Inject using the default symbols (malloc / timezone)
linjector-cli -p 1234 -f /data/local/tmp/payload.so

# Inject by package name (restarts the app)
linjector-cli -a com.example.app -f /data/local/tmp/payload.so

# Use memfd mode (no file on disk in the target process)
linjector-cli -p 1234 -f /data/local/tmp/payload.so -i memfd-dlopen

# Specify custom hook symbols
linjector-cli -p 1234 -f /data/local/tmp/payload.so \
    --func-sym libssl.so!SSL_read \
    --var-sym  libssl.so!ssl_session_cache_client_lru

# Debug logging
linjector-cli -p 1234 -f /data/local/tmp/payload.so -d
```

---

## Log output

Log lines are written to **stderr** in the format:

```
[INFO ] new injector for pid: 1234
[INFO ] module 'libdl.so': path=/apex/com.android.runtime/lib64/bionic/libdl.so vm_addr=0x79abc00000
[WARN ] symbol not found in .symtab, trying .dynsym: dlopen
[DEBUG] dlsym: 'dlopen' found in .dynsym at 0x79abc01234
[INFO ] build second stage shellcode
[INFO ] injection mode: raw-dlopen  dlopen=0x79abc01234  oldfun=0x79def05678
[INFO ] second stage size: 148 bytes
[INFO ] build first stage shellcode
[INFO ] first stage size: 176 bytes
[INFO ] write first stage shellcode -> 0x79def05678
[INFO ] wait for shellcode to trigger...
[INFO ] new map: 0x7f1234560000
[INFO ] restore original bytes
[INFO ] injection done.
[INFO ] injection successful
```

On Android, passing `--logcat` additionally routes all messages to `logcat` under the tag `linjector`.

---

## Project structure

```
inject_c/
├── Android.mk              ndk-build module definitions
├── Application.mk          Global ndk-build settings (ABI, STL, API level)
├── CMakeLists.txt          CMake build (development / cross-compile)
├── include/
│   └── linjector/
│       ├── error.hpp       InjectionError enum + InjectionException
│       ├── log.hpp         Logging macros (LLOG_INFO / DEBUG / WARN / ERROR)
│       ├── injector.hpp    Injector class declaration
│       ├── remote_mem.hpp  RemoteMem – /proc/<pid>/mem read/write
│       ├── remote_module.hpp RemoteModule – ELF symbol resolution
│       ├── remote_proc.hpp RemoteProc – /proc/<pid>/maps parsing
│       ├── shellcode.hpp   Stage-1 and stage-2 shellcode builders
│       └── utils.hpp       File / process utility helpers
└── src/
    ├── injector.cpp        Top-level injection orchestration
    ├── log.cpp             Global log-level variable
    ├── remote_mem.cpp      pread64/pwrite64 on /proc/<pid>/mem
    ├── remote_module.cpp   ELF parsing (.symtab → .dynsym) + APEX fallback
    ├── remote_proc.cpp     /proc/<pid>/maps parser
    ├── shellcode.cpp       Manual AArch64 instruction encoder
    ├── utils.cpp           chcon / chmod / am / monkey helpers
    └── main.cpp            CLI (mirrors Rust bin/cli.rs)
```

---

## Android compatibility

| Android version | API | Notes |
|-----------------|-----|-------|
| ≤ 9 (Pie)       | ≤ 28 | Libraries at `/system/lib64/`. Fully supported. |
| 10 (Q)          | 29  | bionic libraries moved to APEX (`/apex/com.android.runtime/lib64/bionic/`). The injector tries the APEX path first, then falls back to `/system/lib64/`. |
| 11–15           | 30–35 | Same as Android 10. `memfd-dlopen` **does not work** — SELinux blocks `dlopen` on memfd-backed paths. Use `raw-dlopen`. |

---

## Differences from the Rust version

| Aspect | Rust (linjector-rs) | C++ (this project) |
|--------|--------------------|--------------------|
| Shellcode assembly | `dynasmrt` JIT assembler | Manual AArch64 byte encoding (no external assembler) |
| `alloc_len` encoding | `MOV X1, imm` (variable-length) | `LDR X1, [PC, #offset]` (always 1 instruction, supports any size) |
| Error handling | `Result<T, E>` | C++ exceptions (`InjectionException`) |
| ELF parsing | `goblin` crate | Direct `<elf.h>` struct access |
| APEX path fallback | Not present | Tries 6 candidate paths in order |
| Build | Cargo + `cargo-ndk` | ndk-build or CMake |
