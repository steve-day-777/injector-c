// shellcode.cpp
// Manual AArch64 shellcode builder – mirrors the dynasmrt-based Rust implementation
// in src/shellcode.rs.  No external assembler library is needed.
//
// Naming convention for instruction helpers:
//   emit_<mnemonic>_<variant>(buf, operands...)
// All helpers append exactly 4 bytes (one AArch64 instruction) to `buf`.

#include "linjector/shellcode.hpp"

#include <cassert>
#include <cstring>

#include "linjector/error.hpp"

namespace linjector::shellcode {

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

namespace {

// Append a 32-bit little-endian word (one instruction).
void emit32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v));
    b.push_back(static_cast<uint8_t>(v >> 8U));
    b.push_back(static_cast<uint8_t>(v >> 16U));
    b.push_back(static_cast<uint8_t>(v >> 24U));
}

// Append a 64-bit little-endian value (data, not an instruction).
void emit64(std::vector<uint8_t>& b, uint64_t v) {
    emit32(b, static_cast<uint32_t>(v));
    emit32(b, static_cast<uint32_t>(v >> 32U));
}

// Pad to the next 4-byte boundary (data section alignment).
void align4(std::vector<uint8_t>& b) {
    while (b.size() % 4 != 0) b.push_back(0);
}

// ---------------------------------------------------------------------------
// Instruction encoders
// Each function appends exactly 4 bytes.
// ---------------------------------------------------------------------------

// LDR Xt, [PC, #byte_delta]  (literal, 64-bit load)
// byte_delta must be a multiple of 4, range ±1 MB.
void emit_ldr_lit_x(std::vector<uint8_t>& b, int rt, int32_t byte_delta) {
    const int32_t imm19 = byte_delta / 4;
    emit32(b, 0x58000000U | (static_cast<uint32_t>(imm19 & 0x7FFFF) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// LDR Wt, [PC, #byte_delta]  (literal, 32-bit load)
void emit_ldr_lit_w(std::vector<uint8_t>& b, int rt, int32_t byte_delta) {
    const int32_t imm19 = byte_delta / 4;
    emit32(b, 0x18000000U | (static_cast<uint32_t>(imm19 & 0x7FFFF) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// ADR Xd, [PC, #byte_delta]  (compute PC-relative address, no memory access)
void emit_adr_x(std::vector<uint8_t>& b, int rd, int32_t byte_delta) {
    const uint32_t immlo = static_cast<uint32_t>(byte_delta) & 0x3U;
    const uint32_t immhi = static_cast<uint32_t>(byte_delta >> 2) & 0x7FFFFU;
    emit32(b, 0x10000000U | (immlo << 29U) | (immhi << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// LDXRB Wt, [Xn]  (load exclusive byte)
void emit_ldxrb(std::vector<uint8_t>& b, int rt, int rn) {
    emit32(b, 0x085F7C00U | (static_cast<uint32_t>(rn & 0x1F) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// STXRB Ws, Wt, [Xn]  (store exclusive byte; Ws receives success flag)
void emit_stxrb(std::vector<uint8_t>& b, int rs, int rt, int rn) {
    emit32(b, 0x08007C00U | (static_cast<uint32_t>(rs & 0x1F) << 16U)
                          | (static_cast<uint32_t>(rn & 0x1F) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// CBNZ Wt, #byte_delta  (compare-and-branch-if-non-zero, 32-bit register)
void emit_cbnz_w(std::vector<uint8_t>& b, int rt, int32_t byte_delta) {
    const int32_t imm19 = byte_delta / 4;
    emit32(b, 0x35000000U | (static_cast<uint32_t>(imm19 & 0x7FFFF) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// CBZ Xt, #byte_delta  (compare-and-branch-if-zero, 64-bit register)
void emit_cbz_x(std::vector<uint8_t>& b, int rt, int32_t byte_delta) {
    const int32_t imm19 = byte_delta / 4;
    emit32(b, 0xB4000000U | (static_cast<uint32_t>(imm19 & 0x7FFFF) << 5U)
                          | static_cast<uint32_t>(rt & 0x1F));
}

// SUB SP, SP, #imm12
void emit_sub_sp(std::vector<uint8_t>& b, uint32_t imm12) {
    emit32(b, 0xD1000000U | ((imm12 & 0xFFFU) << 10U) | (31U << 5U) | 31U);
}

// ADD SP, SP, #imm12
void emit_add_sp(std::vector<uint8_t>& b, uint32_t imm12) {
    emit32(b, 0x91000000U | ((imm12 & 0xFFFU) << 10U) | (31U << 5U) | 31U);
}

// STP Xt1, Xt2, [Xn, #imm8]  (signed offset, 64-bit pair store)
void emit_stp_x(std::vector<uint8_t>& b, int xt1, int xt2, int xn, int32_t imm) {
    const int32_t imm7 = imm / 8;
    emit32(b, 0xA9000000U | (static_cast<uint32_t>(imm7 & 0x7F) << 15U)
                          | (static_cast<uint32_t>(xt2 & 0x1F) << 10U)
                          | (static_cast<uint32_t>(xn  & 0x1F) << 5U)
                          | static_cast<uint32_t>(xt1 & 0x1F));
}

// LDP Xt1, Xt2, [Xn, #imm8]  (signed offset, 64-bit pair load)
void emit_ldp_x(std::vector<uint8_t>& b, int xt1, int xt2, int xn, int32_t imm) {
    const int32_t imm7 = imm / 8;
    emit32(b, 0xA9400000U | (static_cast<uint32_t>(imm7 & 0x7F) << 15U)
                          | (static_cast<uint32_t>(xt2 & 0x1F) << 10U)
                          | (static_cast<uint32_t>(xn  & 0x1F) << 5U)
                          | static_cast<uint32_t>(xt1 & 0x1F));
}

// MOVZ Xd, #imm16  (zero-extended 16-bit immediate, 64-bit register)
void emit_movz_x(std::vector<uint8_t>& b, int rd, uint16_t imm16) {
    emit32(b, 0xD2800000U | (static_cast<uint32_t>(imm16) << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// MOVZ Wd, #imm16  (zero-extended 16-bit immediate, 32-bit register)
void emit_movz_w(std::vector<uint8_t>& b, int rd, uint16_t imm16) {
    emit32(b, 0x52800000U | (static_cast<uint32_t>(imm16) << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// MOVK Xd, #imm16, lsl shift  (insert 16-bit immediate at given shift, 64-bit)
void emit_movk_x(std::vector<uint8_t>& b, int rd, uint16_t imm16, int shift) {
    const uint32_t hw = static_cast<uint32_t>(shift / 16);
    emit32(b, 0xF2800000U | (hw << 21U)
                          | (static_cast<uint32_t>(imm16) << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// Emit a full 64-bit immediate into Xd using MOVZ + up to 3 MOVK instructions.
void emit_mov64_x(std::vector<uint8_t>& b, int rd, uint64_t val) {
    emit_movz_x(b, rd, static_cast<uint16_t>(val & 0xFFFFU));
    if (val >> 16U) {
        emit_movk_x(b, rd, static_cast<uint16_t>((val >> 16U) & 0xFFFFU), 16);
    }
    if (val >> 32U) {
        emit_movk_x(b, rd, static_cast<uint16_t>((val >> 32U) & 0xFFFFU), 32);
    }
    if (val >> 48U) {
        emit_movk_x(b, rd, static_cast<uint16_t>((val >> 48U) & 0xFFFFU), 48);
    }
}

// MVN Xd, XZR  –  sets Xd = 0xFFFFFFFFFFFFFFFF (-1)
// Encoded as ORN Xd, XZR, XZR (shifted-register, shift=0)
void emit_mvn_xzr(std::vector<uint8_t>& b, int rd) {
    emit32(b, 0xAA200000U | (31U << 16U) | (0U << 10U) | (31U << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// MOV Xd, Xn  (register copy, encoded as ORR Xd, XZR, Xn)
void emit_mov_xr(std::vector<uint8_t>& b, int rd, int rn) {
    emit32(b, 0xAA000000U | (static_cast<uint32_t>(rn & 0x1F) << 16U)
                          | (0U << 10U) | (31U << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// SVC #imm16
void emit_svc(std::vector<uint8_t>& b, uint16_t imm) {
    emit32(b, 0xD4000001U | (static_cast<uint32_t>(imm) << 5U));
}

// STR Wt, [Xn]  (32-bit store, unsigned offset = 0)
void emit_str_w0(std::vector<uint8_t>& b, int wt, int xn) {
    emit32(b, 0xB9000000U | (0U << 10U)
                          | (static_cast<uint32_t>(xn & 0x1F) << 5U)
                          | static_cast<uint32_t>(wt & 0x1F));
}

// STR Xt, [Xn, #offset]  (64-bit store, unsigned offset in bytes, must be mult of 8)
void emit_str_x(std::vector<uint8_t>& b, int xt, int xn, uint32_t offset_bytes) {
    const uint32_t imm12 = offset_bytes / 8U;
    emit32(b, 0xF9000000U | ((imm12 & 0xFFFU) << 10U)
                          | (static_cast<uint32_t>(xn & 0x1F) << 5U)
                          | static_cast<uint32_t>(xt & 0x1F));
}

// DSB ISH  (data synchronisation barrier, inner shareable)
void emit_dsb_ish(std::vector<uint8_t>& b) { emit32(b, 0xD5033B9FU); }

// ISB  (instruction synchronisation barrier)
void emit_isb(std::vector<uint8_t>& b)     { emit32(b, 0xD5033FDFU); }

// ORR Xd, Xn, #1  (logical immediate #1; N=1, immr=0, imms=0)
void emit_orr_x_1(std::vector<uint8_t>& b, int rd, int rn) {
    emit32(b, 0xB2000000U | (1U << 22U) | (0U << 16U) | (0U << 10U)
                          | (static_cast<uint32_t>(rn & 0x1F) << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// EOR Xd, Xn, #1  (logical immediate #1; N=1, immr=0, imms=0)
void emit_eor_x_1(std::vector<uint8_t>& b, int rd, int rn) {
    emit32(b, 0xD2000000U | (1U << 22U) | (0U << 16U) | (0U << 10U)
                          | (static_cast<uint32_t>(rn & 0x1F) << 5U)
                          | static_cast<uint32_t>(rd & 0x1F));
}

// BR Xn  (unconditional branch to register)
void emit_br_x(std::vector<uint8_t>& b, int rn) {
    emit32(b, 0xD61F0000U | (static_cast<uint32_t>(rn & 0x1F) << 5U));
}

// BLR Xn  (branch with link to register)
void emit_blr_x(std::vector<uint8_t>& b, int rn) {
    emit32(b, 0xD63F0000U | (static_cast<uint32_t>(rn & 0x1F) << 5U));
}

// BRK #imm16
void emit_brk(std::vector<uint8_t>& b, uint16_t imm) {
    emit32(b, 0xD4200000U | (static_cast<uint32_t>(imm) << 5U));
}

// ---------------------------------------------------------------------------
// Emit 16 LDP pairs to restore all callee-saved registers from the stack.
// Matches the ldp sequence in the Rust raw_dlopen / memfd_dlopen shellcodes.
// ---------------------------------------------------------------------------
void emit_restore_regs(std::vector<uint8_t>& b) {
    // SP was decremented by 0x100 in main_shellcode; restore all registers.
    emit_ldp_x(b,  0,  1, 31, 0x000);
    emit_ldp_x(b,  2,  3, 31, 0x010);
    emit_ldp_x(b,  4,  5, 31, 0x020);
    emit_ldp_x(b,  6,  7, 31, 0x030);
    emit_ldp_x(b,  8,  9, 31, 0x040);
    emit_ldp_x(b, 10, 11, 31, 0x050);
    emit_ldp_x(b, 12, 13, 31, 0x060);
    emit_ldp_x(b, 14, 15, 31, 0x070);
    emit_ldp_x(b, 16, 17, 31, 0x080);
    emit_ldp_x(b, 18, 19, 31, 0x090);
    emit_ldp_x(b, 20, 21, 31, 0x0A0);
    emit_ldp_x(b, 22, 23, 31, 0x0B0);
    emit_ldp_x(b, 24, 25, 31, 0x0C0);
    emit_ldp_x(b, 26, 27, 31, 0x0D0);
    emit_ldp_x(b, 28, 29, 31, 0x0E0);
    emit_ldp_x(b, 30, 31, 31, 0x0F0);  // x30=LR, x31=XZR (discard)
    emit_add_sp(b, 0x100);
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Public shellcode builders
// ---------------------------------------------------------------------------

// main_shellcode  –  Stage 1, overwrites the prologue of the hijacked function.
//
// Behaviour (mirrors Rust main_shellcode):
//   1. Spin on *var_addr using load-exclusive / store-exclusive until we
//      acquire the single-entry "lock" (bit 0 of the byte at var_addr).
//   2. Save all 31 general-purpose registers onto the stack.
//   3. Call mmap(NULL, alloc_len, PROT_READ|PROT_WRITE|PROT_EXEC,
//              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) via SVC.
//   4. Write a self-jump instruction (B #0) to the very start of the new page
//      so that the injector can detect when we have reached that page.
//   5. Store (mmap_result | 0x1) into *var_addr to signal the injector.
//   6. Clear bit 0 and jump to the new page; the injector will overwrite it
//      with the stage-2 shellcode.
//
// Layout (all sizes in bytes) – exactly 39 instructions regardless of alloc_len:
//   [0   .. 155]  39 AArch64 instructions
//   [156 .. 163]  data: var_addr   (8-byte qword)
//   [164 .. 171]  data: alloc_len  (8-byte qword, avoids variable-length encoding)
//   [172 .. 175]  data: self_jmp   (4-byte dword, encoding of "B #0")
//   Total: 176 bytes
std::vector<uint8_t> main_shellcode(const std::size_t var_addr,
                                     const std::size_t alloc_len) {
    constexpr std::size_t VAR_ADDR_OFF   = 156;
    constexpr std::size_t ALLOC_LEN_OFF  = 164;
    constexpr std::size_t SELF_JMP_OFF   = 172;

    std::vector<uint8_t> b;
    b.reserve(176);

    // --- instruction 0 (PC=0): ldr x6, ->var_addr  (delta = 156)
    emit_ldr_lit_x(b, 6, static_cast<int32_t>(VAR_ADDR_OFF));

    // --- instructions 1-2 (PC=4..8): spin until we can claim the byte lock
    constexpr int32_t start_pc = 0;  // label "start" = PC 0
    emit_ldxrb(b, 1, 6);             // ldxrb w1, [x6]
    emit_cbnz_w(b, 1, start_pc - static_cast<int32_t>(b.size()));  // cbnz w1, start

    // --- instructions 3-5 (PC=12..20): try to store 1 atomically
    emit_movz_w(b, 2, 1);            // mov w2, #1
    emit_stxrb(b, 1, 2, 6);         // stxrb w1, w2, [x6]
    emit_cbnz_w(b, 1, start_pc - static_cast<int32_t>(b.size()));  // cbnz w1, start

    // --- instructions 6-23 (PC=24..88): save stack frame and all registers
    emit_sub_sp(b, 0x100);
    emit_stp_x(b,  0,  1, 31, 0x000);
    emit_stp_x(b,  2,  3, 31, 0x010);
    emit_stp_x(b,  4,  5, 31, 0x020);
    emit_stp_x(b,  6,  7, 31, 0x030);
    emit_stp_x(b,  8,  9, 31, 0x040);
    emit_stp_x(b, 10, 11, 31, 0x050);
    emit_stp_x(b, 12, 13, 31, 0x060);
    emit_stp_x(b, 14, 15, 31, 0x070);
    emit_stp_x(b, 16, 17, 31, 0x080);
    emit_stp_x(b, 18, 19, 31, 0x090);
    emit_stp_x(b, 20, 21, 31, 0x0A0);
    emit_stp_x(b, 22, 23, 31, 0x0B0);
    emit_stp_x(b, 24, 25, 31, 0x0C0);
    emit_stp_x(b, 26, 27, 31, 0x0D0);
    emit_stp_x(b, 28, 29, 31, 0x0E0);
    emit_stp_x(b, 30, 31, 31, 0x0F0);  // x30=LR, x31 treated as XZR

    // --- instructions 24-31 (PC=92..124): mmap syscall arguments
    //     syscall number for mmap on AArch64 Linux = 0xDE (222)
    emit_movz_x(b, 0, 0);           // x0 = NULL
    // Use LDR literal for alloc_len: always 1 instruction regardless of size.
    emit_ldr_lit_x(b, 1,
        static_cast<int32_t>(ALLOC_LEN_OFF) - static_cast<int32_t>(b.size()));
    emit_movz_x(b, 2, 7);           // x2 = PROT_READ|WRITE|EXEC
    emit_movz_x(b, 3, 0x22);        // x3 = MAP_PRIVATE|MAP_ANON
    emit_mvn_xzr(b, 4);             // x4 = -1 (fd)
    emit_movz_x(b, 5, 0);           // x5 = 0 (offset)
    emit_movz_x(b, 8, 0xDE);        // x8 = mmap syscall no
    emit_svc(b, 0);

    // --- instruction 32 (PC=124): ldr w1, ->self_jmp  (load "B #0" opcode)
    emit_ldr_lit_w(b, 1,
        static_cast<int32_t>(SELF_JMP_OFF) - static_cast<int32_t>(b.size()));

    // --- instructions 33-38 (PC=128..152)
    emit_str_w0(b, 1, 0);   // str w1, [x0]  – write self-jmp to new page[0]
    emit_dsb_ish(b);         // data synchronisation barrier
    emit_isb(b);             // instruction synchronisation barrier
    emit_orr_x_1(b, 0, 0);  // x0 |= 1  (set signal bit)
    emit_str_x(b, 0, 6, 0); // str x0, [x6]  (* var_addr = mmap_result | 1)
    emit_eor_x_1(b, 0, 0);  // x0 ^= 1  (clear signal bit)
    emit_br_x(b, 0);         // br x0   (jump to new page)

    assert(b.size() == VAR_ADDR_OFF);  // must be exactly 156 bytes here

    // --- Data section ---
    emit64(b, static_cast<uint64_t>(var_addr));    // var_addr
    emit64(b, static_cast<uint64_t>(alloc_len));   // alloc_len (always qword)
    emit32(b, 0x14000000U);                        // self_jmp  ("B #0")

    return b;
}

// raw_dlopen_shellcode  –  Stage 2 for RawDlopen mode.
//
// Runs on the freshly mmap'd page.  Calls dlopen(path, RTLD_NOW),
// restores all saved registers, then jumps back to the original function.
//
// Layout:
//   [0  .. 99]   25 instructions (100 bytes)
//   [100 ..]     dlopen_path bytes + null + alignment padding
//   [+8  ]       dlopen_flags  qword (value = 2 = RTLD_NOW)
//   [+8  ]       dlopen        qword (dlopen_addr)
//   [+8  ]       oldfun        qword (jmp_addr)
std::vector<uint8_t> raw_dlopen_shellcode(const std::size_t dlopen_addr,
                                           const std::string& dlopen_path,
                                           const std::size_t  jmp_addr) {
    // Pre-compute data-section offsets
    constexpr std::size_t INSN_SIZE = 25 * 4;          // = 100
    const std::size_t path_len    = dlopen_path.size() + 1;  // incl. null
    const std::size_t path_padded = (path_len + 3) & ~std::size_t{3};
    const std::size_t flags_off   = INSN_SIZE + path_padded;
    const std::size_t dlopen_off  = flags_off + 8;
    const std::size_t oldfun_off  = dlopen_off + 8;

    std::vector<uint8_t> b;
    b.reserve(oldfun_off + 8);

    // --- instruction 0 (PC=0): adr x0, ->dlopen_path
    emit_adr_x(b, 0, static_cast<int32_t>(INSN_SIZE));

    // --- instruction 1 (PC=4): ldr x1, ->dlopen_flags
    emit_ldr_lit_x(b, 1,
        static_cast<int32_t>(flags_off) - static_cast<int32_t>(b.size()));

    // --- instruction 2 (PC=8): ldr x8, ->dlopen
    emit_ldr_lit_x(b, 8,
        static_cast<int32_t>(dlopen_off) - static_cast<int32_t>(b.size()));

    // --- instruction 3 (PC=12): blr x8
    emit_blr_x(b, 8);

    // --- instruction 4 (PC=16): cbz x0, crash
    //     crash label is at PC = 96  (instruction 24)
    constexpr int32_t CRASH_PC = 96;
    emit_cbz_x(b, 0, CRASH_PC - static_cast<int32_t>(b.size()));

    // --- instructions 5-21: restore all saved registers
    emit_restore_regs(b);   // 17 instructions = 68 bytes  -> PC=84 after

    // --- instruction 22 (PC=84): ldr x8, ->oldfun
    emit_ldr_lit_x(b, 8,
        static_cast<int32_t>(oldfun_off) - static_cast<int32_t>(b.size()));

    // --- instruction 23 (PC=88): br x8
    emit_br_x(b, 8);

    // --- instruction 24 (PC=92): brk #1  (crash path if dlopen returned NULL)
    assert(static_cast<int32_t>(b.size()) == CRASH_PC - 4);  // about to be at 92
    emit_brk(b, 1);  // PC = 96 now
    // Note: crash label lands here (PC = 96), so CRASH_PC should be 96.
    // Let's double-check: we emitted 5+17+1+1+1 = 25 instructions so far
    // but the crash instruction itself is number 24 (0-indexed), so PC=96:
    assert(b.size() == INSN_SIZE);  // should now be exactly 100 bytes

    // --- Data section ---
    // dlopen_path (null-terminated, padded to 4 bytes)
    b.insert(b.end(), dlopen_path.begin(), dlopen_path.end());
    b.push_back(0);  // null terminator
    while (b.size() % 4 != 0) b.push_back(0);  // alignment padding

    // dlopen_flags = RTLD_NOW = 2
    emit64(b, 2);

    // dlopen address
    emit64(b, static_cast<uint64_t>(dlopen_addr));

    // original function address (jmp_addr)
    emit64(b, static_cast<uint64_t>(jmp_addr));

    return b;
}

// memfd_dlopen_shellcode  –  Stage 2 for MemFdDlopen mode.
//
// Runs on the mmap'd page.  Steps:
//   1. memfd_create("", 0)         -> fd in x0
//   2. sprintf(buf, "/proc/self/fd/%d", fd)  using the injected sprintf
//   3. write(fd, library_data, len)
//   4. dlopen("/proc/self/fd/<n>", RTLD_NOW)
//   5. Restore all registers and jump to the original function.
//
// Layout (instruction section = 38 instructions = 152 bytes):
//   [152]  memfd_name  : 1 null byte + 3 padding    = 4 bytes
//   [156]  dlopen_flags: qword = 2
//   [164]  dlopen      : qword
//   [172]  oldfun      : qword
//   [180]  sprintf     : qword
//   [188]  fd_template : "/proc/self/fd/%d\0" + padding = 20 bytes
//   [208]  fd_buf      : 32 zero bytes
//   [240]  library_data: variable
std::vector<uint8_t> memfd_dlopen_shellcode(
        const std::size_t dlopen_addr,
        const std::size_t jmp_addr,
        const std::vector<uint8_t>& library_data,
        const std::size_t sprintf_addr) {
    // Fixed data-section offsets (derived from the instruction layout below)
    constexpr std::size_t INSN_SIZE     = 152;
    constexpr std::size_t MEMFD_NAME_OFF = INSN_SIZE + 0;   // 152
    constexpr std::size_t FLAGS_OFF      = INSN_SIZE + 4;   // 156
    constexpr std::size_t DLOPEN_OFF     = INSN_SIZE + 12;  // 164
    constexpr std::size_t OLDFUN_OFF     = INSN_SIZE + 20;  // 172
    constexpr std::size_t SPRINTF_OFF    = INSN_SIZE + 28;  // 180
    constexpr std::size_t TEMPLATE_OFF   = INSN_SIZE + 36;  // 188
    constexpr std::size_t FDBUF_OFF      = INSN_SIZE + 56;  // 208
    constexpr std::size_t LIBDATA_OFF    = INSN_SIZE + 88;  // 240

    std::vector<uint8_t> b;
    b.reserve(LIBDATA_OFF + library_data.size());

    // ---- Group 1: memfd_create("", 0) ----
    // instruction 0 (PC=0): adr x0, ->memfd_name
    emit_adr_x(b, 0, static_cast<int32_t>(MEMFD_NAME_OFF));  // delta = 152
    // instruction 1 (PC=4): movz x1, #0  (flags=0)
    emit_movz_x(b, 1, 0);
    // instruction 2 (PC=8): movz x8, #0x117  (memfd_create syscall)
    emit_movz_x(b, 8, 0x117);
    // instruction 3 (PC=12): svc #0
    emit_svc(b, 0);

    // ---- Group 2: sprintf(fd_buf, "/proc/self/fd/%d", fd) ----
    // instruction 4 (PC=16): mov x2, x0  (save fd)
    emit_mov_xr(b, 2, 0);
    // instruction 5 (PC=20): adr x0, ->fd_buf
    emit_adr_x(b, 0, static_cast<int32_t>(FDBUF_OFF) - static_cast<int32_t>(b.size()));
    // instruction 6 (PC=24): adr x1, ->fd_template
    emit_adr_x(b, 1, static_cast<int32_t>(TEMPLATE_OFF) - static_cast<int32_t>(b.size()));
    // instruction 7 (PC=28): ldr x8, ->sprintf
    emit_ldr_lit_x(b, 8, static_cast<int32_t>(SPRINTF_OFF) - static_cast<int32_t>(b.size()));
    // instruction 8 (PC=32): blr x8
    emit_blr_x(b, 8);

    // ---- Group 3: write(fd, library_data, len) ----
    // instruction 9 (PC=36): mov x0, x2  (restore fd)
    emit_mov_xr(b, 0, 2);
    // instruction 10 (PC=40): adr x1, ->library_data
    emit_adr_x(b, 1, static_cast<int32_t>(LIBDATA_OFF) - static_cast<int32_t>(b.size()));
    // instructions 11-12 (PC=44..48): mov x2, lib_len  (32-bit immediate, 2 instrs)
    {
        const auto lib_len = static_cast<uint32_t>(library_data.size());
        emit_movz_x(b, 2, static_cast<uint16_t>(lib_len & 0xFFFFU));
        emit_movk_x(b, 2, static_cast<uint16_t>((lib_len >> 16U) & 0xFFFFU), 16);
    }
    // instruction 13 (PC=52): movz x8, #0x40  (write syscall)
    emit_movz_x(b, 8, 0x40);
    // instruction 14 (PC=56): svc #0
    emit_svc(b, 0);

    // ---- Group 4: dlopen("/proc/self/fd/<n>", RTLD_NOW) ----
    // instruction 15 (PC=60): adr x0, ->fd_buf
    emit_adr_x(b, 0, static_cast<int32_t>(FDBUF_OFF) - static_cast<int32_t>(b.size()));
    // instruction 16 (PC=64): ldr x1, ->dlopen_flags
    emit_ldr_lit_x(b, 1, static_cast<int32_t>(FLAGS_OFF) - static_cast<int32_t>(b.size()));
    // instruction 17 (PC=68): ldr x8, ->dlopen
    emit_ldr_lit_x(b, 8, static_cast<int32_t>(DLOPEN_OFF) - static_cast<int32_t>(b.size()));
    // instruction 18 (PC=72): blr x8
    emit_blr_x(b, 8);

    // ---- Group 5: restore registers and return ----
    // instructions 19-35 (PC=76..143): 17 restore instructions
    emit_restore_regs(b);   // 17 instructions -> ends at PC=144

    // instruction 36 (PC=144): ldr x8, ->oldfun
    emit_ldr_lit_x(b, 8, static_cast<int32_t>(OLDFUN_OFF) - static_cast<int32_t>(b.size()));
    // instruction 37 (PC=148): br x8
    emit_br_x(b, 8);

    assert(b.size() == INSN_SIZE);

    // --- Data section ---
    // memfd_name: empty string (1 null byte + padding)
    b.push_back(0);
    while (b.size() % 4 != 0) b.push_back(0);          // -> offset 156 ✓

    emit64(b, 2);                                        // dlopen_flags = RTLD_NOW
    emit64(b, static_cast<uint64_t>(dlopen_addr));       // dlopen
    emit64(b, static_cast<uint64_t>(jmp_addr));          // oldfun
    emit64(b, static_cast<uint64_t>(sprintf_addr));      // sprintf

    // fd_template: "/proc/self/fd/%d\0" (18 bytes) + 2 padding = 20 bytes
    static const char tmpl[] = "/proc/self/fd/%d";
    b.insert(b.end(), tmpl, tmpl + sizeof(tmpl));  // includes null terminator
    while (b.size() % 4 != 0) b.push_back(0);          // -> offset 208 ✓

    // fd_format_buffer: 32 zero bytes
    b.insert(b.end(), 32, 0);                            // -> offset 240 ✓

    assert(b.size() == LIBDATA_OFF);

    // library_data bytes
    b.insert(b.end(), library_data.begin(), library_data.end());

    return b;
}

// raw_shellcode – not implemented (mirrors Rust unimplemented!())
std::vector<uint8_t> raw_shellcode() {
    throw InjectionException(InjectionError::ShellcodeError,
                             "raw shellcode mode is not yet implemented");
}

// self_jmp – returns the 4-byte AArch64 encoding of "B #0" (branch to self).
std::vector<uint8_t> self_jmp() {
    std::vector<uint8_t> b;
    emit32(b, 0x14000000U);  // B #0 in AArch64
    return b;
}

}  // namespace linjector::shellcode

