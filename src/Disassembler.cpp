#include "Disassembler.h"
#include "Config.h"
#include <cstring>

namespace SwiftHook {

#if SWIFTHOOK_X64 || SWIFTHOOK_X86

    // Simplified x86/x64 length disassembler
    // Based on Hacker Disassembler Engine (HDE)
    size_t Disassembler::GetX86InstructionLength(const uint8_t* pCode) {
        if (!pCode) return 0;

        size_t len = 0;
        uint8_t byte;

        // Prefix bytes
        bool hasPrefix = true;
        while (hasPrefix) {
            byte = pCode[len++];
            switch (byte) {
                // Legacy prefixes
            case 0xF0: case 0xF2: case 0xF3: // LOCK, REPNE, REP
            case 0x2E: case 0x36: case 0x3E: case 0x26: // Segment overrides
            case 0x64: case 0x65: // FS, GS
            case 0x66: case 0x67: // Operand/Address size
                continue;

#if SWIFTHOOK_X64
                // REX prefixes (x64 only)
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                continue;
#endif

            default:
                hasPrefix = false;
                break;
            }
        }

        // Opcode
        byte = pCode[len - 1]; // We already read one byte

        // Two-byte opcode
        if (byte == 0x0F) {
            if (len >= 15) return 0; // Safety check
            byte = pCode[len++];

            // Three-byte opcode
            if (byte == 0x38 || byte == 0x3A) {
                if (len >= 15) return 0;
                len++;
            }
        }

        // ModR/M byte
        bool hasModRM = true;
        bool hasSIB = false;
        uint8_t mod = 0;

        // Check if instruction has ModR/M
        // This is a simplified check - real disassembler would have lookup tables
        if (byte >= 0x80 && byte <= 0x8F) hasModRM = true;
        else if (byte >= 0xC0 && byte <= 0xC1) hasModRM = true;
        else if (byte >= 0xD0 && byte <= 0xD3) hasModRM = true;
        else if (byte == 0x69 || byte == 0x6B) hasModRM = true;
        else if (byte >= 0x80 && byte <= 0x83) hasModRM = true;
        else hasModRM = false;

        if (hasModRM) {
            if (len >= 15) return 0;
            uint8_t modrm = pCode[len++];
            mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            // SIB byte
#if SWIFTHOOK_X64
            if (rm == 4 && mod != 3) {
#else
            if (rm == 4 && mod != 3) {
#endif
                if (len >= 15) return 0;
                hasSIB = true;
                len++;
            }

            // Displacement
            if (mod == 1) {
                len += 1; // disp8
            }
            else if (mod == 2) {
                len += 4; // disp32
            }
            else if (mod == 0 && rm == 5) {
                len += 4; // disp32
            }
            }

        // Immediate
        // Simplified - would need opcode table for accuracy
        if (byte == 0xE8 || byte == 0xE9) {
            len += 4; // rel32
        }
        else if (byte >= 0xB8 && byte <= 0xBF) {
#if SWIFTHOOK_X64
            len += 8; // imm64 for MOV reg, imm
#else
            len += 4; // imm32
#endif
        }

        // Safety check
        if (len > 15) return 0;

        return len;
        }

#endif // SWIFTHOOK_X64 || SWIFTHOOK_X86

    size_t Disassembler::GetInstructionLength(const void* pCode) {
        if (!pCode) return 0;

#if SWIFTHOOK_X64 || SWIFTHOOK_X86
        return GetX86InstructionLength(static_cast<const uint8_t*>(pCode));
#else
        // ARM/ARM64 instructions are fixed length
        return 4;
#endif
    }

    size_t Disassembler::CopyInstructions(void* pDest, const void* pSrc,
        size_t minLength, size_t maxLength) {
        if (!pDest || !pSrc || minLength == 0 || maxLength < minLength) {
            return 0;
        }

        const uint8_t* src = static_cast<const uint8_t*>(pSrc);
        uint8_t* dest = static_cast<uint8_t*>(pDest);
        size_t totalLen = 0;

        while (totalLen < minLength) {
            size_t instrLen = GetInstructionLength(src + totalLen);

            if (instrLen == 0 || totalLen + instrLen > maxLength) {
                return 0; // Error: invalid instruction or buffer overflow
            }

            std::memcpy(dest + totalLen, src + totalLen, instrLen);
            totalLen += instrLen;
        }

        return totalLen;
    }

    bool Disassembler::IsHookable(const void* pCode, size_t requiredLength) {
        if (!pCode || requiredLength == 0) return false;

        const uint8_t* code = static_cast<const uint8_t*>(pCode);
        size_t totalLen = 0;

        while (totalLen < requiredLength) {
            size_t instrLen = GetInstructionLength(code + totalLen);

            if (instrLen == 0) {
                return false; // Invalid instruction
            }

            totalLen += instrLen;

            // Check for instructions that can't be relocated easily
            // This is simplified - full implementation would check for:
            // - RIP-relative instructions
            // - Short jumps
            // - etc.
        }

        return true;
    }

    } // namespace SwiftHook