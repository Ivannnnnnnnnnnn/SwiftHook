#include "Disassembler.h"
#include "Config.h"
#include <cstring>
#include <limits>

namespace SwiftHook {

#if SWIFTHOOK_X64 || SWIFTHOOK_X86

    namespace {
        bool IsPrefixByte(uint8_t byte) {
            switch (byte) {
            case 0xF0: case 0xF2: case 0xF3:
            case 0x2E: case 0x36: case 0x3E: case 0x26:
            case 0x64: case 0x65:
            case 0x66: case 0x67:
                return true;
#if SWIFTHOOK_X64
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                return true;
#endif
            default:
                return false;
            }
        }

        bool DecodeRelativeBranch(const uint8_t* code, size_t len,
            size_t* dispOffset, size_t* dispSize) {
            if (!code || len == 0 || !dispOffset || !dispSize) {
                return false;
            }

            size_t offset = 0;
            while (offset < len && IsPrefixByte(code[offset])) {
                offset++;
            }
            if (offset >= len) return false;

            uint8_t op = code[offset];
            if (op == 0x0F) {
                if (offset + 1 >= len) return false;
                uint8_t op2 = code[offset + 1];
                if (op2 >= 0x80 && op2 <= 0x8F) {
                    *dispOffset = offset + 2;
                    *dispSize = 4;
                    return (offset + 2 + 4) <= len;
                }
                return false;
            }

            if (op == 0xE8 || op == 0xE9) {
                *dispOffset = offset + 1;
                *dispSize = 4;
                return (offset + 1 + 4) <= len;
            }

            if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) {
                *dispOffset = offset + 1;
                *dispSize = 1;
                return (offset + 1 + 1) <= len;
            }

            return false;
        }
    }

    // Simplified x86/x64 length disassembler
    // Based on Hacker Disassembler Engine (HDE)
    size_t Disassembler::GetX86InstructionLength(const uint8_t* pCode) {
        if (!pCode) return 0;

        size_t len = 0;
        uint8_t byte;

        // Prefix bytes
        bool hasPrefix = true;
        bool hasOpSizePrefix = false;
        while (hasPrefix) {
            byte = pCode[len++];
            switch (byte) {
                // Legacy prefixes
            case 0xF0: case 0xF2: case 0xF3: // LOCK, REPNE, REP
            case 0x2E: case 0x36: case 0x3E: case 0x26: // Segment overrides
            case 0x64: case 0x65: // FS, GS
            case 0x67: // Address size
                continue;
            case 0x66: // Operand size
                hasOpSizePrefix = true;
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

        bool isTwoByteOpcode = false;
        uint8_t secondOpcode = 0;

        // Two-byte opcode
        if (byte == 0x0F) {
            if (len >= 15) return 0; // Safety check
            isTwoByteOpcode = true;
            secondOpcode = pCode[len++];
            byte = secondOpcode;

            // Three-byte opcode
            if (byte == 0x38 || byte == 0x3A) {
                if (len >= 15) return 0;
                byte = pCode[len++];
            }
        }

        // ModR/M byte
        bool hasModRM = false;
        bool hasSIB = false;
        uint8_t mod = 0;

        // Check if instruction has ModR/M
        // This is a simplified check - real disassembler would have lookup tables
        if (isTwoByteOpcode) {
            // Most 0x0F opcodes use ModR/M, with a few exceptions.
            hasModRM = true;
            if (secondOpcode == 0x05 || secondOpcode == 0x31 ||
                (secondOpcode >= 0x80 && secondOpcode <= 0x8F)) { // SYSCALL/RDTSC/Jcc
                hasModRM = false;
            }
        }
        else if (byte <= 0x3F) {
            // AL/EAX immediate forms don't use ModR/M
            switch (byte) {
            case 0x04: case 0x05:
            case 0x0C: case 0x0D:
            case 0x14: case 0x15:
            case 0x1C: case 0x1D:
            case 0x24: case 0x25:
            case 0x2C: case 0x2D:
            case 0x34: case 0x35:
            case 0x3C: case 0x3D:
                hasModRM = false;
                break;
            default:
                hasModRM = true;
                break;
            }
        }
        else if (byte >= 0x80 && byte <= 0x8F) {
            hasModRM = true;
        }
        else if (byte == 0x8D || byte == 0xC6 || byte == 0xC7) {
            hasModRM = true;
        }
        else if (byte >= 0xC0 && byte <= 0xC1) {
            hasModRM = true;
        }
        else if (byte >= 0xD0 && byte <= 0xD3) {
            hasModRM = true;
        }
        else if (byte == 0x69 || byte == 0x6B) {
            hasModRM = true;
        }
        else if (byte == 0xF6 || byte == 0xF7 || byte == 0xFE || byte == 0xFF) {
            hasModRM = true;
        }

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
        size_t immSize = 0;
        if (isTwoByteOpcode && secondOpcode >= 0x80 && secondOpcode <= 0x8F) {
            immSize = 4; // Jcc rel32
        }
        else if (byte >= 0x70 && byte <= 0x7F) {
            immSize = 1; // Jcc rel8
        }
        else {
            switch (byte) {
            case 0xE8: // CALL rel32
            case 0xE9: // JMP rel32
                immSize = 4;
                break;
            case 0xEB: // JMP rel8
                immSize = 1;
                break;
            case 0x68: // PUSH imm32
                immSize = 4;
                break;
            case 0x6A: // PUSH imm8
                immSize = 1;
                break;
            case 0x69: // IMUL r, r/m, imm32
                immSize = 4;
                break;
            case 0x6B: // IMUL r, r/m, imm8
                immSize = 1;
                break;
            case 0x80: // GRP1 r/m, imm8
            case 0x82: // GRP1 r/m, imm8 (undefined on some CPUs)
            case 0x83: // GRP1 r/m, imm8
            case 0xC6: // MOV r/m, imm8
                immSize = 1;
                break;
            case 0x81: // GRP1 r/m, imm32
            case 0xC7: // MOV r/m, imm32
                immSize = 4;
                break;
            case 0xA8: // TEST AL, imm8
                immSize = 1;
                break;
            case 0xA9: // TEST EAX, imm32
                immSize = 4;
                break;
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
                immSize = 1; // AL, imm8
                break;
            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
                immSize = 4; // EAX, imm32
                break;
            case 0xC2: // RET imm16
                immSize = 2;
                break;
            default:
                break;
            }
        }

        if (byte >= 0xB8 && byte <= 0xBF) {
#if SWIFTHOOK_X64
            immSize = 8; // imm64 for MOV reg, imm
#else
            immSize = 4; // imm32
#endif
        }

#if !SWIFTHOOK_X64
        if (hasOpSizePrefix && immSize == 4) {
            immSize = 2;
        }
#endif

        len += immSize;

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

#if SWIFTHOOK_X64 || SWIFTHOOK_X86
            size_t dispOffset = 0;
            size_t dispSize = 0;
            if (DecodeRelativeBranch(src + totalLen, instrLen, &dispOffset, &dispSize)) {
                const uint8_t* srcInstr = src + totalLen;
                uint8_t* dstInstr = dest + totalLen;

                intptr_t srcNext = reinterpret_cast<intptr_t>(srcInstr + instrLen);
                intptr_t dstNext = reinterpret_cast<intptr_t>(dstInstr + instrLen);

                if (dispSize == 1) {
                    int8_t disp8 = 0;
                    std::memcpy(&disp8, srcInstr + dispOffset, sizeof(disp8));
                    intptr_t target = srcNext + disp8;
                    intptr_t newDisp = target - dstNext;
                    if (newDisp < std::numeric_limits<int8_t>::min() ||
                        newDisp > std::numeric_limits<int8_t>::max()) {
                        return 0;
                    }
                    int8_t newDisp8 = static_cast<int8_t>(newDisp);
                    std::memcpy(dstInstr + dispOffset, &newDisp8, sizeof(newDisp8));
                }
                else if (dispSize == 4) {
                    int32_t disp32 = 0;
                    std::memcpy(&disp32, srcInstr + dispOffset, sizeof(disp32));
                    intptr_t target = srcNext + disp32;
                    intptr_t newDisp = target - dstNext;
                    if (newDisp < std::numeric_limits<int32_t>::min() ||
                        newDisp > std::numeric_limits<int32_t>::max()) {
                        return 0;
                    }
                    int32_t newDisp32 = static_cast<int32_t>(newDisp);
                    std::memcpy(dstInstr + dispOffset, &newDisp32, sizeof(newDisp32));
                }
            }
#endif
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
                return false;
            }
            totalLen += instrLen;
        }

        return true;
    }

    } // namespace SwiftHook
