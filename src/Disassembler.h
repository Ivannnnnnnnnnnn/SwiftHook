#pragma once

#include <cstdint>
#include <cstddef>

namespace SwiftHook {

    /**
     * @brief Length disassembler for x86/x64 instructions
     *
     * This class provides functionality to determine the length of machine code
     * instructions, which is essential for safely copying instructions when
     * creating trampolines.
     */
    class Disassembler {
    public:
        /**
         * @brief Get the length of a single instruction
         * @param pCode Pointer to the instruction
         * @return Length in bytes, or 0 if invalid
         */
        static size_t GetInstructionLength(const void* pCode);

        /**
         * @brief Copy instructions until at least minLength bytes are copied
         * @param pDest Destination buffer
         * @param pSrc Source code
         * @param minLength Minimum number of bytes to copy
         * @param maxLength Maximum buffer size
         * @return Number of bytes copied, or 0 on error
         */
        static size_t CopyInstructions(void* pDest, const void* pSrc,
            size_t minLength, size_t maxLength);

        /**
         * @brief Check if code can be safely hooked
         * @param pCode Pointer to code
         * @param requiredLength Minimum length needed for hook
         * @return true if hookable, false otherwise
         */
        static bool IsHookable(const void* pCode, size_t requiredLength);

    private:
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
        /**
         * @brief Get x86/x64 instruction length
         */
        static size_t GetX86InstructionLength(const uint8_t* pCode);
#endif
    };

} // namespace SwiftHook