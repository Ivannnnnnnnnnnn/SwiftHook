#pragma once

#include <cstdint>
#include <cstddef>

namespace SwiftHook {

    /**
     * @brief Manages allocation of memory for trampolines
     *
     * Trampolines are small code stubs that contain the original instructions
     * from the hooked function plus a jump back to the rest of the function.
     * They must be allocated close to the original function (within 2GB on x64)
     * to allow for relative jumps.
     */
    class TrampolineAllocator {
    public:
        TrampolineAllocator();
        ~TrampolineAllocator();

        // Non-copyable
        TrampolineAllocator(const TrampolineAllocator&) = delete;
        TrampolineAllocator& operator=(const TrampolineAllocator&) = delete;

        /**
         * @brief Allocate memory for a trampoline near the target address
         * @param pTarget Target function address
         * @param size Size in bytes to allocate
         * @return Pointer to allocated memory, or nullptr on failure
         */
        void* Allocate(void* pTarget, size_t size);

        /**
         * @brief Free previously allocated trampoline memory
         * @param pMemory Pointer to memory to free
         * @return true on success, false on failure
         */
        bool Free(void* pMemory);

        /**
         * @brief Free all allocated trampolines
         */
        void FreeAll();

        /**
         * @brief Get the number of allocated trampolines
         */
        size_t GetAllocationCount() const;

    private:
        struct Impl;
        Impl* pImpl;

        /**
         * @brief Find or allocate a memory block near the target
         */
        void* FindNearbyMemory(void* pTarget, size_t size);

        /**
         * @brief Check if an address is within relative jump range
         */
        static bool IsInRelativeJumpRange(void* pFrom, void* pTo);
    };

} // namespace SwiftHook