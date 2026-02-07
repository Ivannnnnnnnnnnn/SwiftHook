#include "TrampolineAllocator.h"
#include "Config.h"
#include <vector>
#include <mutex>

#if SWIFTHOOK_WINDOWS
#include <Windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace SwiftHook {

    struct MemoryBlock {
        void* pAddress;
        size_t size;
        size_t used;
    };

    struct TrampolineAllocator::Impl {
        std::vector<MemoryBlock> blocks;
        std::mutex mutex;

        static constexpr size_t BLOCK_SIZE = 4096; // One page
        static constexpr size_t MAX_DISTANCE = 0x7FF00000; // ~2GB for x64 relative jumps
    };

    TrampolineAllocator::TrampolineAllocator()
        : pImpl(new Impl()) {
    }

    TrampolineAllocator::~TrampolineAllocator() {
        FreeAll();
        delete pImpl;
    }

    bool TrampolineAllocator::IsInRelativeJumpRange(void* pFrom, void* pTo) {
#if SWIFTHOOK_X64
        // On x64, relative jumps are limited to ±2GB
        intptr_t from = reinterpret_cast<intptr_t>(pFrom);
        intptr_t to = reinterpret_cast<intptr_t>(pTo);
        intptr_t diff = to - from;

        return (diff >= -0x7FFFFFFF && diff <= 0x7FFFFFFF);
#else
        // On x86, we can reach anywhere
        SWIFTHOOK_UNUSED(pFrom);
        SWIFTHOOK_UNUSED(pTo);
        return true;
#endif
    }

    void* TrampolineAllocator::FindNearbyMemory(void* pTarget, size_t size) {
#if SWIFTHOOK_WINDOWS
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        uintptr_t target = reinterpret_cast<uintptr_t>(pTarget);
        uintptr_t minAddr = (target > Impl::MAX_DISTANCE) ?
            (target - Impl::MAX_DISTANCE) : 0;
        uintptr_t maxAddr = target + Impl::MAX_DISTANCE;

        // Align to allocation granularity
        minAddr = (minAddr / si.dwAllocationGranularity) * si.dwAllocationGranularity;

        // Try to allocate near the target
        for (uintptr_t addr = minAddr; addr < maxAddr; addr += si.dwAllocationGranularity) {
            void* pMem = VirtualAlloc(
                reinterpret_cast<void*>(addr),
                Impl::BLOCK_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (pMem && IsInRelativeJumpRange(pTarget, pMem)) {
                return pMem;
            }

            if (pMem) {
                VirtualFree(pMem, 0, MEM_RELEASE);
            }
        }

        // Fallback: let the system choose
        return VirtualAlloc(nullptr, Impl::BLOCK_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
        // Unix-like systems
        SWIFTHOOK_UNUSED(pTarget);

        void* pMem = mmap(nullptr, Impl::BLOCK_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        return (pMem == MAP_FAILED) ? nullptr : pMem;
#endif
    }

    void* TrampolineAllocator::Allocate(void* pTarget, size_t size) {
        if (!pTarget || size == 0 || size > Impl::BLOCK_SIZE) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lock(pImpl->mutex);

        // Try to find space in existing blocks
        for (auto& block : pImpl->blocks) {
            if (block.used + size <= block.size &&
                IsInRelativeJumpRange(pTarget, block.pAddress)) {
                void* pResult = static_cast<uint8_t*>(block.pAddress) + block.used;
                block.used += size;
                return pResult;
            }
        }

        // Need to allocate a new block
        void* pNewBlock = FindNearbyMemory(pTarget, size);
        if (!pNewBlock) {
            return nullptr;
        }

        MemoryBlock block;
        block.pAddress = pNewBlock;
        block.size = Impl::BLOCK_SIZE;
        block.used = size;

        pImpl->blocks.push_back(block);

        return pNewBlock;
    }

    bool TrampolineAllocator::Free(void* pMemory) {
        if (!pMemory) return false;

        std::lock_guard<std::mutex> lock(pImpl->mutex);

        // Note: This is simplified. A real implementation would track
        // individual allocations within blocks for proper freeing.
        // For now, we only free entire blocks in FreeAll().

        SWIFTHOOK_UNUSED(pMemory);
        return true;
    }

    void TrampolineAllocator::FreeAll() {
        std::lock_guard<std::mutex> lock(pImpl->mutex);

        for (auto& block : pImpl->blocks) {
#if SWIFTHOOK_WINDOWS
            VirtualFree(block.pAddress, 0, MEM_RELEASE);
#else
            munmap(block.pAddress, block.size);
#endif
        }

        pImpl->blocks.clear();
    }

    size_t TrampolineAllocator::GetAllocationCount() const {
        std::lock_guard<std::mutex> lock(pImpl->mutex);
        return pImpl->blocks.size();
    }

} // namespace SwiftHook