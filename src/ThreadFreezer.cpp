#include "ThreadFreezer.h"
#include "Config.h"
#include <vector>

#if SWIFTHOOK_WINDOWS
#include <Windows.h>
#include <TlHelp32.h>
#else
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace SwiftHook {

    struct ThreadInfo {
#if SWIFTHOOK_WINDOWS
        DWORD threadId;
        HANDLE handle;
#else
        pthread_t thread;
#endif
    };

    struct ThreadFreezer::Impl {
        std::vector<ThreadInfo> frozenThreads;
        bool isFrozen;

#if SWIFTHOOK_WINDOWS
        DWORD currentThreadId;
        DWORD currentProcessId;
#else
        pthread_t currentThread;
#endif

        Impl() : isFrozen(false) {
#if SWIFTHOOK_WINDOWS
            currentThreadId = GetCurrentThreadId();
            currentProcessId = GetCurrentProcessId();
#else
            currentThread = pthread_self();
#endif
        }
    };

    ThreadFreezer::ThreadFreezer()
        : pImpl(new Impl()) {
    }

    ThreadFreezer::~ThreadFreezer() {
        if (pImpl->isFrozen) {
            Unfreeze();
        }
        delete pImpl;
    }

#if SWIFTHOOK_WINDOWS

    bool ThreadFreezer::FreezeWindows() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hSnapshot, &te32)) {
            CloseHandle(hSnapshot);
            return false;
        }

        bool success = true;

        do {
            // Skip threads not belonging to our process
            if (te32.th32OwnerProcessID != pImpl->currentProcessId) {
                continue;
            }

            // Skip current thread
            if (te32.th32ThreadID == pImpl->currentThreadId) {
                continue;
            }

            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                DWORD suspendCount = SuspendThread(hThread);
                if (suspendCount != (DWORD)-1) {
                    ThreadInfo info;
                    info.threadId = te32.th32ThreadID;
                    info.handle = hThread;
                    pImpl->frozenThreads.push_back(info);
                }
                else {
                    CloseHandle(hThread);
                    success = false;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));

        CloseHandle(hSnapshot);
        return success;
    }

    bool ThreadFreezer::UnfreezeWindows() {
        bool success = true;

        for (auto& info : pImpl->frozenThreads) {
            if (ResumeThread(info.handle) == (DWORD)-1) {
                success = false;
            }
            CloseHandle(info.handle);
        }

        pImpl->frozenThreads.clear();
        return success;
    }

#else // Unix systems

    bool ThreadFreezer::FreezeUnix() {
        //TODO
        return true;
    }

    bool ThreadFreezer::UnfreezeUnix() {
        //TODO
        pImpl->frozenThreads.clear();
        return true;
    }

#endif

    bool ThreadFreezer::Freeze() {
        if (pImpl->isFrozen) {
            return false; // Already frozen
        }

#if SWIFTHOOK_WINDOWS
        bool result = FreezeWindows();
#else
        bool result = FreezeUnix();
#endif

        if (result) {
            pImpl->isFrozen = true;
        }

        return result;
    }

    bool ThreadFreezer::Unfreeze() {
        if (!pImpl->isFrozen) {
            return false; // Not frozen
        }

#if SWIFTHOOK_WINDOWS
        bool result = UnfreezeWindows();
#else
        bool result = UnfreezeUnix();
#endif

        if (result) {
            pImpl->isFrozen = false;
        }

        return result;
    }

    bool ThreadFreezer::IsFrozen() const {
        return pImpl->isFrozen;
    }

    size_t ThreadFreezer::GetFrozenCount() const {
        return pImpl->frozenThreads.size();
    }

} // namespace SwiftHook