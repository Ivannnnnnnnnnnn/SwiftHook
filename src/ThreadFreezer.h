#pragma once

#include <cstdint>

namespace SwiftHook {

    /**
     * @brief Thread freezing utility for safe hook installation
     *
     * When installing or removing hooks, we need to freeze all other threads
     * to prevent them from executing code that we're modifying. This class
     * provides safe thread suspension and resumption.
     */
    class ThreadFreezer {
    public:
        ThreadFreezer();
        ~ThreadFreezer();

        // Non-copyable
        ThreadFreezer(const ThreadFreezer&) = delete;
        ThreadFreezer& operator=(const ThreadFreezer&) = delete;

        /**
         * @brief Freeze all threads except the current one
         * @return true on success, false on failure
         */
        bool Freeze();

        /**
         * @brief Resume all frozen threads
         * @return true on success, false on failure
         */
        bool Unfreeze();

        /**
         * @brief Check if threads are currently frozen
         */
        bool IsFrozen() const;

        /**
         * @brief Get the number of frozen threads
         */
        size_t GetFrozenCount() const;

    private:
        struct Impl;
        Impl* pImpl;

#if defined(_WIN32) || defined(_WIN64)
        /**
         * @brief Enumerate and suspend Windows threads
         */
        bool FreezeWindows();

        /**
         * @brief Resume Windows threads
         */
        bool UnfreezeWindows();
#else
        /**
         * @brief Freeze threads on Unix-like systems
         */
        bool FreezeUnix();

        /**
         * @brief Resume Unix threads
         */
        bool UnfreezeUnix();
#endif
    };

    /**
     * @brief RAII wrapper for thread freezing
     */
    class ScopedThreadFreezer {
    public:
        explicit ScopedThreadFreezer(ThreadFreezer& freezer)
            : m_freezer(freezer), m_frozen(false) {
            m_frozen = m_freezer.Freeze();
        }

        ~ScopedThreadFreezer() {
            if (m_frozen) {
                m_freezer.Unfreeze();
            }
        }

        bool IsValid() const { return m_frozen; }

        // Non-copyable, non-movable
        ScopedThreadFreezer(const ScopedThreadFreezer&) = delete;
        ScopedThreadFreezer& operator=(const ScopedThreadFreezer&) = delete;

    private:
        ThreadFreezer& m_freezer;
        bool m_frozen;
    };

} // namespace SwiftHook