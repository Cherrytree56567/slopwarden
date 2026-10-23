#include <ogc/irq.h>

#include <cstdint>

/*
 * 64-bit atomics for the core's std::atomic<std::int64_t>. 32-bit PowerPC has no 64-bit
 * atomic instructions and devkitPPC ships no libatomic, so GCC calls these. The Wii's CPU has
 * a single core, so masking interrupts around the access is enough to make it atomic.
 */
namespace {
    struct InterruptsOff {
        std::uint32_t m_level = IRQ_Disable();
        ~InterruptsOff() { IRQ_Restore(m_level); }
    };
}

extern "C" {
std::uint64_t __atomic_load_8(const volatile void* ptr, int) {
    InterruptsOff off;
    return *static_cast<const volatile std::uint64_t*>(ptr);
}

void __atomic_store_8(volatile void* ptr, std::uint64_t value, int) {
    InterruptsOff off;
    *static_cast<volatile std::uint64_t*>(ptr) = value;
}

std::uint64_t __atomic_exchange_8(volatile void* ptr, std::uint64_t value, int) {
    InterruptsOff off;
    volatile std::uint64_t* p = static_cast<volatile std::uint64_t*>(ptr);
    std::uint64_t old = *p;
    *p = value;
    return old;
}

bool __atomic_compare_exchange_8(volatile void* ptr, void* expected, std::uint64_t desired, bool, int, int) {
    InterruptsOff off;
    volatile std::uint64_t* p = static_cast<volatile std::uint64_t*>(ptr);
    std::uint64_t* e = static_cast<std::uint64_t*>(expected);
    if (*p == *e) {
        *p = desired;
        return true;
    }
    *e = *p;
    return false;
}

std::uint64_t __atomic_fetch_add_8(volatile void* ptr, std::uint64_t value, int) {
    InterruptsOff off;
    volatile std::uint64_t* p = static_cast<volatile std::uint64_t*>(ptr);
    std::uint64_t old = *p;
    *p = old + value;
    return old;
}

std::uint64_t __atomic_fetch_sub_8(volatile void* ptr, std::uint64_t value, int) {
    InterruptsOff off;
    volatile std::uint64_t* p = static_cast<volatile std::uint64_t*>(ptr);
    std::uint64_t old = *p;
    *p = old - value;
    return old;
}
}
