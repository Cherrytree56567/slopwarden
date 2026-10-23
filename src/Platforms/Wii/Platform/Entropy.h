#pragma once
#include <cstddef>
#include <cstdint>

/*
 * The Wii has no operating system random generator, so ClientWarden gathers its own: noise
 * from the Wii Remote's accelerometer and IR camera while the user moves it, together with
 * the CPU timebase at each sample (the jitter between when the remote reports and when we read
 * it). Everything goes into a SHA-512 pool; once enough has been credited the pool seeds a
 * ChaCha20 generator, which backs clientwarden::random::secure() for the rest of the run.
 * Nothing secret is generated before then: random::secure() throws until the pool is ready.
 */
namespace clientwarden::wii::entropy {
    /**
     * @brief How many bits must be credited before the generator is seeded.
     */
    constexpr size_t c_required_bits = 256;

    /**
     * @brief Mixes one Wii Remote reading into the pool, crediting it conservatively (at most a
     * bit or two, and only when the reading differs from the last one).
     *
     * @param accel_x Raw accelerometer X (10-bit)
     * @param accel_y Raw accelerometer Y
     * @param accel_z Raw accelerometer Z
     * @param ir_x IR pointer X in raw camera units, or -1 if not visible
     * @param ir_y IR pointer Y, or -1
     */
    void addWiimoteSample(int accel_x, int accel_y, int accel_z, int ir_x, int ir_y);

    /**
     * @brief Mixes uncredited data into the pool (timings, button presses, anything that might
     * help but can't be relied on).
     *
     * @param data The bytes
     * @param size Their length
     */
    void addUncredited(const void* data, size_t size);

    /**
     * @brief The bits credited so far, capped at c_required_bits.
     */
    size_t creditedBits();

    /**
     * @brief Whether the generator has been seeded (creditedBits() reached c_required_bits).
     */
    bool ready();

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    /**
     * @brief Test builds only (Dolphin, whose emulated remote is still): credits the pool as if
     * the remote had moved. Never compiled into release builds.
     */
    void creditForTesting();
#endif
}
