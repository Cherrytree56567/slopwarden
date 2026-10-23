#include "Entropy.h"

#include <algorithm>
#include <array>
#include <memory>
#include <mutex>
#include <string>

#include <botan/chacha_rng.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <ogc/lwp_watchdog.h>

#include "platform/random/random.h"

namespace clientwarden::wii::entropy {
    namespace {
        /*
         * Credit is counted in half bits: one half bit per reading that differs from the last.
         * The accelerometer's low bits and the IR camera's sub-pixel position are noisy even
         * when the remote is held still, but nobody can say how noisy, so this stays well below
         * what the readings plausibly carry. 256 bits takes a few seconds of waving at 100 Hz.
         */
        constexpr size_t c_required_half_bits = c_required_bits * 2;

        struct Reading {
            int ax = -1, ay = -1, az = -1, irx = -1, iry = -1;

            bool operator==(const Reading&) const = default;
        };

        std::mutex g_mutex;
        std::unique_ptr<Botan::HashFunction> g_pool;
        size_t g_half_bits = 0;
        Reading g_last;
        std::unique_ptr<Botan::ChaCha_RNG> g_rng;

        Botan::HashFunction& pool_() {
            if (!g_pool) {
                g_pool = Botan::HashFunction::create_or_throw("SHA-512");
            }
            return *g_pool;
        }

        void mixTime_() {
            uint64_t ticks = gettime();
            pool_().update(reinterpret_cast<const uint8_t*>(&ticks), sizeof(ticks));
        }

        /*
         * Seeds the generator from the pool once enough is credited. The pool keeps running so
         * later readings still reach the generator.
         */
        void seedIfReady_() {
            if (g_rng || g_half_bits < c_required_half_bits) {
                return;
            }
            Botan::secure_vector<uint8_t> seed = pool_().final();
            g_rng = std::make_unique<Botan::ChaCha_RNG>(seed);
            pool_().update(seed);
        }

        /*
         * random::secure(): the ChaCha generator behind a lock, refusing to produce anything
         * until it has been seeded, and stirring in the timebase on every request.
         */
        class WiiRng final : public Botan::RandomNumberGenerator {
        public:
            bool accepts_input() const override { return true; }

            bool is_seeded() const override {
                std::lock_guard<std::mutex> lock(g_mutex);
                return g_rng != nullptr;
            }

            std::string name() const override { return "Wii entropy pool + ChaCha_RNG"; }

            void clear() override {}

        private:
            void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (!g_rng) {
                    throw Botan::PRNG_Unseeded("the Wii entropy pool isn't full yet");
                }
                uint64_t ticks = gettime();
                g_rng->add_entropy(reinterpret_cast<const uint8_t*>(&ticks), sizeof(ticks));
                if (!input.empty()) {
                    g_rng->add_entropy(input.data(), input.size());
                }
                if (!output.empty()) {
                    g_rng->randomize(output.data(), output.size());
                }
            }
        };
    }

    void addWiimoteSample(int accel_x, int accel_y, int accel_z, int ir_x, int ir_y) {
        std::lock_guard<std::mutex> lock(g_mutex);
        Reading reading { accel_x, accel_y, accel_z, ir_x, ir_y };
        std::array<int32_t, 5> values = { accel_x, accel_y, accel_z, ir_x, ir_y };
        mixTime_();
        pool_().update(reinterpret_cast<const uint8_t*>(values.data()), sizeof(values));

        if (!(reading == g_last) && accel_x >= 0) {
            ++g_half_bits;
        }
        g_last = reading;

        if (g_rng) {
            uint64_t ticks = gettime();
            g_rng->add_entropy(reinterpret_cast<const uint8_t*>(values.data()), sizeof(values));
            g_rng->add_entropy(reinterpret_cast<const uint8_t*>(&ticks), sizeof(ticks));
        }
        seedIfReady_();
    }

    void addUncredited(const void* data, size_t size) {
        std::lock_guard<std::mutex> lock(g_mutex);
        mixTime_();
        pool_().update(static_cast<const uint8_t*>(data), size);
        if (g_rng) {
            g_rng->add_entropy(static_cast<const uint8_t*>(data), size);
        }
    }

    size_t creditedBits() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return std::min(g_half_bits / 2, c_required_bits);
    }

    bool ready() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_rng != nullptr;
    }

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    void creditForTesting() {
        std::lock_guard<std::mutex> lock(g_mutex);
        mixTime_();
        g_half_bits = c_required_half_bits;
        seedIfReady_();
    }
#endif
}

namespace clientwarden::random {
    Botan::RandomNumberGenerator& secure() {
        static wii::entropy::WiiRng rng;
        return rng;
    }
}
