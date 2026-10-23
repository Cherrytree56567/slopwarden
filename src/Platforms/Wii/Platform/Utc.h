#pragma once
#include <cstdint>
#include <string_view>

/*
 * Corrects the console clock to UTC. The Wii keeps local time with no time zone, so the
 * difference to a server's Date header (time zone plus drift) is the correction. It is kept
 * in data/clock.txt for starts before the network is up.
 */
namespace clientwarden::wii::utc {
    /**
     * @brief The seconds to add to the console clock to get UTC.
     */
    int64_t offsetSeconds();

    /**
     * @brief Learns the offset from an HTTP Date header ("Tue, 21 Oct 2026 11:22:09 GMT").
     *
     * @param date_header The header value
     */
    void observeServerDate(std::string_view date_header);

    /**
     * @brief Loads the saved offset; call once the SD card is mounted.
     */
    void load();
}
