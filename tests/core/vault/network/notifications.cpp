#include <catch2/catch_test_macros.hpp>
#include <type_traits>
#include <msgpack.hpp>

#include "utils/encoding/encoding.h"
#include "vault/network/network.h"

using namespace clientwarden;

namespace {
    /**
     * @brief Builds a framed SignalR MessagePack invocation:
     * [1, {}, null, "ReceiveMessage", [{Type: n, Payload: {Id: "abc"}}]]
     */
    SecureBytes invocation(int type) {
        msgpack::sbuffer buffer;
        msgpack::packer<msgpack::sbuffer> packer(buffer);
        packer.pack_array(5);
        packer.pack(1);
        packer.pack_map(0);
        packer.pack_nil();
        packer.pack(std::string_view("ReceiveMessage"));
        packer.pack_array(1);
        packer.pack_map(2);
        packer.pack(std::string_view("Type"));
        packer.pack(type);
        packer.pack(std::string_view("Payload"));
        packer.pack_map(1);
        packer.pack(std::string_view("Id"));
        packer.pack(std::string_view("abc"));

        SecureBytes framed;
        size_t length = buffer.size();
        do {
            uint8_t byte = static_cast<uint8_t>(length & 0x7f);
            length >>= 7;
            if (length) {
                byte |= 0x80;
            }
            framed.push_back(byte);
        } while (length);
        framed.insert(framed.end(), buffer.data(), buffer.data() + buffer.size());
        return framed;
    }

    /**
     * @brief Concatenates two frames.
     */
    SecureBytes join(SecureBytes a, SecureBytes b) {
        a.insert(a.end(), b.begin(), b.end());
        return a;
    }
}

TEST_CASE("Parses push notifications") {
    REQUIRE(parseNotificationFrame(invocation(0)) == std::vector<PushType> { PushType::SyncCipherUpdate });
    REQUIRE(parseNotificationFrame(invocation(11)) == std::vector<PushType> { PushType::LogOut });
}

TEST_CASE("Parses several messages in one frame") {
    REQUIRE(parseNotificationFrame(join(invocation(1), invocation(7))) ==
        std::vector<PushType> { PushType::SyncCipherCreate, PushType::SyncFolderCreate });
}

TEST_CASE("Malformed frames are ignored, not trusted") {
    REQUIRE(parseNotificationFrame(SecureBytes()).empty());
    REQUIRE(parseNotificationFrame(encoding::bytesOf("{}\x1e")).empty());
    REQUIRE(parseNotificationFrame(SecureBytes(6, 0xff)).empty());
    REQUIRE(parseNotificationFrame(SecureBytes { 0x7f }).empty());     // length beyond frame

    SecureBytes truncated = invocation(0);
    truncated.resize(truncated.size() - 3);
    REQUIRE(parseNotificationFrame(truncated).empty());

    msgpack::sbuffer buffer;
    msgpack::pack(buffer, 42);
    SecureBytes not_array = { static_cast<uint8_t>(buffer.size()) };
    not_array.insert(not_array.end(), buffer.data(), buffer.data() + buffer.size());
    REQUIRE(parseNotificationFrame(not_array).empty());
}
