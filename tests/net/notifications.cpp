#include <catch2/catch_test_macros.hpp>
#include <msgpack.hpp>
#include "Net/Notifications.h"

using namespace ClientWarden;

namespace {
    /*
     * Builds a SignalR MessagePack invocation: [1, {}, null, "ReceiveMessage", [{Type: n, Payload: {...}}]]
    */
    std::string Invocation(int type) {
        msgpack::sbuffer buf;
        msgpack::packer<msgpack::sbuffer> pk(buf);
        pk.pack_array(5);
        pk.pack(1);
        pk.pack_map(0);
        pk.pack_nil();
        pk.pack(std::string("ReceiveMessage"));
        pk.pack_array(1);
        pk.pack_map(2);
        pk.pack(std::string("Type"));
        pk.pack(type);
        pk.pack(std::string("Payload"));
        pk.pack_map(1);
        pk.pack(std::string("Id"));
        pk.pack(std::string("abc"));

        std::string body(buf.data(), buf.size());
        std::string framed;
        size_t len = body.size();
        do {
            uint8_t b = len & 0x7f;
            len >>= 7;
            if (len) b |= 0x80;
            framed.push_back(static_cast<char>(b));
        } while (len);
        return framed + body;
    }
}

TEST_CASE("Parses push notifications") {
    REQUIRE(ParseNotificationFrame(Invocation(0)) == std::vector<PushType> { PushType::SyncCipherUpdate });
    REQUIRE(ParseNotificationFrame(Invocation(11)) == std::vector<PushType> { PushType::LogOut });
}

TEST_CASE("Parses several messages in one frame") {
    REQUIRE(ParseNotificationFrame(Invocation(1) + Invocation(7)) == std::vector<PushType> { PushType::SyncCipherCreate, PushType::SyncFolderCreate });
}

TEST_CASE("Malformed frames are ignored, not trusted") {
    REQUIRE(ParseNotificationFrame("").empty());
    REQUIRE(ParseNotificationFrame("{}\x1e").empty());
    REQUIRE(ParseNotificationFrame(std::string("\xff\xff\xff\xff\xff\xff", 6)).empty());
    REQUIRE(ParseNotificationFrame(std::string("\x7f", 1)).empty());       // length beyond frame

    std::string truncated = Invocation(0);
    truncated.resize(truncated.size() - 3);
    REQUIRE(ParseNotificationFrame(truncated).empty());

    msgpack::sbuffer buf;
    msgpack::pack(buf, 42);
    std::string notArray = std::string(1, static_cast<char>(buf.size())) + std::string(buf.data(), buf.size());
    REQUIRE(ParseNotificationFrame(notArray).empty());
}
