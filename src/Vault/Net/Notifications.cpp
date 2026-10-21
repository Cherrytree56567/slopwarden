#include "Notifications.h"

#include <optional>
#include <type_traits>  // msgpack expects this to be included already
#include <msgpack.hpp>

namespace ClientWarden {
    namespace {
        constexpr int InvocationMessage = 1;

        /*
         * SignalR prefixes each binary message with its length as a
         * little-endian base-128 varint of at most 5 bytes.
        */
        bool ReadLength(std::string_view frame, size_t& pos, size_t& length) {
            length = 0;
            for (int shift = 0; shift < 35 && pos < frame.size(); shift += 7) {
                auto byte = static_cast<uint8_t>(frame[pos++]);
                length |= static_cast<size_t>(byte & 0x7f) << shift;
                if (!(byte & 0x80)) {
                    return true;
                }
            }
            return false;
        }

        bool IsInt(const msgpack::object& o) {
            return o.type == msgpack::type::POSITIVE_INTEGER || o.type == msgpack::type::NEGATIVE_INTEGER;
        }

        std::optional<PushType> TypeOf(const msgpack::object& message) {
            if (message.type != msgpack::type::ARRAY || message.via.array.size < 5) {
                return std::nullopt;
            }
            const auto& fields = message.via.array.ptr;
            if (!IsInt(fields[0]) || fields[0].as<int>() != InvocationMessage) {
                return std::nullopt;
            }

            const auto& args = fields[4];
            if (args.type != msgpack::type::ARRAY || args.via.array.size < 1 || args.via.array.ptr[0].type != msgpack::type::MAP) {
                return std::nullopt;
            }

            const auto& map = args.via.array.ptr[0].via.map;
            for (uint32_t i = 0; i < map.size; ++i) {
                const auto& kv = map.ptr[i];
                if (kv.key.type == msgpack::type::STR && kv.key.as<std::string_view>() == "Type" && IsInt(kv.val)) {
                    return static_cast<PushType>(kv.val.as<int>());
                }
            }
            return std::nullopt;
        }
    }

    std::vector<PushType> ParseNotificationFrame(std::string_view frame) {
        std::vector<PushType> out;

        size_t pos = 0;
        while (pos < frame.size()) {
            size_t length = 0;
            if (!ReadLength(frame, pos, length) || length > frame.size() - pos) {
                break;
            }

            try {
                msgpack::object_handle oh = msgpack::unpack(frame.data() + pos, length);
                if (auto type = TypeOf(oh.get())) {
                    out.push_back(*type);
                }
            } catch (const std::exception&) {
                // Not a MessagePack invocation (e.g. the JSON handshake reply).
            }
            pos += length;
        }
        return out;
    }
}
