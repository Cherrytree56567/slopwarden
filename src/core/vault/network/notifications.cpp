#include <optional>
#include <type_traits> // msgpack expects this to be included already
#include <msgpack.hpp>

#include "network.h"

namespace clientwarden {
    namespace {
        constexpr int c_invocation_message = 1;

        /**
         * @brief Reads a SignalR length prefix (little-endian base-128 varint, at most 5 bytes).
         *
         * @param frame The frame
         * @param pos Read position; advanced past the prefix
         * @param length Receives the message length
         * @return False if the prefix is truncated or too long
         */
        bool readLength_(std::span<const uint8_t> frame, size_t& pos, size_t& length) {
            length = 0;
            for (int shift = 0; shift < 35 && pos < frame.size(); shift += 7) {
                uint8_t byte = frame[pos++];
                length |= static_cast<size_t>(byte & 0x7f) << shift;
                if (!(byte & 0x80)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Whether a msgpack object is an integer.
         *
         * @param object The object
         * @return True for positive or negative integers
         */
        bool isInt_(const msgpack::object& object) {
            return object.type == msgpack::type::POSITIVE_INTEGER ||
                   object.type == msgpack::type::NEGATIVE_INTEGER;
        }

        /**
         * @brief Extracts the push type from one invocation message.
         *
         * @param message [1, headers, invocationId, target, [ {Type: n, Payload: ...} ]]
         * @return The type, or nullopt if the message isn't a well-formed invocation
         */
        std::optional<PushType> typeOf_(const msgpack::object& message) {
            if (message.type != msgpack::type::ARRAY || message.via.array.size < 5) {
                return std::nullopt;
            }
            const msgpack::object& kind = message.via.array.ptr[0];
            if (!isInt_(kind) || kind.as<int>() != c_invocation_message) {
                return std::nullopt;
            }

            const msgpack::object& args = message.via.array.ptr[4];
            if (args.type != msgpack::type::ARRAY || args.via.array.size < 1 ||
                    args.via.array.ptr[0].type != msgpack::type::MAP) {
                return std::nullopt;
            }

            const msgpack::object_map& map = args.via.array.ptr[0].via.map;
            for (uint32_t i = 0; i < map.size; ++i) {
                const msgpack::object_kv& kv = map.ptr[i];
                bool is_type = kv.key.type == msgpack::type::STR &&
                               kv.key.as<std::string_view>() == "Type";
                if (is_type && isInt_(kv.val)) {
                    return static_cast<PushType>(kv.val.as<int>());
                }
            }
            return std::nullopt;
        }
    }

    std::vector<PushType> parseNotificationFrame(std::span<const uint8_t> frame) {
        std::vector<PushType> out;

        size_t pos = 0;
        while (pos < frame.size()) {
            size_t length = 0;
            if (!readLength_(frame, pos, length) || length > frame.size() - pos) {
                break;
            }

            try {
                msgpack::object_handle handle =
                        msgpack::unpack(reinterpret_cast<const char*>(frame.data() + pos), length);
                std::optional<PushType> type = typeOf_(handle.get());
                if (type) {
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
