#pragma once
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>

#include "Clientwarden.h"

namespace ClientWarden {
    /*
     * The four Bitwarden endpoints. Vaultwarden usually serves the first
     * two from one origin. See SPEC.md.
    */
    struct ServerUrls {
        std::string vault;          // /identity/* and /api/* vault operations
        std::string api;            // /alive, /api/config, /api/accounts/*
        std::string icons;          // favicon service
        std::string notifications;  // websocket hub

        bool Valid() const;
        nlohmann::json ToJson() const;
        static std::optional<ServerUrls> FromJson(const nlohmann::json& j);
    };

    enum class Host {
        Vault,
        Api,
        Icons
    };

    enum class HttpMethod {
        Get,
        Post,
        Put,
        Delete
    };

    struct HttpFile {
        std::string field;
        std::string fileName;
        std::string content;
    };

    struct HttpRequest {
        HttpMethod method = HttpMethod::Get;
        Host host = Host::Vault;
        std::string path;   // relative to the host, or an absolute URL
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        std::string contentType;
        std::optional<HttpFile> file;
        std::function<void(float)> onProgress;
        int timeoutSeconds = 30;
    };

    struct HttpResponse {
        int status = 0;     // 0 = no response (offline, DNS, TLS, timeout)
        std::string body;

        bool Ok() const { return status >= 200 && status < 300; }
        bool Reached() const { return status != 0; }

        /*
         * Parses the body without throwing; malformed JSON yields nullopt.
        */
        std::optional<nlohmann::json> Json() const;
    };

    class HttpTransport {
    public:
        virtual ~HttpTransport() = default;

        virtual void Configure(const ServerUrls& urls) = 0;
        virtual HttpResponse Send(const HttpRequest& request) = 0;

        /*
         * Connects to the notification hub and delivers each binary frame
         * to onFrame until the server disconnects or stop is requested.
         * Returns false if the connection couldn't be established.
        */
        virtual bool Listen(const std::string& bearer, const std::function<void(std::string_view)>& onFrame, std::stop_token stop) = 0;
    };

    /*
     * cpp-httplib backed transport. Keeps a small pool of keep-alive
     * connections per host so concurrent requests (icon downloads during
     * a sync, say) don't serialise behind one socket.
    */
    class HttplibTransport : public HttpTransport {
    public:
        HttplibTransport();
        ~HttplibTransport() override;

        void Configure(const ServerUrls& urls) override;
        HttpResponse Send(const HttpRequest& request) override;
        bool Listen(const std::string& bearer, const std::function<void(std::string_view)>& onFrame, std::stop_token stop) override;

    private:
        struct Pool;
        std::unique_ptr<Pool> pool;
    };
}
