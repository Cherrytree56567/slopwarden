#pragma once
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string_view>
#include <utility>
#include <vector>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief The Bitwarden endpoints. Vaultwarden usually serves vault and api from one origin.
     */
    struct ServerUrls {
        SecureString m_vault;         // /identity/* and /api/* vault operations
        SecureString m_api;           // /alive, /api/config, /api/accounts/*
        SecureString m_icons;         // favicon service
        SecureString m_notifications; // websocket hub

        /**
         * @brief Whether every URL has an http(s) (or ws(s) for notifications) scheme.
         *
         * @return True if usable
         */
        bool valid() const;

        /**
         * @brief Serialises for storage.
         *
         * @return {vault, api, icons, notifications}
         */
        Json toJson() const;

        /**
         * @brief Reads back what toJson wrote.
         *
         * @param json The stored object
         * @return The URLs, or nullopt if missing or invalid
         */
        static std::optional<ServerUrls> fromJson(const Json& json);
    };

    /**
     * @brief Which configured endpoint a request goes to.
     */
    enum class Host { Vault, Api, Icons };

    /**
     * @brief HTTP verbs the API uses.
     */
    enum class HttpMethod { Get, Post, Put, Delete };

    /**
     * @brief A file part for multipart uploads.
     */
    struct HttpFile {
        SecureString m_field;
        SecureString m_file_name;
        SecureBytes m_content;
    };

    /**
     * @brief One HTTP request.
     */
    struct HttpRequest {
        HttpMethod m_method = HttpMethod::Get;
        Host m_host = Host::Vault;
        SecureString m_path; // relative to the host, or an absolute URL
        std::vector<std::pair<SecureString, SecureString>> m_headers;
        SecureString m_body;
        SecureString m_content_type;
        std::optional<HttpFile> m_file;
        std::function<void(float)> m_on_progress;
        int m_timeout_seconds = 30;

        /**
         * @brief Whether m_path is an absolute URL (e.g. a pre-signed blob URL).
         *
         * @return True for http:// or https:// paths
         */
        bool absolute() const;
    };

    /**
     * @brief One HTTP response.
     */
    struct HttpResponse {
        int m_status = 0; // 0 = no response (offline, DNS, TLS, timeout)
        SecureBytes m_body;

        /**
         * @brief Whether the status is 2xx.
         *
         * @return True on success
         */
        bool ok() const;

        /**
         * @brief Whether the server answered at all.
         *
         * @return False for transport failures
         */
        bool reached() const;

        /**
         * @brief Parses the body without throwing.
         *
         * @return The JSON, or nullopt if malformed
         */
        std::optional<Json> json() const;
    };

    /**
     * @brief Sends HTTP requests and listens to the notification hub.
     *
     * Production uses HttplibTransport; tests plug in a fake server here.
     */
    class HttpTransport {
    public:
        virtual ~HttpTransport() = default;

        /**
         * @brief Points the transport at a server.
         *
         * @param urls The server endpoints
         */
        virtual void configure(ServerUrls urls) = 0;

        /**
         * @brief Sends a request and waits for the response.
         *
         * @param request The request
         * @return The response (status 0 if unreachable)
         */
        virtual HttpResponse send(HttpRequest request) = 0;

        /**
         * @brief Connects to the notification hub and delivers each frame until disconnected.
         *
         * @param bearer The access token
         * @param on_frame Called with each binary frame
         * @param stop Requests disconnection
         * @return False if the connection couldn't be established
         */
        virtual bool listen(std::string_view bearer,
                std::function<void(std::span<const uint8_t>)> on_frame, std::stop_token stop) = 0;
    };

    /**
     * @brief cpp-httplib transport with a small keep-alive connection pool per host.
     */
    class HttplibTransport : public HttpTransport {
    public:
        HttplibTransport();
        ~HttplibTransport() override;

        void configure(ServerUrls urls) override;
        HttpResponse send(HttpRequest request) override;
        bool listen(std::string_view bearer, std::function<void(std::span<const uint8_t>)> on_frame,
                std::stop_token stop) override;

    private:
        struct Pool;
        std::shared_ptr<Pool> m_pool_;
    };
}
