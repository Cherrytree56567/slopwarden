#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#if defined(_WIN32) && defined(__MINGW32__)
/*
 * MinGW's ws2tcpip.h lacks this declaration (its ws2_32 import library has the function),
 * and cpp-httplib uses it to cancel slow DNS lookups.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
extern "C" INT WSAAPI GetAddrInfoExCancel(LPHANDLE handle);
#endif
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>

#include "http.h"
#include "platform_transport.h"
#include "utils/logger/logger.h"

/*
 * Allowlisted std::string boundary: cpp-httplib's API only takes and returns std::string.
 * Request data is copied in at the last moment and responses are copied into secure memory
 * immediately; the temporaries are wiped.
 */
namespace clientwarden {
    namespace {
        constexpr size_t c_max_idle_per_host = 4;

        void wipe_(std::string& s) {
            volatile char* p = s.data();
            for (size_t i = 0; i < s.size(); ++i) {
                p[i] = 0;
            }
            s.clear();
        }

        std::string plain_(std::string_view s) {
            return std::string(s);
        }

        /**
         * @brief Splits "https://host:port/path?q" into its origin and the rest.
         */
        std::pair<std::string, std::string> splitUrl_(std::string_view url) {
            size_t scheme = url.find("://");
            size_t path = scheme == std::string_view::npos ? scheme : url.find('/', scheme + 3);
            if (path == std::string_view::npos) {
                return { plain_(url), "/" };
            }
            return { plain_(url.substr(0, path)), plain_(url.substr(path)) };
        }

#ifdef __ANDROID__
        /**
         * @brief The system's trusted CAs as one PEM bundle. Android has no OpenSSL default
         * paths, and its cacerts directory is named by the old subject hash OpenSSL 3 doesn't
         * look up, so the certificates are read in directly (the updatable APEX copy first).
         */
        const std::string& androidCaBundle_() {
            static const std::string bundle = []() {
                std::string pem;
                for (std::string_view dir :
                        { "/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts" }) {
                    std::error_code error;
                    for (const std::filesystem::directory_entry& entry :
                            std::filesystem::directory_iterator(
                                    std::filesystem::path(dir), error)) {
                        std::ifstream in(entry.path(), std::ios::binary);
                        pem.append(std::istreambuf_iterator<char>(in),
                                std::istreambuf_iterator<char>());
                        pem.push_back('\n');
                    }
                    if (!pem.empty()) {
                        break;
                    }
                }
                return pem;
            }();
            return bundle;
        }
#endif

        std::shared_ptr<httplib::Client> makeClient_(std::string origin) {
            std::shared_ptr<httplib::Client> client = std::make_shared<httplib::Client>(origin);
#ifdef __ANDROID__
            const std::string& bundle = androidCaBundle_();
            client->load_ca_cert_store(bundle.data(), bundle.size());
#endif
            client->set_connection_timeout(5);
            client->set_keep_alive(true);
            client->set_follow_location(false);
            return client;
        }
    }

    /**
     * @brief Idle keep-alive connections per host. A generation counter lets configure()
     * invalidate connections that are checked out while the server changes.
     */
    struct HttplibTransport::Pool {
        std::mutex m_mutex;
        ServerUrls m_urls;
        uint64_t m_generation = 0;
        std::map<Host, std::vector<std::shared_ptr<httplib::Client>>> m_idle;

        std::string origin(Host host) {
            switch (host) {
            case Host::Vault: return plain_(m_urls.m_vault);
            case Host::Api: return plain_(m_urls.m_api);
            case Host::Icons: return plain_(m_urls.m_icons);
            }
            return std::string();
        }

        std::pair<std::shared_ptr<httplib::Client>, uint64_t> acquire(Host host) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<std::shared_ptr<httplib::Client>>& list = m_idle[host];
            if (!list.empty()) {
                std::shared_ptr<httplib::Client> client = list.back();
                list.pop_back();
                return { client, m_generation };
            }
            return { makeClient_(origin(host)), m_generation };
        }

        void release(Host host, std::shared_ptr<httplib::Client> client, uint64_t generation) {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<std::shared_ptr<httplib::Client>>& list = m_idle[host];
            if (generation == m_generation && list.size() < c_max_idle_per_host) {
                list.push_back(std::move(client));
            }
        }
    };

    HttplibTransport::HttplibTransport() : m_pool_(std::make_shared<Pool>()) {}

    HttplibTransport::~HttplibTransport() = default;

    void HttplibTransport::configure(ServerUrls urls) {
        if (!urls.m_vault.starts_with("https://") || !urls.m_api.starts_with("https://")) {
            Logger::get()->warn("Server is not using HTTPS; credentials will be sent in the clear");
        }

        std::lock_guard<std::mutex> lock(m_pool_->m_mutex);
        m_pool_->m_urls = std::move(urls);
        m_pool_->m_idle.clear();
        ++m_pool_->m_generation;
    }

    HttpResponse HttplibTransport::send(HttpRequest request) {
        httplib::Headers headers;
        for (std::pair<SecureString, SecureString>& header : request.m_headers) {
            headers.emplace(plain_(header.first), plain_(header.second));
        }

        httplib::DownloadProgress download = nullptr;
        httplib::UploadProgress upload = nullptr;
        if (request.m_on_progress) {
            std::function<void(float)> report = request.m_on_progress;
            std::function<bool(size_t, size_t)> progress = [report](size_t current, size_t total) {
                if (total > 0) {
                    report(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            };
            download = progress;
            upload = progress;
        }

        /*
         * Absolute URLs (attachment blobs) can point at a different origin, so they get a
         * throwaway client rather than a pooled one.
         */
        bool absolute = request.absolute();
        std::shared_ptr<httplib::Client> client;
        uint64_t generation = 0;
        std::string path;
        if (absolute) {
            std::pair<std::string, std::string> parts = splitUrl_(request.m_path);
            client = makeClient_(parts.first);
            path = parts.second;
        } else {
            std::tie(client, generation) = m_pool_->acquire(request.m_host);
            path = plain_(request.m_path);
        }
        client->set_read_timeout(request.m_timeout_seconds);
        client->set_write_timeout(request.m_timeout_seconds);

        std::string body = plain_(request.m_body);
        std::string content_type = plain_(request.m_content_type);
        httplib::Result result;
        try {
            switch (request.m_method) {
            case HttpMethod::Get: result = client->Get(path, headers, download); break;
            case HttpMethod::Post:
                if (request.m_file) {
                    std::string content(
                            request.m_file->m_content.begin(), request.m_file->m_content.end());
                    httplib::UploadFormDataItems items = { { plain_(request.m_file->m_field),
                            content, plain_(request.m_file->m_file_name),
                            "application/octet-stream" } };
                    result = client->Post(path, headers, items, upload);
                    wipe_(content);
                } else {
                    result = client->Post(path, headers, body, content_type);
                }
                break;
            case HttpMethod::Put: result = client->Put(path, headers, body, content_type); break;
            case HttpMethod::Delete: result = client->Delete(path, headers); break;
            }
        } catch (const std::exception& e) {
            Logger::get()->warn("HTTP request failed: {}", e.what());
            wipe_(body);
            return HttpResponse();
        }
        wipe_(body);
        for (std::pair<const std::string, std::string>& header : headers) {
            wipe_(header.second);
        }

        if (!result) {
            Logger::get()->debug("HTTP request failed: {}", httplib::to_string(result.error()));
            return HttpResponse();
        }

        HttpResponse response;
        response.m_status = result->status;
        response.m_body.assign(result->body.begin(), result->body.end());
        wipe_(result->body);

        if (!absolute) {
            m_pool_->release(request.m_host, client, generation);
        }
        return response;
    }

    bool HttplibTransport::listen(std::string_view bearer,
            std::function<void(std::span<const uint8_t>)> on_frame, std::stop_token stop) {
        std::string url;
        {
            std::lock_guard<std::mutex> lock(m_pool_->m_mutex);
            url = plain_(m_pool_->m_urls.m_notifications);
        }
        if (url.empty()) {
            return false;
        }

        /*
         * The hub is configured as an http(s) URL like the other endpoints; the WebSocket
         * client only takes ws(s).
         */
        if (url.starts_with("https://")) {
            url.replace(0, 5, "wss");
        } else if (url.starts_with("http://")) {
            url.replace(0, 4, "ws");
        }

        std::string authorization = "Bearer " + plain_(bearer);
        std::unique_ptr<httplib::ws::WebSocketClient> client;
        try {
            client = std::make_unique<httplib::ws::WebSocketClient>(
                    url + "/hub", httplib::Headers { { "Authorization", authorization } });
        } catch (const std::exception& e) {
            wipe_(authorization);
            Logger::get()->warn("Notification hub URL rejected: {}", e.what());
            return false;
        }
        wipe_(authorization);
        httplib::ws::WebSocketClient& ws = *client;
        ws.set_connection_timeout(5);
        ws.set_websocket_ping_interval(30);
#ifdef __ANDROID__
        const std::string& bundle = androidCaBundle_();
        ws.load_ca_cert_store(bundle.data(), bundle.size());
#endif
        try {
            if (!ws.connect()) {
                return false;
            }
        } catch (const std::exception& e) {
            Logger::get()->debug("Notification hub connect failed: {}", e.what());
            return false;
        }

        /*
         * read() blocks, so a stop request closes the socket from the requesting thread.
         */
        std::stop_callback on_stop(
                stop, [&ws]() { ws.close(httplib::ws::CloseStatus::GoingAway, "shutting down"); });

        ws.send(std::string("{\"protocol\":\"messagepack\",\"version\":1}\x1e"));

        std::string message;
        while (!stop.stop_requested() && ws.read(message) != httplib::ws::ReadResult::Fail) {
            on_frame(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(message.data()), message.size()));
        }
        return true;
    }

    std::shared_ptr<HttpTransport> createPlatformTransport() {
        return std::make_shared<HttplibTransport>();
    }
}
