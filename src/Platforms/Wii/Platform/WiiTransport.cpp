#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <network.h>
#include <ogc/lwp_watchdog.h>
#include <psa/crypto.h>

#include "System.h"
#include "Utc.h"
#include "platform/http/platform_transport.h"
#include "platform/paths/paths.h"
#include "platform/random/random.h"
#include "utils/encoding/encoding.h"
#include "utils/logger/logger.h"

/*
 * HTTPS on the Wii: libogc's sockets carrying mbedTLS, verified against Mozilla's CA bundle
 * (cacert.pem in the app folder). One request per connection, one request at a time: mbedTLS
 * is built without threading support, and the Wii has a single core anyway. There is no
 * notification hub (listen() declines), so the vault syncs when unlocked and on demand.
 */

/*
 * mbedTLS's platform hooks (configured with MBEDTLS_PLATFORM_MS_TIME_ALT and
 * MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG): our clock and our random generator.
 */
extern "C" {
mbedtls_ms_time_t mbedtls_ms_time(void) {
    return static_cast<mbedtls_ms_time_t>(ticks_to_millisecs(gettime()));
}

psa_status_t mbedtls_psa_external_get_random(
        mbedtls_psa_external_random_context_t*, uint8_t* output, size_t output_size, size_t* output_length) {
    try {
        clientwarden::random::secure().randomize(output, output_size);
        *output_length = output_size;
        return PSA_SUCCESS;
    } catch (...) {
        *output_length = 0;
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
}
}

namespace clientwarden {
    namespace {
        constexpr size_t c_max_header_bytes = 64 * 1024;

        struct Url {
            bool m_tls = true;
            SecureString m_host;
            int m_port = 443;
            SecureString m_path = "/";
        };

        /**
         * @brief Splits "https://host:port/path?query".
         */
        std::optional<Url> parseUrl_(std::string_view url) {
            Url out;
            if (url.starts_with("https://")) {
                url.remove_prefix(8);
            } else if (url.starts_with("http://")) {
                url.remove_prefix(7);
                out.m_tls = false;
                out.m_port = 80;
            } else {
                return std::nullopt;
            }
            size_t slash = url.find('/');
            std::string_view authority = url.substr(0, slash);
            if (slash != std::string_view::npos) {
                out.m_path = SecureString(url.substr(slash));
            }
            size_t colon = authority.rfind(':');
            if (colon != std::string_view::npos && authority.find(']') == std::string_view::npos) {
                std::int64_t port = 0;
                if (!parseInt(authority.substr(colon + 1), port) || port <= 0 || port > 65535) {
                    return std::nullopt;
                }
                out.m_port = static_cast<int>(port);
                authority = authority.substr(0, colon);
            }
            if (authority.empty()) {
                return std::nullopt;
            }
            out.m_host = SecureString(authority);
            return out;
        }

        const char* methodName_(HttpMethod method) {
            switch (method) {
            case HttpMethod::Get: return "GET";
            case HttpMethod::Post: return "POST";
            case HttpMethod::Put: return "PUT";
            case HttpMethod::Delete: return "DELETE";
            }
            return "GET";
        }

        /**
         * @brief The shared TLS configuration: the CA bundle and our random generator.
         */
        struct Tls {
            mbedtls_x509_crt m_ca;
            mbedtls_ssl_config m_config;
            bool m_ok = false;

            Tls() {
                mbedtls_x509_crt_init(&m_ca);
                mbedtls_ssl_config_init(&m_config);
                if (psa_crypto_init() != PSA_SUCCESS) {
                    Logger::get()->error("TLS: random generator not ready");
                    return;
                }

                std::ifstream in(paths::resourceDirectory() / "cacert.pem", std::ios::binary);
                std::vector<unsigned char> pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                pem.push_back('\0');
                if (pem.size() < 2 || mbedtls_x509_crt_parse(&m_ca, pem.data(), pem.size()) < 0) {
                    Logger::get()->error("TLS: couldn't load cacert.pem");
                    return;
                }

                if (mbedtls_ssl_config_defaults(&m_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                            MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
                    return;
                }
                mbedtls_ssl_conf_authmode(&m_config, MBEDTLS_SSL_VERIFY_REQUIRED);
                mbedtls_ssl_conf_ca_chain(&m_config, &m_ca, nullptr);
                mbedtls_ssl_conf_min_tls_version(&m_config, MBEDTLS_SSL_VERSION_TLS1_2);
                mbedtls_ssl_conf_rng(&m_config, rng_, nullptr);
                m_ok = true;
            }

            static int rng_(void*, unsigned char* output, size_t size) {
                try {
                    random::secure().randomize(output, size);
                    return 0;
                } catch (...) {
                    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                }
            }
        };

        Tls& tls_() {
            static Tls tls;
            return tls;
        }

        /**
         * @brief One connection: a socket, wrapped in TLS for https.
         */
        class Connection {
        public:
            ~Connection() {
                if (m_tls_started) {
                    mbedtls_ssl_close_notify(&m_ssl);
                }
                mbedtls_ssl_free(&m_ssl);
                if (m_socket >= 0) {
                    net_close(m_socket);
                }
            }

            /**
             * @brief Resolves, connects and (for https) handshakes and verifies the certificate.
             */
            bool open(const Url& url) {
                mbedtls_ssl_init(&m_ssl);
                hostent* host = net_gethostbyname(url.m_host.c_str());
                if (!host || host->h_addrtype != AF_INET || !host->h_addr_list[0]) {
                    Logger::get()->warn("HTTP: can't resolve {}", url.m_host);
                    return false;
                }
                sockaddr_in address = {};
                address.sin_family = AF_INET;
                address.sin_port = htons(static_cast<u16>(url.m_port));
                std::memcpy(&address.sin_addr, host->h_addr_list[0], sizeof(address.sin_addr));

                m_socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                if (m_socket < 0 || net_connect(m_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
                    Logger::get()->warn("HTTP: can't connect to {}:{}", url.m_host, url.m_port);
                    return false;
                }
                if (!url.m_tls) {
                    return true;
                }

                Tls& tls = tls_();
                if (!tls.m_ok || mbedtls_ssl_setup(&m_ssl, &tls.m_config) != 0 ||
                        mbedtls_ssl_set_hostname(&m_ssl, url.m_host.c_str()) != 0) {
                    return false;
                }
                mbedtls_ssl_set_bio(&m_ssl, this, send_, receive_, nullptr);
                m_tls_started = true;
                int result = 0;
                while ((result = mbedtls_ssl_handshake(&m_ssl)) != 0) {
                    if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        char reason[128] = {};
                        mbedtls_strerror(result, reason, sizeof(reason));
                        Logger::get()->warn("TLS handshake with {} failed: {}", url.m_host, reason);
                        m_tls_started = false;
                        return false;
                    }
                }
                return true;
            }

            bool write(const void* data, size_t size) {
                const unsigned char* bytes = static_cast<const unsigned char*>(data);
                while (size > 0) {
                    int written = m_tls_started ? mbedtls_ssl_write(&m_ssl, bytes, size)
                                                : net_send(m_socket, bytes, size, 0);
                    if (written == MBEDTLS_ERR_SSL_WANT_WRITE || written == MBEDTLS_ERR_SSL_WANT_READ) {
                        continue;
                    }
                    if (written <= 0) {
                        return false;
                    }
                    bytes += written;
                    size -= static_cast<size_t>(written);
                }
                return true;
            }

            /**
             * @brief Reads what's available; 0 at the end of the stream, -1 on error.
             */
            int read(unsigned char* buffer, size_t size) {
                while (true) {
                    int got = m_tls_started ? mbedtls_ssl_read(&m_ssl, buffer, size)
                                            : net_recv(m_socket, buffer, size, 0);
                    if (got == MBEDTLS_ERR_SSL_WANT_READ || got == MBEDTLS_ERR_SSL_WANT_WRITE) {
                        continue;
                    }
                    if (got == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                        return 0;
                    }
                    return got < 0 ? -1 : got;
                }
            }

        private:
            static int send_(void* context, const unsigned char* data, size_t size) {
                int sent = net_send(static_cast<Connection*>(context)->m_socket, data, size, 0);
                return sent < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : sent;
            }

            static int receive_(void* context, unsigned char* data, size_t size) {
                int got = net_recv(static_cast<Connection*>(context)->m_socket, data, size, 0);
                return got < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : got;
            }

            s32 m_socket = -1;
            mbedtls_ssl_context m_ssl;
            bool m_tls_started = false;
        };

        /**
         * @brief Buffers a connection's input for line- and length-based reads.
         */
        class Reader {
        public:
            explicit Reader(Connection& connection) : m_connection(connection) {}

            /**
             * @brief The next CRLF-terminated line, without the CRLF.
             */
            std::optional<SecureString> line() {
                while (true) {
                    size_t end = m_buffer.find("\r\n");
                    if (end != SecureString::npos) {
                        SecureString out = m_buffer.substr(0, end);
                        m_buffer.erase(0, end + 2);
                        return out;
                    }
                    if (m_buffer.size() > c_max_header_bytes || !fill_()) {
                        return std::nullopt;
                    }
                }
            }

            /**
             * @brief Exactly `size` bytes appended to `out`, or false if the stream ends first.
             */
            bool bytes(size_t size, SecureBytes& out, const std::function<void(size_t)>& progress) {
                while (size > 0) {
                    if (m_buffer.empty() && !fill_()) {
                        return false;
                    }
                    size_t take = std::min(size, m_buffer.size());
                    out.insert(out.end(), m_buffer.begin(), m_buffer.begin() + static_cast<std::ptrdiff_t>(take));
                    m_buffer.erase(0, take);
                    size -= take;
                    if (progress) {
                        progress(out.size());
                    }
                }
                return true;
            }

            /**
             * @brief Everything up to the end of the stream.
             */
            void rest(SecureBytes& out) {
                do {
                    out.insert(out.end(), m_buffer.begin(), m_buffer.end());
                    m_buffer.clear();
                } while (fill_());
            }

        private:
            bool fill_() {
                unsigned char chunk[4096];
                int got = m_connection.read(chunk, sizeof(chunk));
                if (got <= 0) {
                    return false;
                }
                m_buffer.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(got));
                std::fill(std::begin(chunk), std::end(chunk), 0);
                return true;
            }

            Connection& m_connection;
            SecureString m_buffer;
        };

        /**
         * @brief Builds a multipart/form-data body with one file part (attachment and Send
         * uploads).
         */
        SecureString multipart_(const HttpFile& file, SecureString& boundary) {
            SecureBytes nonce(12);
            random::secure().randomize(nonce.data(), nonce.size());
            boundary = SecureString("----clientwarden") + encoding::hexEncode(nonce);
            SecureString body = SecureString("--") + boundary + "\r\n" +
                                "Content-Disposition: form-data; name=\"" + file.m_field +
                                "\"; filename=\"" + file.m_file_name + "\"\r\n" +
                                "Content-Type: application/octet-stream\r\n\r\n";
            body.append(reinterpret_cast<const char*>(file.m_content.data()), file.m_content.size());
            body += SecureString("\r\n--") + boundary + "--\r\n";
            return body;
        }

        SecureString lower_(std::string_view text) {
            SecureString out(text);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = static_cast<char>(c - 'A' + 'a');
                }
            }
            return out;
        }
    }

    class WiiTransport : public HttpTransport {
    public:
        void configure(ServerUrls urls) override {
            std::lock_guard<std::mutex> lock(m_mutex_);
            m_urls_ = std::move(urls);
        }

        HttpResponse send(HttpRequest request) override {
            ServerUrls urls;
            {
                std::lock_guard<std::mutex> lock(m_mutex_);
                urls = m_urls_;
            }
            /*
             * One request at a time across every transport: mbedTLS's PSA state is global.
             */
            static std::mutex s_exchange_mutex;
            std::lock_guard<std::mutex> exchange(s_exchange_mutex);
            if (!wii::networkReady()) {
                return HttpResponse();
            }

            /*
             * Like cpp-httplib, a configured URL contributes only its scheme, host and port;
             * request paths are complete ("/api/sync", "/identity/connect/token").
             */
            std::optional<Url> url;
            if (request.absolute()) {
                url = parseUrl_(request.m_path);
            } else {
                url = parseUrl_(origin_(urls, request.m_host));
                if (url) {
                    url->m_path = request.m_path;
                }
            }
            if (!url) {
                return HttpResponse();
            }

            try {
                return exchange_(*url, request);
            } catch (const std::exception& e) {
                Logger::get()->warn("HTTP request failed: {}", e.what());
                return HttpResponse();
            }
        }

        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }

    private:
        static SecureString origin_(const ServerUrls& urls, Host host) {
            switch (host) {
            case Host::Vault: return urls.m_vault;
            case Host::Api: return urls.m_api;
            case Host::Icons: return urls.m_icons;
            }
            return SecureString();
        }

        HttpResponse exchange_(const Url& url, const HttpRequest& request) {
            Connection connection;
            if (!connection.open(url)) {
                return HttpResponse();
            }

            SecureString body = request.m_body;
            SecureString content_type = request.m_content_type;
            if (request.m_file) {
                SecureString boundary;
                body = multipart_(*request.m_file, boundary);
                content_type = SecureString("multipart/form-data; boundary=") + boundary;
            }

            bool default_port = url.m_port == (url.m_tls ? 443 : 80);
            SecureString head = SecureString(methodName_(request.m_method)) + " " + url.m_path + " HTTP/1.1\r\n" +
                                "Host: " + url.m_host +
                                (default_port ? SecureString() : SecureString(":") + toSecureString(url.m_port)) +
                                "\r\nConnection: close\r\nUser-Agent: ClientWarden (Wii)\r\n";
            for (const std::pair<SecureString, SecureString>& header : request.m_headers) {
                head += header.first + ": " + header.second + "\r\n";
            }
            bool has_body = !body.empty() || request.m_method == HttpMethod::Post || request.m_method == HttpMethod::Put;
            if (has_body) {
                if (!content_type.empty()) {
                    head += SecureString("Content-Type: ") + content_type + "\r\n";
                }
                head += SecureString("Content-Length: ") + toSecureString(static_cast<std::int64_t>(body.size())) + "\r\n";
            }
            head += "\r\n";
            if (!connection.write(head.data(), head.size()) || (!body.empty() && !connection.write(body.data(), body.size()))) {
                return HttpResponse();
            }
            if (request.m_on_progress && request.m_file) {
                request.m_on_progress(1.0f);
            }

            Reader reader(connection);
            std::optional<SecureString> status_line = reader.line();
            if (!status_line || !status_line->starts_with("HTTP/1.") || status_line->size() < 12) {
                return HttpResponse();
            }
            std::int64_t status = 0;
            if (!parseInt(std::string_view(*status_line).substr(9, 3), status)) {
                return HttpResponse();
            }

            std::map<SecureString, SecureString, std::less<>> headers;
            while (true) {
                std::optional<SecureString> line = reader.line();
                if (!line) {
                    return HttpResponse();
                }
                if (line->empty()) {
                    break;
                }
                size_t colon = line->find(':');
                if (colon != SecureString::npos) {
                    headers[lower_(std::string_view(*line).substr(0, colon))] = trim(std::string_view(*line).substr(colon + 1));
                }
            }
            if (std::map<SecureString, SecureString, std::less<>>::iterator date = headers.find("date"); date != headers.end()) {
                wii::utc::observeServerDate(date->second);
            }

            HttpResponse response;
            response.m_status = static_cast<int>(status);
            std::int64_t total = -1;
            if (std::map<SecureString, SecureString, std::less<>>::iterator length = headers.find("content-length");
                    length != headers.end()) {
                parseInt(length->second, total);
            }
            std::function<void(size_t)> progress;
            if (request.m_on_progress && !request.m_file && total > 0) {
                progress = [&request, total](size_t got) {
                    request.m_on_progress(static_cast<float>(got) / static_cast<float>(total));
                };
            }

            SecureString encoding = headers.contains("transfer-encoding") ? lower_(headers["transfer-encoding"]) : SecureString();
            if (encoding.find("chunked") != SecureString::npos) {
                while (true) {
                    std::optional<SecureString> size_line = reader.line();
                    if (!size_line) {
                        return HttpResponse();
                    }
                    size_t chunk = std::strtoul(size_line->c_str(), nullptr, 16);
                    if (chunk == 0) {
                        break;
                    }
                    if (!reader.bytes(chunk, response.m_body, nullptr) || !reader.line()) {
                        return HttpResponse();
                    }
                }
            } else if (total >= 0) {
                if (!reader.bytes(static_cast<size_t>(total), response.m_body, progress)) {
                    return HttpResponse();
                }
            } else {
                reader.rest(response.m_body);
            }
            return response;
        }

        std::mutex m_mutex_;
        ServerUrls m_urls_;
    };

    std::shared_ptr<HttpTransport> createPlatformTransport() {
        return std::make_shared<WiiTransport>();
    }
}
