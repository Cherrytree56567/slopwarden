#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#include <httplib.h>

#include "Http.h"

namespace ClientWarden {
    namespace {
        constexpr size_t MaxIdlePerHost = 4;

        /*
         * Splits "https://host:port/path?q" into its origin and the rest.
        */
        std::pair<std::string, std::string> SplitUrl(const std::string& url) {
            size_t scheme = url.find("://");
            size_t pathStart = scheme == std::string::npos ? std::string::npos : url.find('/', scheme + 3);
            if (pathStart == std::string::npos) {
                return { url, "/" };
            }
            return { url.substr(0, pathStart), url.substr(pathStart) };
        }

        std::unique_ptr<httplib::Client> MakeClient(const std::string& origin) {
            auto client = std::make_unique<httplib::Client>(origin);
            client->set_connection_timeout(5);
            client->set_keep_alive(true);
            client->set_follow_location(false);
            return client;
        }
    }

    struct HttplibTransport::Pool {
        std::mutex mutex;
        ServerUrls urls;
        uint64_t generation = 0;
        std::map<Host, std::vector<std::unique_ptr<httplib::Client>>> idle;

        std::string Origin(Host host) const {
            switch (host) {
                case Host::Vault: return urls.vault;
                case Host::Api: return urls.api;
                case Host::Icons: return urls.icons;
            }
            return {};
        }

        /*
         * Checks a connection out of the pool, creating one if none are
         * idle. The generation lets Configure() invalidate connections
         * that are checked out while the server URLs change.
        */
        std::pair<std::unique_ptr<httplib::Client>, uint64_t> Acquire(Host host) {
            std::lock_guard lock(mutex);
            auto& list = idle[host];
            if (!list.empty()) {
                auto client = std::move(list.back());
                list.pop_back();
                return { std::move(client), generation };
            }
            return { MakeClient(Origin(host)), generation };
        }

        void Release(Host host, std::unique_ptr<httplib::Client> client, uint64_t gen) {
            std::lock_guard lock(mutex);
            auto& list = idle[host];
            if (gen == generation && list.size() < MaxIdlePerHost) {
                list.push_back(std::move(client));
            }
        }
    };

    HttplibTransport::HttplibTransport() : pool(std::make_unique<Pool>()) {}
    HttplibTransport::~HttplibTransport() = default;

    void HttplibTransport::Configure(const ServerUrls& urls) {
        if (!urls.vault.starts_with("https://") || !urls.api.starts_with("https://")) {
            Log()->warn("Server is not using HTTPS; credentials will be sent in the clear");
        }

        std::lock_guard lock(pool->mutex);
        pool->urls = urls;
        pool->idle.clear();
        ++pool->generation;
    }

    HttpResponse HttplibTransport::Send(const HttpRequest& req) {
        httplib::Headers headers(req.headers.begin(), req.headers.end());

        httplib::DownloadProgress download = nullptr;
        httplib::UploadProgress upload = nullptr;
        if (req.onProgress) {
            auto progress = [&req](uint64_t current, uint64_t total) {
                if (total > 0) {
                    req.onProgress(static_cast<float>(current) / static_cast<float>(total));
                }
                return true;
            };
            download = progress;
            upload = progress;
        }

        /*
         * Absolute URLs (attachment blobs) can point at a different
         * origin, so they get a throwaway client rather than a pooled one.
        */
        bool absolute = req.path.starts_with("https://") || req.path.starts_with("http://");
        std::unique_ptr<httplib::Client> client;
        uint64_t gen = 0;
        std::string path = req.path;

        if (absolute) {
            auto [origin, rest] = SplitUrl(req.path);
            client = MakeClient(origin);
            path = rest;
        } else {
            std::tie(client, gen) = pool->Acquire(req.host);
        }
        client->set_read_timeout(req.timeoutSeconds);
        client->set_write_timeout(req.timeoutSeconds);

        httplib::Result res;
        try {
            switch (req.method) {
                case HttpMethod::Get:
                    res = client->Get(path, headers, download);
                    break;
                case HttpMethod::Post:
                    if (req.file) {
                        httplib::UploadFormDataItems items = {
                            { req.file->field, req.file->content, req.file->fileName, "application/octet-stream" }
                        };
                        res = client->Post(path, headers, items, upload);
                    } else {
                        res = client->Post(path, headers, req.body, req.contentType);
                    }
                    break;
                case HttpMethod::Put:
                    res = client->Put(path, headers, req.body, req.contentType);
                    break;
                case HttpMethod::Delete:
                    res = client->Delete(path, headers);
                    break;
            }
        } catch (const std::exception& e) {
            Log()->warn("HTTP {} failed: {}", path, e.what());
            return {};
        }

        if (!res) {
            Log()->debug("HTTP {} failed: {}", path, httplib::to_string(res.error()));
            return {};
        }

        HttpResponse out { res->status, std::move(res->body) };
        if (!absolute) {
            pool->Release(req.host, std::move(client), gen);
        }
        return out;
    }

    bool HttplibTransport::Listen(const std::string& bearer, const std::function<void(std::string_view)>& onFrame, std::stop_token stop) {
        std::string url;
        {
            std::lock_guard lock(pool->mutex);
            url = pool->urls.notifications;
        }
        if (url.empty()) {
            return false;
        }

        httplib::ws::WebSocketClient ws(url + "/hub", { { "Authorization", "Bearer " + bearer } });
        ws.set_connection_timeout(5);
        ws.set_websocket_ping_interval(30);
        try {
            if (!ws.connect()) {
                return false;
            }
        } catch (const std::exception& e) {
            Log()->debug("Notification hub connect failed: {}", e.what());
            return false;
        }

        /*
         * read() blocks, so a stop request closes the socket from the
         * requesting thread to unblock it.
        */
        std::stop_callback onStop(stop, [&ws] {
            ws.close(httplib::ws::CloseStatus::GoingAway, "shutting down");
        });

        ws.send(std::string("{\"protocol\":\"messagepack\",\"version\":1}\x1e"));

        std::string msg;
        while (!stop.stop_requested() && ws.read(msg) != httplib::ws::ReadResult::Fail) {
            onFrame(msg);
        }
        return true;
    }
}
