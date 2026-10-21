#include "Http.h"

namespace ClientWarden {
    namespace {
        bool ValidUrl(const std::string& url) {
            return url.starts_with("https://") || url.starts_with("http://");
        }
    }

    bool ServerUrls::Valid() const {
        return ValidUrl(vault) && ValidUrl(api) && ValidUrl(icons) && (notifications.empty() || ValidUrl(notifications) ||
            notifications.starts_with("wss://") || notifications.starts_with("ws://"));
    }

    nlohmann::json ServerUrls::ToJson() const {
        return { { "vault", vault }, { "api", api }, { "icons", icons }, { "notifications", notifications } };
    }

    std::optional<ServerUrls> ServerUrls::FromJson(const nlohmann::json& j) {
        if (!j.is_object()) {
            return std::nullopt;
        }

        ServerUrls urls {
            j.value("vault", ""),
            j.value("api", ""),
            j.value("icons", ""),
            j.value("notifications", "")
        };
        if (!urls.Valid()) {
            return std::nullopt;
        }
        return urls;
    }

    std::optional<nlohmann::json> HttpResponse::Json() const {
        nlohmann::json j = nlohmann::json::parse(body, nullptr, false);
        if (j.is_discarded()) {
            return std::nullopt;
        }
        return j;
    }
}
