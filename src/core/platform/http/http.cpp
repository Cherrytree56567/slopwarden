#include "http.h"

namespace clientwarden {
    namespace {
        bool hasScheme_(std::string_view url, std::initializer_list<std::string_view> schemes) {
            for (std::string_view scheme : schemes) {
                if (url.starts_with(scheme)) {
                    return true;
                }
            }
            return false;
        }
    }

    bool ServerUrls::valid() const {
        return hasScheme_(m_vault, { "https://", "http://" }) &&
               hasScheme_(m_api, { "https://", "http://" }) &&
               hasScheme_(m_icons, { "https://", "http://" }) &&
               (m_notifications.empty() ||
                       hasScheme_(m_notifications, { "https://", "http://", "wss://", "ws://" }));
    }

    Json ServerUrls::toJson() const {
        return { { "vault", m_vault }, { "api", m_api }, { "icons", m_icons },
            { "notifications", m_notifications } };
    }

    std::optional<ServerUrls> ServerUrls::fromJson(const Json& json) {
        ServerUrls urls { stringAt(json, "vault"), stringAt(json, "api"), stringAt(json, "icons"),
            stringAt(json, "notifications") };
        if (!urls.valid()) {
            return std::nullopt;
        }
        return urls;
    }

    bool HttpRequest::absolute() const {
        return m_path.starts_with("https://") || m_path.starts_with("http://");
    }

    bool HttpResponse::ok() const {
        return m_status >= 200 && m_status < 300;
    }

    bool HttpResponse::reached() const {
        return m_status != 0;
    }

    std::optional<Json> HttpResponse::json() const {
        Json parsed = Json::parse(m_body.begin(), m_body.end(), nullptr, false);
        if (parsed.is_discarded()) {
            return std::nullopt;
        }
        return parsed;
    }
}
