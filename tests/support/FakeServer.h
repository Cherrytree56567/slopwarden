#pragma once
#include <map>
#include <mutex>
#include <sstream>

#include "Crypto/Crypto.h"
#include "Net/Http.h"
#include "Platform/FileStore.h"
#include "Platform/SecretStore.h"
#include "Util/Util.h"

/*
 * An in-memory Bitwarden server speaking the same HTTP protocol the
 * real one does, plugged in through the HttpTransport seam.
*/
namespace ClientWarden::Testing {
    inline std::map<std::string, std::string> ParseForm(const std::string& body) {
        auto decode = [](const std::string& s) {
            std::string out;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '%' && i + 2 < s.size()) {
                    out.push_back(static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16)));
                    i += 2;
                } else {
                    out.push_back(s[i] == '+' ? ' ' : s[i]);
                }
            }
            return out;
        };

        std::map<std::string, std::string> out;
        std::istringstream ss(body);
        for (std::string pair; std::getline(ss, pair, '&');) {
            size_t eq = pair.find('=');
            out[decode(pair.substr(0, eq))] = eq == std::string::npos ? "" : decode(pair.substr(eq + 1));
        }
        return out;
    }

    class FakeServer {
    public:
        std::string email = "user@example.com";
        std::string password = "correct horse battery staple";
        Crypto::KdfParams kdf { Crypto::KdfType::PBKDF2, 100000 };

        Bytes masterKey;
        Crypto::SymmetricKey userKey;
        std::string protectedKey;
        std::string passwordHash;

        bool online = true;
        bool requireTotp = false;
        bool requirePasskey = false;
        std::string lastPasskeyAssertion;
        bool requireDeviceVerification = false;
        bool revokeRefresh = false;
        std::string version = "2026.9.0";

        std::string accessToken = "access-1";
        std::string refreshToken = "refresh-1";
        int tokensIssued = 0;

        std::map<std::string, nlohmann::json> ciphers;
        std::map<std::string, nlohmann::json> folders;
        std::map<std::string, std::string> blobs;

        std::mutex mutex;
        std::vector<HttpRequest> requests;

        FakeServer() {
            masterKey = Crypto::DeriveMasterKey(password, email, kdf);
            userKey = Crypto::SymmetricKey::Generate();
            protectedKey = Crypto::WrapKey(userKey, Crypto::StretchMasterKey(masterKey));
            passwordHash = Crypto::HashMasterPassword(masterKey, password);
        }

        void InvalidateAccessToken() {
            std::lock_guard lock(mutex);
            accessToken = "expired";
        }

        size_t Count(HttpMethod method, std::string_view prefix) {
            std::lock_guard lock(mutex);
            return std::count_if(requests.begin(), requests.end(), [&](const HttpRequest& r) {
                return r.method == method && r.path.starts_with(prefix);
            });
        }

        std::optional<HttpRequest> Last(HttpMethod method, std::string_view prefix) {
            std::lock_guard lock(mutex);
            for (auto it = requests.rbegin(); it != requests.rend(); ++it) {
                if (it->method == method && it->path.starts_with(prefix)) {
                    return *it;
                }
            }
            return std::nullopt;
        }

        HttpResponse Handle(const HttpRequest& req) {
            std::lock_guard lock(mutex);
            requests.push_back(req);

            if (!online) {
                return {};
            }

            const std::string& p = req.path;
            auto json = [](int status, const nlohmann::json& body) { return HttpResponse { status, body.dump() }; };

            if (p == "/alive") return { 200, "" };
            if (p == "/api/config") return json(200, { { "version", version } });
            if (p == "/identity/accounts/prelogin") return json(200, { { "kdf", static_cast<int>(kdf.type) }, { "kdfIterations", kdf.iterations } });
            if (p == "/identity/connect/token") return Token(ParseForm(req.body));
            if (p.starts_with("https://blob.example/")) {
                auto it = blobs.find(p.substr(21));
                return it == blobs.end() ? HttpResponse { 404, "" } : HttpResponse { 200, it->second };
            }
            if (req.host == Host::Icons) return { 200, "PNGDATA" };

            if (!Authorized(req)) return { 401, "" };

            nlohmann::json body = req.body.empty() ? nlohmann::json() : nlohmann::json::parse(req.body, nullptr, false);

            if (p == "/api/sync") return json(200, Sync());
            if (p == "/api/accounts/profile") return json(200, Profile());

            if (p == "/api/ciphers" && req.method == HttpMethod::Post) {
                body["id"] = "srv-" + NewGuid();
                body["revisionDate"] = NowTime();
                ciphers[body["id"]] = body;
                return json(200, body);
            }
            if (p.starts_with("/api/ciphers/archive") || p.starts_with("/api/ciphers/unarchive")) {
                bool archive = p == "/api/ciphers/archive";
                for (const auto& id : body["ids"]) {
                    if (ciphers.contains(id)) ciphers[id]["archivedDate"] = archive ? nlohmann::json(NowTime()) : nlohmann::json();
                }
                return { 200, "" };
            }
            if (p.starts_with("/api/ciphers/")) return Cipher(req, body);

            if (p == "/api/folders" && req.method == HttpMethod::Post) {
                nlohmann::json f = { { "id", "srv-" + NewGuid() }, { "name", body["name"] }, { "revisionDate", NowTime() }, { "object", "folder" } };
                folders[f["id"]] = f;
                return json(200, f);
            }
            if (p.starts_with("/api/folders/")) {
                std::string id = p.substr(13);
                if (!folders.contains(id)) return { 404, "" };
                if (req.method == HttpMethod::Delete) {
                    folders.erase(id);
                    return { 200, "" };
                }
                folders[id]["name"] = body["name"];
                folders[id]["revisionDate"] = NowTime();
                return json(200, folders[id]);
            }
            return { 404, "" };
        }

        nlohmann::json Profile() const {
            return { { "id", "user-1" }, { "name", "Test User" }, { "email", email }, { "key", protectedKey } };
        }

    private:
        bool Authorized(const HttpRequest& req) const {
            for (const auto& [k, v] : req.headers) {
                if (k == "Authorization") return v == "Bearer " + accessToken;
            }
            return false;
        }

        HttpResponse Issue() {
            accessToken = "access-" + std::to_string(++tokensIssued + 1);
            return { 200, nlohmann::json { { "access_token", accessToken }, { "refresh_token", refreshToken }, { "expires_in", 3600 } }.dump() };
        }

        HttpResponse Token(std::map<std::string, std::string> form) {
            auto error = [](nlohmann::json body) { return HttpResponse { 400, body.dump() }; };

            if (form["grant_type"] == "refresh_token") {
                if (revokeRefresh || form["refresh_token"] != refreshToken) {
                    return error({ { "error", "invalid_grant" } });
                }
                return Issue();
            }

            if (form["username"] != email || form["password"] != passwordHash) {
                return error({ { "error", "invalid_grant" }, { "error_description", "invalid_username_or_password" } });
            }
            if (requireTotp) {
                if (!form.contains("twoFactorToken")) {
                    return error({ { "error", "invalid_grant" }, { "error_description", "Two factor required." }, { "TwoFactorProviders", { "0" } } });
                }
                if (form["twoFactorToken"] != "123456" || form["twoFactorProvider"] != "0") {
                    return error({ { "error", "invalid_grant" }, { "error_description", "Two-step token is invalid." } });
                }
            }
            if (requirePasskey) {
                if (form["twoFactorProvider"] != "7") {
                    return error({ { "error", "invalid_grant" }, { "error_description", "Two factor required." }, { "TwoFactorProviders", { "7" } },
                        { "TwoFactorProviders2", { { "7", { { "challenge", "chal-123" } } } } } });
                }
                lastPasskeyAssertion = form["twoFactorToken"];
            }
            if (requireDeviceVerification && form["newDeviceOtp"] != "654321") {
                return error({ { "error", "invalid_grant" }, { "error_description", "New device verification required" } });
            }
            return Issue();
        }

        nlohmann::json Sync() const {
            nlohmann::json c = nlohmann::json::array();
            for (const auto& [id, cipher] : ciphers) c.push_back(cipher);
            nlohmann::json f = nlohmann::json::array();
            for (const auto& [id, folder] : folders) f.push_back(folder);
            return { { "profile", Profile() }, { "ciphers", c }, { "folders", f }, { "domains", nlohmann::json::object() } };
        }

        HttpResponse Cipher(const HttpRequest& req, nlohmann::json body) {
            std::string rest = req.path.substr(13);
            std::string id = rest.substr(0, rest.find('/'));
            std::string action = rest.size() > id.size() ? rest.substr(id.size() + 1) : "";

            if (!ciphers.contains(id)) return { 404, "" };
            nlohmann::json& c = ciphers[id];

            if (action.empty() && req.method == HttpMethod::Put) {
                body["revisionDate"] = NowTime();
                c = body;
                return { 200, c.dump() };
            }
            if (action.empty() && req.method == HttpMethod::Delete) {
                ciphers.erase(id);
                return { 200, "" };
            }
            if (action == "delete") { c["deletedDate"] = NowTime(); return { 200, "" }; }
            if (action == "restore") { c["deletedDate"] = nullptr; return { 200, "" }; }

            if (action == "attachment/v2") {
                nlohmann::json att = { { "id", "att-1" }, { "fileName", body["fileName"] }, { "key", body["key"] }, { "size", std::to_string(body["fileSize"].get<int>()) } };
                c["attachments"] = nlohmann::json::array({ att });
                return { 200, nlohmann::json { { "attachmentId", "att-1" }, { "cipherResponse", c } }.dump() };
            }
            if (action.starts_with("attachment/")) {
                std::string attId = action.substr(11);
                if (req.method == HttpMethod::Post) {
                    blobs[attId] = req.file ? req.file->content : "";
                    return { 200, "" };
                }
                if (req.method == HttpMethod::Delete) {
                    c["attachments"] = nlohmann::json::array();
                    blobs.erase(attId);
                    return { 200, "" };
                }
                const auto& att = c["attachments"][0];
                return { 200, nlohmann::json { { "id", attId }, { "fileName", att["fileName"] }, { "key", att["key"] }, { "url", "https://blob.example/" + attId } }.dump() };
            }
            return { 404, "" };
        }
    };

    /*
     * Transport and stores that forward to objects owned by the test, so
     * one fixture can outlive several Vault instances (app restarts).
    */
    class FakeTransport : public HttpTransport {
    public:
        explicit FakeTransport(FakeServer& server) : server(server) {}
        void Configure(const ServerUrls&) override {}
        HttpResponse Send(const HttpRequest& req) override { return server.Handle(req); }
        bool Listen(const std::string&, const std::function<void(std::string_view)>&, std::stop_token) override { return false; }

    private:
        FakeServer& server;
    };

    class SharedSecrets : public SecretStore {
    public:
        explicit SharedSecrets(MemorySecretStore& inner) : inner(inner) {}
        std::optional<SecretString> Get(std::string_view k) override { return inner.Get(k); }
        bool Set(std::string_view k, std::string_view v, SecretProtection p) override { return inner.Set(k, v, p); }
        bool Remove(std::string_view k) override { return inner.Remove(k); }

    private:
        MemorySecretStore& inner;
    };

    class SharedFiles : public FileStore {
    public:
        explicit SharedFiles(MemoryFileStore& inner) : inner(inner) {}
        std::optional<std::string> Read(const std::filesystem::path& f) override { return inner.Read(f); }
        void Write(const std::filesystem::path& f, std::span<const uint8_t> d) override { inner.Write(f, d); }
        void Remove(const std::filesystem::path& f) override { inner.Remove(f); }
        void RemoveTree(const std::filesystem::path& d) override { inner.RemoveTree(d); }
        bool Exists(const std::filesystem::path& f) override { return inner.Exists(f); }
        std::filesystem::path Root() const override { return inner.Root(); }
        using FileStore::Write;

    private:
        MemoryFileStore& inner;
    };

    inline ServerUrls TestUrls() {
        return { "https://vault.example", "https://api.example", "https://icons.example", "wss://notify.example" };
    }
}
