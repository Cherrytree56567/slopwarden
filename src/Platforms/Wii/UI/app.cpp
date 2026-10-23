#include "app.h"

#include <algorithm>
#include <atomic>
#include <cstdio>

#include "Platform/Entropy.h"
#include "Platform/System.h"

namespace clientwarden::wii::ui {
    namespace {
        constexpr int c_margin = 24;
        constexpr int c_content_w = c_screen_w - 2 * c_margin;
        constexpr int c_header_y = 18;
        constexpr int c_header_h = 44;
        constexpr int c_content_y = 74;
        constexpr int c_content_h = c_screen_h - c_content_y - 34;
        constexpr int c_row_h = 44;
        constexpr int c_field_h = 62;

        /**
         * @brief Readable names for schema field keys (as the desktop app shows them).
         */
        SecureString fieldLabel_(std::string_view key) {
            static const std::pair<std::string_view, std::string_view> c_known[] = {
                { "ssn", "Social Security number" }, { "pin", "PIN" }, { "iban", "IBAN" },
                { "swiftCode", "SWIFT code" }, { "code", "Security code" }, { "expMonth", "Expiry month" },
                { "expYear", "Expiry year" }, { "keyFingerprint", "Fingerprint" }, { "address1", "Address 1" },
                { "address2", "Address 2" }, { "address3", "Address 3" }, { "postalCode", "Postcode" },
                { "dateOfBirth", "Date of birth" }, { "nationalIdentificationNumber", "National ID number" },
            };
            for (const auto& entry : c_known) {
                if (entry.first == key) {
                    return SecureString(entry.second);
                }
            }
            SecureString out;
            for (size_t i = 0; i < key.size(); ++i) {
                char c = key[i];
                if (i == 0 && c >= 'a' && c <= 'z') {
                    out.push_back(static_cast<char>(c - 'a' + 'A'));
                } else if (c >= 'A' && c <= 'Z') {
                    out.push_back(' ');
                    out.push_back(static_cast<char>(c - 'A' + 'a'));
                } else {
                    out.push_back(c);
                }
            }
            return out;
        }

        SecureString typeLabel_(std::string_view type) {
            if (type == "login") return "Login";
            if (type == "card") return "Card";
            if (type == "identity") return "Identity";
            if (type == "note") return "Secure note";
            if (type == "sshKey") return "SSH key";
            if (type == "bankAccount") return "Bank account";
            if (type == "driversLicense") return "Driver's licence";
            if (type == "passport") return "Passport";
            return SecureString(type);
        }

        constexpr std::string_view c_types[] = { "login", "card", "identity", "note", "sshKey" };
        constexpr std::string_view c_extended_types[] = { "bankAccount", "driversLicense", "passport" };

        SecureString str_(const Json& j, std::string_view key) {
            return j.is_object() ? stringAt(j, key) : SecureString();
        }

        bool bool_(const Json& j, std::string_view key) {
            return j.is_object() && at(j, key).is_boolean() && at(j, key).get<bool>();
        }

        std::int64_t int_(const Json& j, std::string_view key) {
            return j.is_object() && at(j, key).is_number_integer() ? at(j, key).get<std::int64_t>() : 0;
        }

        /*
         * UTC: the platform corrects the console's clock (Platform/Utc.h) underneath time().
         */
        std::time_t now_() {
            return std::time(nullptr);
        }

        SecureString dateText_(std::int64_t unix_time) {
            if (unix_time <= 0) {
                return "";
            }
            std::time_t t = static_cast<std::time_t>(unix_time);
            std::tm tm {};
            gmtime_r(&t, &tm);
            char buf[32];
            std::strftime(buf, sizeof buf, "%d %b %Y %H:%M UTC", &tm);
            return SecureString(buf);
        }
    }

    namespace {
        std::atomic<bool> g_network_settled { false };
    }

    void markNetworkSettled() {
        g_network_settled = true;
    }

    bool networkSettled() {
        return g_network_settled;
    }

    App::App(Gfx& gfx) : m_gfx_(gfx), m_ui_(gfx) {}

    /*
     * Flow
     */

    void App::call_(std::string_view method, Json args, BridgeClient::Callback callback, bool blocking) {
        if (blocking) {
            m_blocking_++;
        }
        m_bridge_.call(method, std::move(args), [this, callback, blocking](Reply& reply) {
            if (blocking) {
                m_blocking_--;
            }
            if (callback) {
                callback(reply);
            }
        });
    }

    void App::toast_(std::string_view message, bool error) {
        m_toast_ = SecureString(message);
        m_toast_error_ = error;
        m_toast_until_ = std::time(nullptr) + 5;
    }

    void App::go_(Screen screen) {
        if (screen == m_screen_) {
            return;
        }
        m_stack_.push_back(m_screen_);
        m_screen_ = screen;
        m_ui_.resetLayout();
    }

    void App::back_() {
        if (m_stack_.empty()) {
            return;
        }
        Screen previous = m_stack_.back();
        m_stack_.pop_back();
        /*
         * Leaving an item forgets what was revealed and its secrets.
         */
        if (m_screen_ == Screen::Item) {
            m_item_ = Json();
            m_revealed_.clear();
            m_totp_ = Json();
            m_show_history_ = false;
        }
        m_screen_ = previous;
        m_ui_.resetLayout();
        if (m_screen_ == Screen::Items) {
            loadItems_();
        }
    }

    /**
     * @brief Drops everything decrypted (on lock and logout).
     */
    void App::forget_() {
        m_items_ = Json();
        m_item_ = Json();
        m_totp_ = Json();
        m_revealed_.clear();
        m_draft_fields_.clear();
        m_draft_name_.clear();
        m_draft_notes_.clear();
        m_draft_uri_.clear();
        m_draft_totp_.clear();
        m_sends_ = Json();
        m_send_ = Json();
        m_send_text_.clear();
        m_send_password_.clear();
        m_received_ = Json();
        m_open_password_.clear();
        m_generated_.clear();
        m_folders_ = Json();
        m_organizations_ = Json();
        m_filters_.clear();
        m_password_.clear();
        m_code_.clear();
        m_search_.clear();
        m_keyboard_.close();
        m_menu_open_ = false;
        m_type_picker_open_ = false;
        m_confirm_action_ = nullptr;
        m_gfx_.forgetText();
    }

    void App::refreshState_() {
        call_("state.get", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) {
                applyState_(str_(reply.m_result, "state"), str_(reply.m_result, "failure"));
            }
        });
    }

    void App::applyState_(std::string_view state, std::string_view failure) {
        bool was_unlocked = m_state_ == "Unlocked";
        m_state_ = SecureString(state);
        m_failure_ = SecureString(failure);
        auto reset = [this](Screen screen) {
            m_stack_.clear();
            m_screen_ = screen;
            m_ui_.resetLayout();
        };
        if (state == "Unlocked") {
            if (!was_unlocked || m_screen_ < Screen::Home) {
                reset(Screen::Home);
                loadVault_();
            }
            return;
        }
        if (was_unlocked) {
            forget_();
        }
        if (state == "LoggedOut") {
            m_password_.clear();
            reset(Screen::Login);
        } else if (state == "Unlockable") {
            reset(Screen::Unlock);
            call_("vault.profile", Json::object(), [this](Reply& reply) {
                if (reply.m_ok) {
                    m_profile_email_ = str_(reply.m_result, "email");
                }
            });
        } else if (state == "WaitingForTotp" || state == "WaitingForDeviceVerification") {
            m_code_is_device_ = state == "WaitingForDeviceVerification";
            reset(Screen::Code);
        } else if (state == "WaitingForPasskey") {
            reset(Screen::Passkey);
        } else if (state == "Failed") {
            reset(Screen::Failed);
        }
    }

    void App::loginResult_(std::string_view result) {
        m_password_.clear();
        if (result == "Success") {
            refreshState_();
        } else if (result == "NeedsTotp" || result == "NeedsDeviceVerification") {
            m_code_is_device_ = result == "NeedsDeviceVerification";
            m_code_.clear();
            m_screen_ = Screen::Code;
            m_ui_.resetLayout();
        } else if (result == "NeedsPasskey") {
            m_screen_ = Screen::Passkey;
        } else if (result == "InvalidCredentials") {
            toast_("Wrong email or master password");
        } else if (result == "Offline") {
            toast_("Can't reach the server");
        } else {
            toast_("Couldn't log in");
        }
    }

    /*
     * Data
     */

    void App::loadVault_() {
        m_filter_ = { "All items", "all", "" };
        call_("vault.profile", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) {
                m_extended_types_ = bool_(reply.m_result, "extendedItemTypes");
                m_profile_email_ = str_(reply.m_result, "email");
            }
        });
        call_("schema.types", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) m_schema_ = reply.m_result;
        });
        call_("folders.list", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) m_folders_ = reply.m_result;
        });
        call_("organizations.list", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) m_organizations_ = reply.m_result;
        });
        call_("settings.get", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) m_settings_ = reply.m_result;
        });
    }

    void App::loadItems_() {
        m_items_loading_ = true;
        Json args = { { "filter", m_filter_.m_filter }, { "value", m_filter_.m_value }, { "search", m_search_ },
            { "icons", false } };
        call_("items.list", args, [this](Reply& reply) {
            m_items_loading_ = false;
            if (reply.m_ok) {
                m_items_ = reply.m_result;
            } else {
                toast_(reply.m_error);
            }
        });
    }

    void App::openItem_(SecureString id) {
        call_("items.get", { { "id", id } }, [this](Reply& reply) {
            if (!reply.m_ok) {
                toast_(reply.m_error);
                return;
            }
            m_item_ = reply.m_result;
            m_revealed_.clear();
            m_totp_ = Json();
            m_show_history_ = false;
            if (m_screen_ != Screen::Item) {
                go_(Screen::Item);
            }
        }, true);
    }

    void App::loadSends_() {
        call_("sends.list", Json::object(), [this](Reply& reply) {
            if (reply.m_ok) m_sends_ = reply.m_result;
            else toast_(reply.m_error);
        });
    }

    void App::startEdit_(bool existing, std::string_view type) {
        m_draft_fields_.clear();
        m_draft_secret_.clear();
        m_draft_type_ = existing ? str_(m_item_, "type") : SecureString(type);
        m_draft_id_ = existing ? str_(m_item_, "id") : SecureString();
        m_draft_name_ = existing ? str_(m_item_, "name") : SecureString();
        m_draft_notes_ = existing ? str_(m_item_, "notes") : SecureString();
        m_draft_folder_ = existing ? str_(m_item_, "folderId")
                                   : (m_filter_.m_filter == "folder" ? m_filter_.m_value : SecureString());
        m_draft_favorite_ = existing ? bool_(m_item_, "favorite") : m_filter_.m_filter == "favorites";
        m_draft_uri_.clear();
        m_draft_totp_.clear();

        if (existing) {
            for (const Json& field : at(m_item_, "fields")) {
                m_draft_fields_.push_back({ str_(field, "key"), str_(field, "value") });
                m_draft_secret_.push_back({ str_(field, "key"), bool_(field, "secret") });
            }
            const Json& login = at(m_item_, "login");
            if (login.is_object()) {
                const Json& uris = at(login, "uris");
                if (uris.is_array() && !uris.empty() && uris[0].is_string()) {
                    m_draft_uri_ = uris[0].get<SecureString>();
                }
                m_draft_totp_ = str_(login, "totp");
            }
        } else if (m_schema_.is_array()) {
            for (const Json& schema : m_schema_) {
                if (str_(schema, "type") != type) {
                    continue;
                }
                for (const Json& field : at(schema, "fields")) {
                    if (str_(field, "key") == "totp") {
                        continue;
                    }
                    m_draft_fields_.push_back({ str_(field, "key"), SecureString() });
                    m_draft_secret_.push_back({ str_(field, "key"), bool_(field, "secret") });
                }
            }
        }
        go_(Screen::Edit);
    }

    void App::saveEdit_() {
        if (m_draft_name_.empty()) {
            toast_("Give the item a name");
            return;
        }
        Json fields = Json::object();
        for (const std::pair<SecureString, SecureString>& field : m_draft_fields_) {
            fields[field.first] = field.second;
        }
        Json args = { { "type", m_draft_type_ }, { "name", m_draft_name_ }, { "notes", m_draft_notes_ },
            { "folderId", m_draft_folder_ }, { "favorite", m_draft_favorite_ }, { "fields", fields } };
        if (!m_draft_id_.empty()) {
            args["id"] = m_draft_id_;
        } else if (m_filter_.m_filter == "collection" || m_filter_.m_filter == "organization") {
            /*
             * New items made while looking at an organisation go into it.
             */
            SecureString organization = m_filter_.m_filter == "organization" ? m_filter_.m_value : SecureString();
            Json collections = Json::array();
            for (const Json& org : m_organizations_.is_array() ? m_organizations_ : Json::array()) {
                for (const Json& collection : at(org, "collections")) {
                    bool match = m_filter_.m_filter == "collection" ? str_(collection, "id") == m_filter_.m_value
                                                                    : str_(org, "id") == organization;
                    if (match && !bool_(collection, "readOnly") && collections.empty()) {
                        organization = str_(org, "id");
                        collections.push_back(str_(collection, "id"));
                    }
                }
            }
            if (!organization.empty() && !collections.empty()) {
                args["organizationId"] = organization;
                args["collectionIds"] = collections;
            }
        }
        if (m_draft_type_ == "login") {
            Json uris = Json::array();
            if (!m_draft_uri_.empty()) {
                uris.push_back(m_draft_uri_);
            }
            /*
             * Keep any further websites the item already had (only the first is editable here).
             */
            const Json& login = at(m_item_, "login");
            if (!m_draft_id_.empty() && login.is_object()) {
                const Json& old = at(login, "uris");
                for (size_t i = 1; old.is_array() && i < old.size(); ++i) {
                    uris.push_back(old[i]);
                }
            }
            args["login"] = { { "uris", uris }, { "totp", m_draft_totp_ } };
        }
        call_("items.save", args, [this](Reply& reply) {
            if (!reply.m_ok) {
                toast_(reply.m_error);
                return;
            }
            SecureString id = str_(reply.m_result, "id");
            toast_(bool_(reply.m_result, "synced") ? "Saved" : "Saved on the Wii; it will sync later", false);
            m_draft_fields_.clear();
            back_();
            openItem_(id);
        }, true);
    }

    /*
     * Frame
     */

    bool App::frame(Input input) {
        m_input_ = input;
        m_frame_++;

        m_bridge_.poll([this](const Json& event) {
            if (str_(event, "event") == "state") {
                /*
                 * Events can arrive late (a login passes through other states); ask for the
                 * current one rather than trusting the event.
                 */
                refreshState_();
            }
        });

        if (input.any() && m_state_ == "Unlocked" && std::time(nullptr) - m_last_activity_note_ >= 10) {
            m_last_activity_note_ = std::time(nullptr);
            call_("activity.note", Json::object(), nullptr);
        }

        bool blocked = m_blocking_ > 0;
        bool modal = m_keyboard_.isOpen() || m_menu_open_ || m_type_picker_open_ || m_confirm_action_ != nullptr;
        if (blocked) {
            input = Input { input.m_pointer_valid, input.m_pointer_x, input.m_pointer_y };
        }

        if (!blocked && !modal && input.m_home && m_screen_ >= Screen::Login) {
            m_menu_open_ = true;
            input.m_home = false;
            modal = true;
        }
        if (!blocked && !modal && input.m_b && m_toast_until_ > std::time(nullptr)) {
            m_toast_until_ = 0;
            input.m_b = false;
        }
        if (!blocked && !modal && input.m_b) {
            back_();
            input.m_b = false;
        }

        m_input_ = input;    // what the modals see: without the keys handled above
        m_ui_.begin(input);
        m_ui_.setEnabled(!modal && !blocked);
        m_gfx_.clear(colors::c_background);

        switch (m_screen_) {
            case Screen::Entropy: entropy_(); break;
            case Screen::Starting: starting_(); break;
            case Screen::Login: login_(); break;
            case Screen::Code: code_(); break;
            case Screen::Passkey: passkey_(); break;
            case Screen::Unlock: unlock_(); break;
            case Screen::Failed: failed_(); break;
            case Screen::Home: home_(); break;
            case Screen::Items: items_(); break;
            case Screen::Item: item_(); break;
            case Screen::Edit: edit_(); break;
            case Screen::Sends: sends_(); break;
            case Screen::SendEdit: sendEdit_(); break;
            case Screen::SendOpen: sendOpen_(); break;
            case Screen::Generator: generator_(); break;
            case Screen::Settings: settings_(); break;
        }

        m_ui_.setEnabled(!blocked);
        if (m_keyboard_.isOpen()) {
            m_keyboard_.frame(m_ui_, blocked ? Input() : input);
        } else if (m_menu_open_) {
            menu_();
        } else if (m_type_picker_open_) {
            typePicker_();
        } else if (m_confirm_action_) {
            confirm_();
        }
        m_ui_.setEnabled(true);
        toastBar_();
        if (blocked) {
            busy_();
        }

        /*
         * The pointer.
         */
        if (input.m_pointer_valid) {
            int x = input.m_pointer_x;
            int y = input.m_pointer_y;
            for (int i = 0; i < 14; ++i) {
                m_gfx_.fill({ x, y + i, std::max(1, 10 - i * 10 / 14), 1 }, colors::c_on_accent);
                m_gfx_.fill({ x + 1, y + i + 1, std::max(1, 8 - i * 8 / 14), 1 }, colors::c_text);
            }
        }

        m_ui_.end();
        m_gfx_.present();
        return !m_exit_;
    }

    /*
     * Shared pieces
     */

    void App::header_(std::string_view title, bool back) {
        int x = c_margin;
        if (back) {
            if (m_ui_.button({ x, c_header_y, 80, c_header_h }, "Back")) {
                back_();
            }
            x += 92;
        }
        m_gfx_.textFit(x, c_header_y + (c_header_h - m_gfx_.lineHeight(Font::Title)) / 2, title, Font::Title,
                colors::c_text, 300);
    }

    void App::editField_(Rect rect, std::string_view label, SecureString& value, bool masked) {
        if (m_ui_.field(rect, label, value, masked)) {
            SecureString* target = &value;
            m_keyboard_.open(label, value, masked, [target](SecureString text) { *target = std::move(text); });
        }
    }

    void App::toastBar_() {
        if (m_toast_.empty() || m_toast_until_ < std::time(nullptr)) {
            return;
        }
        Rect bar { c_margin, c_screen_h - 30 - 34, c_content_w, 34 };
        m_gfx_.fill(bar, m_toast_error_ ? 0x3b2232 : 0x233a2a);
        m_gfx_.outline(bar, m_toast_error_ ? colors::c_red : colors::c_green, 1);
        m_gfx_.textFit(bar.x + 12, bar.y + (bar.h - m_gfx_.lineHeight(Font::Body)) / 2, m_toast_, Font::Body,
                m_toast_error_ ? colors::c_red : colors::c_green, bar.w - 24);
    }

    void App::busy_() {
        m_gfx_.fill({ 0, 0, c_screen_w, c_screen_h }, 0x0b0b12);
        static const char* c_dots[] = { "Working", "Working.", "Working..", "Working..." };
        const char* text = c_dots[(m_frame_ / 20) % 4];
        m_gfx_.text((c_screen_w - m_gfx_.measure("Working...", Font::Title)) / 2, 200, text, Font::Title,
                colors::c_text);
        m_gfx_.text((c_screen_w - m_gfx_.measure("This can take a while on the Wii", Font::Small)) / 2, 244,
                "This can take a while on the Wii", Font::Small, colors::c_subtext);
        int bar_w = 200;
        int pos = static_cast<int>(m_frame_ * 4 % (bar_w + 60)) - 60;
        m_gfx_.fill({ (c_screen_w - bar_w) / 2, 276, bar_w, 6 }, colors::c_surface2);
        m_gfx_.setClip({ (c_screen_w - bar_w) / 2, 276, bar_w, 6 });
        m_gfx_.fill({ (c_screen_w - bar_w) / 2 + pos, 276, 60, 6 }, colors::c_accent);
        m_gfx_.clearClip();
    }

    void App::menu_() {
        m_gfx_.fill({ 0, 0, c_screen_w, c_screen_h }, 0x0b0b12);
        m_gfx_.text(c_margin + 160, 90, "Menu", Font::Title, colors::c_text);
        int x = c_margin + 160;
        int w = c_content_w - 320;
        int y = 140;
        bool unlocked = m_state_ == "Unlocked";
        bool logged_in = unlocked || m_state_ == "Unlockable";
        if (unlocked && m_ui_.button({ x, y, w, c_row_h }, "Lock now")) {
            m_menu_open_ = false;
            call_("auth.lock", Json::object(), [this](Reply&) { refreshState_(); });
        }
        y += c_row_h + 10;
        if (logged_in && m_ui_.button({ x, y, w, c_row_h }, "Log out", Style::Danger)) {
            m_menu_open_ = false;
            call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); }, true);
        }
        y += c_row_h + 10;
        if (m_ui_.button({ x, y, w, c_row_h }, "Exit to the Homebrew Channel")) {
            m_exit_ = true;
        }
        y += c_row_h + 10;
        if (m_ui_.button({ x, y, w, c_row_h }, "Close", Style::Primary) || m_input_.m_b || m_input_.m_home) {
            m_menu_open_ = false;
        }
    }

    void App::confirm_() {
        m_gfx_.fill({ 0, 0, c_screen_w, c_screen_h }, 0x0b0b12);
        m_gfx_.textWrapped(c_margin + 60, 150, m_confirm_text_, Font::Body, colors::c_text, c_content_w - 120);
        int w = (c_content_w - 120 - 12) / 2;
        if (m_ui_.button({ c_margin + 60, 250, w, c_row_h }, "Cancel") || m_input_.m_b) {
            m_confirm_action_ = nullptr;
            return;
        }
        if (m_ui_.button({ c_margin + 60 + w + 12, 250, w, c_row_h }, "Confirm", Style::Danger)) {
            std::function<void()> action = std::move(m_confirm_action_);
            m_confirm_action_ = nullptr;
            action();
        }
    }

    void App::typePicker_() {
        m_gfx_.fill({ 0, 0, c_screen_w, c_screen_h }, 0x0b0b12);
        m_gfx_.text(c_margin + 120, 40, "New item", Font::Title, colors::c_text);
        std::vector<std::string_view> types(std::begin(c_types), std::end(c_types));
        if (m_extended_types_) {
            types.insert(types.end(), std::begin(c_extended_types), std::end(c_extended_types));
        }
        int y = 86;
        for (std::string_view type : types) {
            if (m_ui_.button({ c_margin + 120, y, c_content_w - 240, 38 }, typeLabel_(type))) {
                m_type_picker_open_ = false;
                startEdit_(false, type);
                return;
            }
            y += 42;
        }
        if (m_ui_.button({ c_margin + 120, y + 6, c_content_w - 240, 38 }, "Cancel", Style::Flat) || m_input_.m_b) {
            m_type_picker_open_ = false;
        }
    }

    /*
     * Start-up and authentication
     */

    void App::entropy_() {
        size_t bits = entropy::creditedBits();
        m_gfx_.text(c_margin, 60, "ClientWarden", Font::Title, colors::c_text);
        m_gfx_.textWrapped(c_margin, 110,
                "Move the Wii Remote around, or point it at the screen and wave it. ClientWarden is "
                "collecting randomness from its motion sensors and camera to keep your vault's "
                "encryption strong. The Wii has no other source of it.",
                Font::Body, colors::c_subtext, c_content_w);
        Rect bar { c_margin, 260, c_content_w, 22 };
        m_gfx_.fill(bar, colors::c_surface2);
        m_gfx_.fill({ bar.x, bar.y, static_cast<int>(bar.w * std::min(bits, entropy::c_required_bits) /
                                                     entropy::c_required_bits), bar.h }, colors::c_accent);
        char label[48];
        std::snprintf(label, sizeof label, "%u of %u bits", static_cast<unsigned>(bits),
                static_cast<unsigned>(entropy::c_required_bits));
        m_gfx_.text(c_margin, 292, label, Font::Small, colors::c_subtext);
        const char* network = networkReady()     ? "Network: connected"
                              : networkSettled() ? "Network: not connected (you can still unlock offline)"
                                                 : "Network: connecting…";
        m_gfx_.text(c_margin, 330, network, Font::Small, networkReady() ? colors::c_green : colors::c_subtext);
        if (entropy::ready() && networkSettled()) {
            m_screen_ = Screen::Starting;
            refreshState_();
        }
    }

    void App::starting_() {
        m_gfx_.text(c_margin, 200, "Opening your vault…", Font::Title, colors::c_text);
    }

    void App::login_() {
        header_("Log in to Bitwarden", false);
        m_ui_.beginColumn("login", { c_margin, c_content_y, c_content_w, c_content_h });

        static const char* c_servers[] = { "Server: bitwarden.com", "Server: bitwarden.eu", "Server: self-hosted" };
        if (m_ui_.button(m_ui_.next(c_row_h), c_servers[m_server_])) {
            m_server_ = (m_server_ + 1) % 3;
        }
        if (m_server_ == 2) {
            editField_(m_ui_.next(c_field_h), "Server URL (e.g. https://vault.example.com)", m_base_url_, false);
        }
        editField_(m_ui_.next(c_field_h), "Email", m_email_, false);
        editField_(m_ui_.next(c_field_h), "Master password", m_password_, true);

        if (m_ui_.button(m_ui_.next(c_row_h), "Log in", Style::Primary)) {
            if (m_email_.empty() || m_password_.empty()) {
                toast_("Enter your email and master password");
            } else if (m_server_ == 2 && m_base_url_.empty()) {
                toast_("Enter your server's URL");
            } else if (!networkReady()) {
                toast_("The Wii isn't connected to the internet");
            } else {
                Json server;
                if (m_server_ == 0) {
                    server = { { "vault", "https://vault.bitwarden.com" }, { "api", "https://api.bitwarden.com" },
                        { "icons", "https://icons.bitwarden.net" },
                        { "notifications", "https://notifications.bitwarden.com" } };
                } else if (m_server_ == 1) {
                    server = { { "vault", "https://vault.bitwarden.eu" }, { "api", "https://api.bitwarden.eu" },
                        { "icons", "https://icons.bitwarden.eu" },
                        { "notifications", "https://notifications.bitwarden.eu" } };
                } else {
                    SecureString base = trim(m_base_url_);
                    while (!base.empty() && base.back() == '/') {
                        base.pop_back();
                    }
                    if (base.find("://") == SecureString::npos) {
                        base = "https://" + base;
                    }
                    server = { { "vault", base }, { "api", base + "/api" }, { "icons", base + "/icons" },
                        { "notifications", base + "/notifications" } };
                }
                call_("auth.setServer", server, nullptr, true);
                call_("auth.login", { { "email", trim(m_email_) }, { "password", m_password_ } },
                        [this](Reply& reply) {
                            if (!reply.m_ok) {
                                m_password_.clear();
                                toast_(reply.m_error);
                                return;
                            }
                            loginResult_(str_(reply.m_result, "result"));
                        }, true);
            }
        }
        Rect note = m_ui_.next(60);
        m_gfx_.textWrapped(note.x, note.y,
                networkReady() ? "Logging in derives your key from your password, which takes a while on the Wii."
                               : "Waiting for the network…",
                Font::Small, colors::c_subtext, note.w);
        m_ui_.endColumn();
    }

    void App::code_() {
        header_(m_code_is_device_ ? "Check your email" : "Two-step login", false);
        m_ui_.beginColumn("code", { c_margin, c_content_y, c_content_w, c_content_h });
        Rect text = m_ui_.next(50);
        m_gfx_.textWrapped(text.x, text.y,
                m_code_is_device_ ? "Bitwarden emailed you a code to confirm this new device."
                                  : "Enter the code from your authenticator app (or the one emailed to you).",
                Font::Body, colors::c_subtext, text.w);
        editField_(m_ui_.next(c_field_h), "Code", m_code_, false);
        if (m_ui_.button(m_ui_.next(c_row_h), "Continue", Style::Primary)) {
            call_("auth.submitCode", { { "code", trim(m_code_) } }, [this](Reply& reply) {
                m_code_.clear();
                if (!reply.m_ok) {
                    toast_(reply.m_error);
                    return;
                }
                SecureString result = str_(reply.m_result, "result");
                if (result == "InvalidCredentials") {
                    toast_("That code didn't work");
                } else {
                    loginResult_(result);
                }
            }, true);
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Cancel")) {
            call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); });
        }
        m_ui_.endColumn();
    }

    void App::passkey_() {
        header_("Passkey needed", false);
        m_gfx_.textWrapped(c_margin, c_content_y + 10,
                "This account asks for a passkey or security key to log in, which the Wii can't "
                "provide. Turn on another two-step method (an authenticator app or email) for your "
                "account, then try again.",
                Font::Body, colors::c_subtext, c_content_w);
        if (m_ui_.button({ c_margin, c_content_y + 150, 200, c_row_h }, "Back to login", Style::Primary)) {
            call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); });
        }
    }

    void App::unlock_() {
        header_("Vault locked", false);
        m_ui_.beginColumn("unlock", { c_margin, c_content_y, c_content_w, c_content_h });
        Rect who = m_ui_.next(30);
        m_gfx_.text(who.x, who.y, m_profile_email_, Font::Body, colors::c_subtext);
        editField_(m_ui_.next(c_field_h), "Master password", m_password_, true);
        if (m_ui_.button(m_ui_.next(c_row_h), "Unlock", Style::Primary)) {
            if (m_password_.empty()) {
                toast_("Enter your master password");
            } else {
                call_("auth.unlock", { { "password", m_password_ } }, [this](Reply& reply) {
                    m_password_.clear();
                    if (!reply.m_ok) {
                        toast_(reply.m_error);
                        return;
                    }
                    SecureString result = str_(reply.m_result, "result");
                    if (result == "Success") {
                        refreshState_();
                    } else if (result == "InvalidPassword") {
                        toast_("Wrong master password");
                    } else {
                        toast_("Couldn't unlock");
                    }
                }, true);
            }
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Log out", Style::Danger)) {
            m_confirm_text_ = "Log out? You'll need your email, master password and any two-step code to log in again.";
            m_confirm_action_ = [this]() {
                call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); }, true);
            };
        }
        m_ui_.endColumn();
    }

    void App::failed_() {
        header_("Something went wrong", false);
        m_gfx_.textWrapped(c_margin, c_content_y + 10,
                m_failure_.empty() ? SecureString("The vault stopped working safely.") : m_failure_, Font::Body,
                colors::c_subtext, c_content_w);
        if (m_ui_.button({ c_margin, c_content_y + 150, 200, c_row_h }, "Log out", Style::Danger)) {
            call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); }, true);
        }
    }

    /*
     * The vault
     */

    void App::home_() {
        header_("Vault", false);
        if (m_ui_.button({ c_screen_w - c_margin - 100, c_header_y, 100, c_header_h }, "Sync")) {
            call_("vault.sync", Json::object(), [this](Reply& reply) {
                if (reply.m_ok && reply.m_result == true) {
                    toast_("Synced", false);
                    loadVault_();
                } else {
                    toast_("Couldn't sync");
                }
            }, true);
        }

        std::vector<Filter> filters;
        filters.push_back({ "All items", "all", "" });
        filters.push_back({ "Favourites", "favorites", "" });
        filters.push_back({ "Types", "", "", 0, true });
        for (std::string_view type : c_types) {
            filters.push_back({ typeLabel_(type), "type", SecureString(type), 1 });
        }
        if (m_extended_types_) {
            for (std::string_view type : c_extended_types) {
                filters.push_back({ typeLabel_(type), "type", SecureString(type), 1 });
            }
        }
        if (m_folders_.is_array() && !m_folders_.empty()) {
            filters.push_back({ "Folders", "", "", 0, true });
            for (const Json& folder : m_folders_) {
                filters.push_back({ str_(folder, "name"), "folder", str_(folder, "id"), 1 });
            }
        }
        if (m_organizations_.is_array() && !m_organizations_.empty()) {
            filters.push_back({ "Organisations", "", "", 0, true });
            filters.push_back({ "My vault", "personal", "", 1 });
            for (const Json& org : m_organizations_) {
                filters.push_back({ str_(org, "name"), "organization", str_(org, "id"), 1 });
                for (const Json& collection : at(org, "collections")) {
                    filters.push_back({ str_(collection, "name"), "collection", str_(collection, "id"), 2 });
                }
            }
        }
        filters.push_back({ "More", "", "", 0, true });
        filters.push_back({ "Archived", "archived", "", 1 });
        filters.push_back({ "Trash", "trash", "", 1 });
        filters.push_back({ "Send", "@send", "", 1 });
        filters.push_back({ "Generator", "@generator", "", 1 });
        filters.push_back({ "Settings", "@settings", "", 1 });

        m_ui_.beginColumn("home", { c_margin, c_content_y, c_content_w, c_content_h });
        for (const Filter& filter : filters) {
            if (filter.m_section) {
                Rect r = m_ui_.next(28, 2);
                m_gfx_.text(r.x + 4, r.y + 8, filter.m_label, Font::Small, colors::c_accent);
                continue;
            }
            Rect r = m_ui_.next(38, 4);
            r.x += filter.m_indent * 18;
            r.w -= filter.m_indent * 18;
            if (m_ui_.row(r, filter.m_label, "")) {
                if (filter.m_filter == "@send") {
                    go_(Screen::Sends);
                    loadSends_();
                } else if (filter.m_filter == "@generator") {
                    go_(Screen::Generator);
                } else if (filter.m_filter == "@settings") {
                    go_(Screen::Settings);
                    call_("settings.get", Json::object(), [this](Reply& reply) {
                        if (reply.m_ok) m_settings_ = reply.m_result;
                    });
                } else {
                    m_filter_ = filter;
                    m_search_.clear();
                    m_items_ = Json();
                    go_(Screen::Items);
                    loadItems_();
                }
            }
        }
        m_ui_.endColumn();
    }

    void App::items_() {
        header_(m_filter_.m_label, true);
        bool can_add = m_filter_.m_filter != "trash" && m_filter_.m_filter != "archived";
        if (can_add && m_ui_.button({ c_screen_w - c_margin - 100, c_header_y, 100, c_header_h }, "New",
                    Style::Primary)) {
            if (m_filter_.m_filter == "type") {
                startEdit_(false, m_filter_.m_value);
            } else {
                m_type_picker_open_ = true;
            }
        }

        m_ui_.beginColumn("items", { c_margin, c_content_y, c_content_w, c_content_h });
        SecureString before = m_search_;
        Rect search = m_ui_.next(c_field_h);
        if (m_ui_.field(search, "Search", m_search_, false)) {
            m_keyboard_.open("Search", m_search_, false, [this](SecureString text) {
                m_search_ = std::move(text);
                loadItems_();
            });
        }
        if (!m_items_.is_array() || m_items_.empty()) {
            Rect r = m_ui_.next(40);
            m_gfx_.text(r.x + 4, r.y + 10, m_items_loading_ ? "Loading…" : "No items", Font::Body,
                    colors::c_subtext);
        } else {
            for (const Json& item : m_items_) {
                SecureString badge = bool_(item, "favorite") ? "★" : "";
                SecureString subtitle = str_(item, "subtitle");
                if (subtitle.empty()) {
                    subtitle = typeLabel_(str_(item, "type"));
                }
                if (m_ui_.row(m_ui_.next(52, 4), str_(item, "name"), subtitle, false, badge)) {
                    SecureString id = str_(item, "id");
                    if (bool_(item, "reprompt")) {
                        m_keyboard_.open("Master password (this item asks for it)", "", true,
                                [this, id](SecureString password) {
                                    call_("auth.verifyPassword", { { "password", password } },
                                            [this, id](Reply& reply) {
                                                if (reply.m_ok && reply.m_result == true) {
                                                    openItem_(id);
                                                } else {
                                                    toast_("Wrong master password");
                                                }
                                            }, true);
                                });
                    } else {
                        openItem_(id);
                    }
                }
            }
        }
        m_ui_.endColumn();
    }

    void App::item_() {
        if (!m_item_.is_object()) {
            header_("", true);
            return;
        }
        header_(str_(m_item_, "name"), true);
        SecureString id = str_(m_item_, "id");
        bool deleted = int_(m_item_, "deleted") > 0;
        bool archived = int_(m_item_, "archived") > 0;
        bool can_edit = bool_(m_item_, "canEdit");
        bool can_view = bool_(m_item_, "canViewPassword");

        /*
         * Live TOTP: fetch a new code when the current one runs out.
         */
        const Json& login = at(m_item_, "login");
        bool has_totp = login.is_object() && !str_(login, "totp").empty();
        if (has_totp && !m_totp_loading_ && (m_totp_.is_null() || now_() >= int_(m_totp_, "validUntil"))) {
            m_totp_loading_ = true;
            call_("items.totp", { { "id", id } }, [this, id](Reply& reply) {
                m_totp_loading_ = false;
                if (str_(m_item_, "id") == id) {
                    m_totp_ = reply.m_ok && reply.m_result.is_object() ? reply.m_result : Json::object();
                    if (!reply.m_ok) {
                        m_totp_["validUntil"] = static_cast<std::int64_t>(now_() + 30);
                    }
                }
            });
        }

        m_ui_.beginColumn("item", { c_margin, c_content_y, c_content_w, c_content_h });

        /*
         * Actions.
         */
        Rect actions = m_ui_.next(40);
        int bx = actions.x;
        auto action = [&](std::string_view label, Style style, int w) {
            bool hit = m_ui_.button({ bx, actions.y, w, actions.h }, label, style);
            bx += w + 8;
            return hit;
        };
        auto reload = [this, id](Reply& reply) {
            if (!reply.m_ok || reply.m_result == false) {
                toast_(reply.m_ok ? SecureString("That didn't work") : reply.m_error);
            }
            openItem_(id);
        };
        if (!deleted) {
            if (can_edit && action("Edit", Style::Primary, 80)) {
                startEdit_(true, "");
            }
            if (action(bool_(m_item_, "favorite") ? "Unfavourite" : "Favourite", Style::Normal, 128)) {
                call_("items.save", { { "id", id }, { "favorite", !bool_(m_item_, "favorite") } }, reload, true);
            }
            if (can_edit && action(archived ? "Unarchive" : "Archive", Style::Normal, 110)) {
                call_(archived ? "items.unarchive" : "items.archive", { { "id", id } }, reload, true);
            }
            if (can_edit && action("Trash", Style::Danger, 80)) {
                call_("items.bin", { { "id", id } }, [this](Reply& reply) {
                    toast_(reply.m_ok ? "Moved to the trash" : reply.m_error, !reply.m_ok);
                    back_();
                }, true);
            }
        } else if (can_edit) {
            if (action("Restore", Style::Primary, 100)) {
                call_("items.restore", { { "id", id } }, reload, true);
            }
            if (action("Delete forever", Style::Danger, 150)) {
                m_confirm_text_ = "Delete this item forever? This can't be undone.";
                m_confirm_action_ = [this, id]() {
                    call_("items.delete", { { "id", id } }, [this](Reply& reply) {
                        toast_(reply.m_ok ? "Deleted" : reply.m_error, !reply.m_ok);
                        back_();
                    }, true);
                };
            }
        }

        Rect type_row = m_ui_.next(24);
        m_gfx_.text(type_row.x, type_row.y, typeLabel_(str_(m_item_, "type")), Font::Small, colors::c_subtext);

        /*
         * A labelled value; secrets get a Reveal button.
         */
        auto value_row = [&](std::string_view key, std::string_view label, std::string_view value, bool secret) {
            if (value.empty() && !(secret && !can_view)) {
                return;
            }
            bool revealed = m_revealed_.count(SecureString(key)) > 0;
            int text_w = c_content_w - (secret && can_view ? 110 : 0);
            int lines = 1;
            if (!secret || revealed) {
                lines = std::max(1, m_gfx_.measure(value, Font::Body) / std::max(1, text_w - 24) + 1);
                lines = std::min(lines, 12);
            }
            Rect r = m_ui_.next(24 + lines * m_gfx_.lineHeight(Font::Body) + 10, 4);
            m_gfx_.fill(r, colors::c_surface);
            m_gfx_.text(r.x + 10, r.y + 4, label, Font::Small, colors::c_subtext);
            if (secret && !can_view) {
                m_gfx_.text(r.x + 10, r.y + 22, "Hidden by your organisation", Font::Body, colors::c_subtext);
                return;
            }
            if (secret && !revealed) {
                m_gfx_.text(r.x + 10, r.y + 22, "••••••••", Font::Body, colors::c_text);
            } else {
                m_gfx_.textWrapped(r.x + 10, r.y + 22, value, Font::Body, colors::c_text, text_w - 24);
            }
            if (secret) {
                SecureString button_label = SecureString(revealed ? "Hide " : "Reveal ") + SecureString(label);
                Rect b { r.x + r.w - 104, r.y + (r.h - 34) / 2, 96, 34 };
                bool hit = m_ui_.button(b, button_label, Style::Normal);
                m_gfx_.fill({ b.x + 2, b.y + 2, b.w - 4, b.h - 4 },
                        b.contains(m_input_.m_pointer_x, m_input_.m_pointer_y) && m_input_.m_pointer_valid
                                ? colors::c_overlay
                                : colors::c_surface2);
                m_gfx_.text(b.x + (b.w - m_gfx_.measure(revealed ? "Hide" : "Reveal", Font::BodyBold)) / 2,
                        b.y + (b.h - m_gfx_.lineHeight(Font::BodyBold)) / 2, revealed ? "Hide" : "Reveal",
                        Font::BodyBold, colors::c_text);
                if (hit) {
                    if (revealed) {
                        m_revealed_.erase(SecureString(key));
                    } else {
                        m_revealed_.insert(SecureString(key));
                    }
                }
            }
        };

        for (const Json& field : at(m_item_, "fields")) {
            SecureString key = str_(field, "key");
            value_row(key, fieldLabel_(key), str_(field, "value"), bool_(field, "secret"));
        }

        if (has_totp) {
            Rect r = m_ui_.next(76, 4);
            m_gfx_.fill(r, colors::c_surface);
            m_gfx_.text(r.x + 10, r.y + 4, "Verification code (TOTP)", Font::Small, colors::c_subtext);
            SecureString code = str_(m_totp_, "code");
            if (code.size() == 6) {
                code = code.substr(0, 3) + " " + code.substr(3);
            }
            m_gfx_.text(r.x + 10, r.y + 24, code.empty() ? SecureString("…") : code, Font::Code, colors::c_text);
            std::int64_t left = int_(m_totp_, "validUntil") - now_();
            std::int64_t period = std::max<std::int64_t>(1, int_(m_totp_, "period"));
            if (left > 0 && left <= period) {
                Rect bar { r.x + 180, r.y + 42, 160, 8 };
                m_gfx_.fill(bar, colors::c_surface2);
                m_gfx_.fill({ bar.x, bar.y, static_cast<int>(bar.w * left / period), bar.h },
                        left <= 5 ? colors::c_red : colors::c_accent);
                char seconds[16];
                std::snprintf(seconds, sizeof seconds, "%llds", static_cast<long long>(left));
                m_gfx_.text(bar.x + bar.w + 10, r.y + 34, seconds, Font::Small, colors::c_subtext);
            }
        }

        if (login.is_object()) {
            const Json& uris = at(login, "uris");
            int n = 0;
            for (const Json& uri : uris.is_array() ? uris : Json::array()) {
                if (uri.is_string()) {
                    value_row("uri" + toSecureString(n), n == 0 ? "Website" : "Website " + toSecureString(n + 1),
                            uri.get<SecureString>(), false);
                    n++;
                }
            }
            const Json& passkeys = at(login, "passkeys");
            if (passkeys.is_array() && !passkeys.empty()) {
                value_row("passkey", "Passkey", "Saved (can't be used on the Wii)", false);
            }
        }

        value_row("notes", "Notes", str_(m_item_, "notes"), false);

        int custom = 0;
        for (const Json& field : at(m_item_, "customFields")) {
            int type = static_cast<int>(int_(field, "type"));
            SecureString value = str_(field, "value");
            if (type == 2) {
                value = at(field, "value").is_string() && value == "true" ? "Yes" : "No";
            }
            value_row("custom" + toSecureString(custom++), str_(field, "name"), value, type == 1);
        }

        const Json& attachments = at(m_item_, "attachments");
        if (attachments.is_array() && !attachments.empty()) {
            Rect r = m_ui_.next(28);
            m_gfx_.text(r.x + 4, r.y + 8, "Attachments (open them on another device)", Font::Small, colors::c_accent);
            for (const Json& attachment : attachments) {
                Rect a = m_ui_.next(28, 2);
                m_gfx_.textFit(a.x + 10, a.y + 4, str_(attachment, "name") + "  (" + str_(attachment, "size") + ")",
                        Font::Body, colors::c_text, a.w - 20);
            }
        }

        if (login.is_object()) {
            const Json& history = at(login, "passwordHistory");
            if (history.is_array() && !history.empty()) {
                if (m_ui_.button(m_ui_.next(36), m_show_history_ ? "Hide password history" : "Password history")) {
                    m_show_history_ = !m_show_history_;
                }
                if (m_show_history_) {
                    int n = 0;
                    for (const Json& entry : history) {
                        value_row("history" + toSecureString(n++), dateText_(int_(entry, "date")),
                                str_(entry, "password"), true);
                    }
                }
            }
        }

        Rect dates = m_ui_.next(40);
        m_gfx_.text(dates.x + 4, dates.y, "Created " + dateText_(int_(m_item_, "created")), Font::Small,
                colors::c_subtext);
        m_gfx_.text(dates.x + 4, dates.y + 18, "Updated " + dateText_(int_(m_item_, "revised")), Font::Small,
                colors::c_subtext);
        m_ui_.endColumn();
    }

    void App::edit_() {
        header_(m_draft_id_.empty() ? "New " + typeLabel_(m_draft_type_) : SecureString("Edit item"), true);
        if (m_ui_.button({ c_screen_w - c_margin - 100, c_header_y, 100, c_header_h }, "Save", Style::Primary)) {
            saveEdit_();
            return;
        }
        m_ui_.beginColumn("edit", { c_margin, c_content_y, c_content_w, c_content_h });
        editField_(m_ui_.next(c_field_h), "Name", m_draft_name_, false);
        for (size_t i = 0; i < m_draft_fields_.size(); ++i) {
            bool secret = i < m_draft_secret_.size() && m_draft_secret_[i].second;
            editField_(m_ui_.next(c_field_h), fieldLabel_(m_draft_fields_[i].first), m_draft_fields_[i].second, secret);
            if (m_draft_fields_[i].first == "password") {
                if (m_ui_.button(m_ui_.next(36), "Generate a password")) {
                    size_t index = i;
                    call_("generator.password", { { "length", 20 }, { "uppercase", true }, { "numbers", true },
                                                        { "symbols", true } },
                            [this, index](Reply& reply) {
                                if (reply.m_ok && index < m_draft_fields_.size() && reply.m_result.is_string()) {
                                    m_draft_fields_[index].second = reply.m_result.get<SecureString>();
                                }
                            });
                }
            }
        }
        if (m_draft_type_ == "login") {
            editField_(m_ui_.next(c_field_h), "Website", m_draft_uri_, false);
            editField_(m_ui_.next(c_field_h), "Authenticator key (TOTP)", m_draft_totp_, true);
        }
        editField_(m_ui_.next(c_field_h), "Notes", m_draft_notes_, false);

        /*
         * Folder: cycles through "No folder" and the folders.
         */
        SecureString folder_name = "No folder";
        int folder_index = -1;
        int count = m_folders_.is_array() ? static_cast<int>(m_folders_.size()) : 0;
        for (int i = 0; i < count; ++i) {
            if (str_(m_folders_[i], "id") == m_draft_folder_) {
                folder_name = str_(m_folders_[i], "name");
                folder_index = i;
            }
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Folder: " + folder_name)) {
            int next = folder_index + 1;
            m_draft_folder_ = next < count ? str_(m_folders_[next], "id") : SecureString();
        }
        m_ui_.toggle(m_ui_.next(c_row_h), "Favourite", m_draft_favorite_);
        if (m_ui_.button(m_ui_.next(c_row_h), "Save", Style::Primary)) {
            saveEdit_();
        }
        m_ui_.endColumn();
    }

    /*
     * Send
     */

    void App::sends_() {
        header_("Send", true);
        m_ui_.beginColumn("sends", { c_margin, c_content_y, c_content_w, c_content_h });
        Rect buttons = m_ui_.next(c_row_h);
        int w = (buttons.w - 8) / 2;
        if (m_ui_.button({ buttons.x, buttons.y, w, buttons.h }, "New text Send", Style::Primary)) {
            m_send_ = Json::object();
            m_send_name_.clear();
            m_send_text_.clear();
            m_send_password_.clear();
            m_send_max_views_.clear();
            m_send_hidden_ = false;
            m_send_disabled_ = false;
            go_(Screen::SendEdit);
        }
        if (m_ui_.button({ buttons.x + w + 8, buttons.y, w, buttons.h }, "Open a Send link")) {
            m_open_link_.clear();
            m_open_password_.clear();
            m_received_ = Json();
            m_open_message_.clear();
            m_received_revealed_ = false;
            go_(Screen::SendOpen);
        }
        if (!m_sends_.is_array() || m_sends_.empty()) {
            Rect r = m_ui_.next(60);
            m_gfx_.textWrapped(r.x + 4, r.y + 10, "No Sends. Share text securely with a link.", Font::Body,
                    colors::c_subtext, r.w);
        } else {
            for (const Json& send : m_sends_) {
                std::int64_t views = int_(send, "accessCount");
                SecureString subtitle = toSecureString(views) + (views == 1 ? " view" : " views");
                if (bool_(send, "disabled")) subtitle += " · disabled";
                if (bool_(send, "hasPassword")) subtitle += " · password";
                subtitle += str_(send, "type") == "file" ? " · file" : "";
                SecureString name = str_(send, "name");
                if (m_ui_.row(m_ui_.next(52, 4), name.empty() ? SecureString("Untitled") : name, subtitle)) {
                    m_send_ = send;
                    m_send_name_ = str_(send, "name");
                    m_send_text_ = str_(send, "text");
                    m_send_password_.clear();
                    std::int64_t max = int_(send, "maxAccessCount");
                    m_send_max_views_ = max > 0 ? toSecureString(max) : SecureString();
                    m_send_hidden_ = bool_(send, "textHidden");
                    m_send_disabled_ = bool_(send, "disabled");
                    go_(Screen::SendEdit);
                }
            }
        }
        m_ui_.endColumn();
    }

    void App::sendEdit_() {
        SecureString id = str_(m_send_, "id");
        bool is_file = str_(m_send_, "type") == "file";
        header_(id.empty() ? "New Send" : "Edit Send", true);
        m_ui_.beginColumn("send", { c_margin, c_content_y, c_content_w, c_content_h });
        editField_(m_ui_.next(c_field_h), "Name", m_send_name_, false);
        if (is_file) {
            Rect r = m_ui_.next(30);
            m_gfx_.text(r.x + 4, r.y + 6, "File: " + str_(m_send_, "fileName"), Font::Body, colors::c_text);
        } else {
            editField_(m_ui_.next(c_field_h), "Text", m_send_text_, false);
            m_ui_.toggle(m_ui_.next(c_row_h), "Hide the text until opened", m_send_hidden_);
        }
        editField_(m_ui_.next(c_field_h),
                bool_(m_send_, "hasPassword") ? "New password (empty keeps it)" : "Password (optional)",
                m_send_password_, true);
        editField_(m_ui_.next(c_field_h), "Maximum views (empty for no limit)", m_send_max_views_, false);
        m_ui_.toggle(m_ui_.next(c_row_h), "Disable this Send", m_send_disabled_);

        if (m_ui_.button(m_ui_.next(c_row_h), "Save", Style::Primary)) {
            Json args = { { "name", m_send_name_ }, { "disabled", m_send_disabled_ } };
            if (!id.empty()) {
                args["id"] = id;
            } else {
                args["type"] = "text";
                args["deletionDate"] = static_cast<std::int64_t>(now_() + 7 * 86400);
            }
            if (!is_file) {
                args["text"] = m_send_text_;
                args["textHidden"] = m_send_hidden_;
            }
            if (!m_send_password_.empty()) {
                args["password"] = m_send_password_;
            }
            std::int64_t max = 0;
            if (!m_send_max_views_.empty() && !parseInt(m_send_max_views_, max)) {
                toast_("Maximum views must be a number");
                m_ui_.endColumn();
                return;
            }
            args["maxAccessCount"] = max;
            call_("sends.save", args, [this](Reply& reply) {
                if (!reply.m_ok) {
                    toast_(reply.m_error);
                    return;
                }
                m_send_ = reply.m_result;
                m_send_password_.clear();
                toast_("Saved. The link is below.", false);
                loadSends_();
            }, true);
        }

        SecureString link = str_(m_send_, "shareUrl");
        if (!link.empty()) {
            Rect title = m_ui_.next(24);
            m_gfx_.text(title.x + 4, title.y + 4, "Share link (type it on the other device)", Font::Small,
                    colors::c_accent);
            int h = std::max(1, m_gfx_.measure(link, Font::Body) / (c_content_w - 20) + 1) *
                            m_gfx_.lineHeight(Font::Body) + 12;
            Rect r = m_ui_.next(h);
            m_gfx_.fill(r, colors::c_surface);
            m_gfx_.textWrapped(r.x + 10, r.y + 6, link, Font::Body, colors::c_text, r.w - 20);
        }
        if (!id.empty()) {
            if (bool_(m_send_, "hasPassword") && m_ui_.button(m_ui_.next(c_row_h), "Remove password")) {
                call_("sends.removePassword", { { "id", id } }, [this](Reply& reply) {
                    toast_(reply.m_ok ? "Password removed" : reply.m_error, !reply.m_ok);
                    if (reply.m_ok) {
                        m_send_["hasPassword"] = false;
                    }
                    loadSends_();
                }, true);
            }
            if (m_ui_.button(m_ui_.next(c_row_h), "Delete Send", Style::Danger)) {
                m_confirm_text_ = "Delete this Send? Its link will stop working.";
                m_confirm_action_ = [this, id]() {
                    call_("sends.delete", { { "id", id } }, [this](Reply& reply) {
                        toast_(reply.m_ok ? "Deleted" : reply.m_error, !reply.m_ok);
                        loadSends_();
                        back_();
                    }, true);
                };
            }
        }
        m_ui_.endColumn();
    }

    void App::sendOpen_() {
        header_("Open a Send", true);
        m_ui_.beginColumn("open", { c_margin, c_content_y, c_content_w, c_content_h });
        if (m_received_.is_object()) {
            Rect title = m_ui_.next(34);
            m_gfx_.textFit(title.x + 4, title.y, str_(m_received_, "name"), Font::Title, colors::c_text, title.w);
            SecureString creator = str_(m_received_, "creator");
            if (!creator.empty()) {
                Rect r = m_ui_.next(22);
                m_gfx_.text(r.x + 4, r.y, "Shared by " + creator, Font::Small, colors::c_subtext);
            }
            if (str_(m_received_, "type") == "file") {
                Rect r = m_ui_.next(60);
                m_gfx_.textWrapped(r.x + 4, r.y, "This Send is a file (" + str_(m_received_, "fileName") +
                        "). Files can't be saved on the Wii; open the link on another device.",
                        Font::Body, colors::c_subtext, r.w);
            } else if (bool_(m_received_, "textHidden") && !m_received_revealed_) {
                if (m_ui_.button(m_ui_.next(c_row_h), "Reveal the text", Style::Primary)) {
                    m_received_revealed_ = true;
                }
            } else {
                SecureString text = str_(m_received_, "text");
                int lines = std::max(1, m_gfx_.measure(text, Font::Body) / (c_content_w - 20) + 1);
                Rect r = m_ui_.next(lines * m_gfx_.lineHeight(Font::Body) + 40);
                m_gfx_.fill(r, colors::c_surface);
                m_gfx_.textWrapped(r.x + 10, r.y + 8, text, Font::Body, colors::c_text, r.w - 20);
            }
            if (m_ui_.button(m_ui_.next(c_row_h), "Done")) {
                m_received_ = Json();
                back_();
            }
            m_ui_.endColumn();
            return;
        }
        editField_(m_ui_.next(c_field_h), "Send link", m_open_link_, false);
        editField_(m_ui_.next(c_field_h), "Password (if it has one)", m_open_password_, true);
        if (m_ui_.button(m_ui_.next(c_row_h), "Open", Style::Primary)) {
            call_("sends.open", { { "link", trim(m_open_link_) }, { "password", m_open_password_ } },
                    [this](Reply& reply) {
                        if (!reply.m_ok) {
                            toast_(reply.m_error);
                            return;
                        }
                        SecureString result = str_(reply.m_result, "result");
                        if (result == "Success") {
                            m_received_ = at(reply.m_result, "send");
                            m_open_password_.clear();
                            m_open_message_.clear();
                        } else if (result == "NeedsPassword") {
                            m_open_message_ = "This Send is password protected.";
                        } else if (result == "WrongPassword") {
                            m_open_message_ = "Wrong password.";
                        } else if (result == "NotAvailable") {
                            m_open_message_ = "This Send has expired, been deleted or reached its view limit.";
                        } else if (result == "InvalidLink") {
                            m_open_message_ = "That isn't a Send link.";
                        } else if (result == "Offline") {
                            m_open_message_ = "Can't reach the server.";
                        } else {
                            m_open_message_ = "Couldn't open this Send.";
                        }
                    }, true);
        }
        if (!m_open_message_.empty()) {
            Rect r = m_ui_.next(50);
            m_gfx_.textWrapped(r.x + 4, r.y + 4, m_open_message_, Font::Body, colors::c_red, r.w);
        }
        m_ui_.endColumn();
    }

    /*
     * Generator and settings
     */

    void App::generator_() {
        header_("Generator", true);
        m_ui_.beginColumn("generator", { c_margin, c_content_y, c_content_w, c_content_h });
        Rect modes = m_ui_.next(c_row_h);
        int w = (modes.w - 16) / 3;
        static const char* c_modes[] = { "Password", "Passphrase", "PIN" };
        for (int i = 0; i < 3; ++i) {
            if (m_ui_.button({ modes.x + i * (w + 8), modes.y, w, modes.h }, c_modes[i],
                        m_gen_mode_ == i ? Style::Primary : Style::Normal)) {
                m_gen_mode_ = i;
                m_generated_.clear();
            }
        }

        int& amount = m_gen_mode_ == 0 ? m_gen_length_ : m_gen_mode_ == 1 ? m_gen_words_ : m_gen_digits_;
        int low = m_gen_mode_ == 0 ? 5 : m_gen_mode_ == 1 ? 3 : 4;
        int high = m_gen_mode_ == 0 ? 128 : m_gen_mode_ == 1 ? 20 : 12;
        Rect amount_row = m_ui_.next(c_row_h);
        if (m_ui_.button({ amount_row.x, amount_row.y, 60, amount_row.h }, "−")) {
            amount = std::max(low, amount - 1);
        }
        char text[48];
        std::snprintf(text, sizeof text, m_gen_mode_ == 0 ? "%d characters" : m_gen_mode_ == 1 ? "%d words" : "%d digits",
                amount);
        m_gfx_.text(amount_row.x + 80, amount_row.y + 10, text, Font::Body, colors::c_text);
        if (m_ui_.button({ amount_row.x + 260, amount_row.y, 60, amount_row.h }, "+")) {
            amount = std::min(high, amount + 1);
        }
        if (m_gen_mode_ == 0) {
            m_ui_.toggle(m_ui_.next(c_row_h), "Uppercase letters", m_gen_upper_);
            m_ui_.toggle(m_ui_.next(c_row_h), "Numbers", m_gen_numbers_);
            m_ui_.toggle(m_ui_.next(c_row_h), "Symbols", m_gen_symbols_);
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Generate", Style::Primary)) {
            auto store = [this](Reply& reply) {
                if (reply.m_ok && reply.m_result.is_string()) {
                    m_generated_ = reply.m_result.get<SecureString>();
                } else {
                    toast_(reply.m_error);
                }
            };
            if (m_gen_mode_ == 0) {
                call_("generator.password", { { "length", m_gen_length_ }, { "uppercase", m_gen_upper_ },
                                                    { "numbers", m_gen_numbers_ }, { "symbols", m_gen_symbols_ } },
                        store);
            } else if (m_gen_mode_ == 1) {
                call_("generator.passphrase", { { "words", m_gen_words_ }, { "capitalize", true } }, store);
            } else {
                call_("generator.pin", { { "digits", m_gen_digits_ } }, store);
            }
        }
        if (!m_generated_.empty()) {
            int lines = std::max(1, m_gfx_.measure(m_generated_, Font::Title) / (c_content_w - 20) + 1);
            Rect r = m_ui_.next(lines * m_gfx_.lineHeight(Font::Title) + 20);
            m_gfx_.fill(r, colors::c_surface);
            m_gfx_.textWrapped(r.x + 10, r.y + 10, m_generated_, Font::Title, colors::c_text, r.w - 20);
        }
        m_ui_.endColumn();
    }

    void App::settings_() {
        header_("Settings", true);
        m_ui_.beginColumn("settings", { c_margin, c_content_y, c_content_w, c_content_h });
        static const int c_minutes[] = { 1, 5, 15, 30, 60, 240 };
        std::int64_t seconds = int_(m_settings_, "autoLockSeconds");
        int current = 1;
        for (int i = 0; i < 6; ++i) {
            if (seconds == c_minutes[i] * 60) {
                current = i;
            }
        }
        char label[64];
        std::snprintf(label, sizeof label, "Lock after %d minute%s without input", c_minutes[current],
                c_minutes[current] == 1 ? "" : "s");
        if (m_ui_.button(m_ui_.next(c_row_h), label)) {
            int next = (current + 1) % 6;
            m_settings_["autoLockSeconds"] = static_cast<std::int64_t>(c_minutes[next] * 60);
            call_("settings.set", { { "autoLockSeconds", c_minutes[next] * 60 } }, nullptr);
        }
        bool logout = str_(m_settings_, "timeoutAction") == "logout";
        if (m_ui_.button(m_ui_.next(c_row_h), logout ? "When the timer runs out: log out" : "When the timer runs out: lock")) {
            m_settings_["timeoutAction"] = logout ? "lock" : "logout";
            call_("settings.set", { { "timeoutAction", logout ? "lock" : "logout" } }, nullptr);
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Sync now")) {
            call_("vault.sync", Json::object(), [this](Reply& reply) {
                toast_(reply.m_ok && reply.m_result == true ? "Synced" : "Couldn't sync",
                        !(reply.m_ok && reply.m_result == true));
            }, true);
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Lock now")) {
            call_("auth.lock", Json::object(), [this](Reply&) { refreshState_(); });
        }
        if (m_ui_.button(m_ui_.next(c_row_h), "Log out", Style::Danger)) {
            m_confirm_text_ = "Log out? You'll need your email, master password and any two-step code to log in again.";
            m_confirm_action_ = [this]() {
                call_("auth.logout", Json::object(), [this](Reply&) { refreshState_(); }, true);
            };
        }
        Rect about = m_ui_.next(80);
        m_gfx_.textWrapped(about.x + 4, about.y + 6,
                "ClientWarden for the Wii. Your vault is encrypted on the SD card; the master password "
                "is needed every time you start it. " +
                        SecureString(networkReady() ? "Online." : "No network."),
                Font::Small, colors::c_subtext, about.w);
        m_ui_.endColumn();
    }
}
