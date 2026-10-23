#pragma once
#include <ctime>
#include <functional>
#include <set>
#include <vector>

#include "bridge_client.h"
#include "keyboard.h"
#include "ui.h"

/*
 * The ClientWarden Wii app: screens, the vault state they follow, and the data they show.
 * One screen at a time, full width (it's a TV); B goes back, HOME opens the menu.
 */
namespace clientwarden::wii::ui {
    /**
     * @brief Records that network start-up has finished (connected or not). The vault isn't
     * touched before then: libogc's network stack isn't safe to use while it's initialising.
     */
    void markNetworkSettled();
    bool networkSettled();

    enum class Screen {
        Entropy, Starting, Login, Code, Passkey, Unlock, Failed,
        Home, Items, Item, Edit, Sends, SendEdit, SendOpen, Generator, Settings
    };

    class App {
    public:
        explicit App(Gfx& gfx);

        /**
         * @brief Runs one frame: handles input, draws, presents.
         *
         * @return False once the user chose to exit
         */
        bool frame(Input input);

        Ui& ui() { return m_ui_; }
        Keyboard& keyboard() { return m_keyboard_; }
        Gfx& gfx() { return m_gfx_; }
        Screen screen() const { return m_screen_; }

        /**
         * @brief Gets every failed vault call (test builds log them).
         */
        void onError(std::function<void(std::string_view, std::string_view)> listener) {
            m_bridge_.m_on_error = std::move(listener);
        }

    private:
        // flow
        void refreshState_();
        void applyState_(std::string_view state, std::string_view failure);
        void go_(Screen screen);
        void back_();
        void forget_();
        void toast_(std::string_view message, bool error = true);
        void call_(std::string_view method, Json args, BridgeClient::Callback callback, bool blocking = false);
        void loginResult_(std::string_view result);

        // data
        void loadVault_();
        void loadItems_();
        void openItem_(SecureString id);
        void loadSends_();
        void startEdit_(bool existing, std::string_view type);
        void saveEdit_();

        // screens
        void header_(std::string_view title, bool back);
        void entropy_();
        void starting_();
        void login_();
        void code_();
        void passkey_();
        void unlock_();
        void failed_();
        void home_();
        void items_();
        void item_();
        void edit_();
        void sends_();
        void sendEdit_();
        void sendOpen_();
        void generator_();
        void settings_();

        // overlays
        void menu_();
        void confirm_();
        void typePicker_();
        void busy_();
        void toastBar_();

        /**
         * @brief A text field that opens the keyboard and writes the result back.
         */
        void editField_(Rect rect, std::string_view label, SecureString& value, bool masked);

        Gfx& m_gfx_;
        Ui m_ui_;
        Keyboard m_keyboard_;
        BridgeClient m_bridge_;
        Input m_input_;
        Screen m_screen_ = Screen::Entropy;
        std::vector<Screen> m_stack_;
        SecureString m_state_;
        SecureString m_failure_;
        int m_blocking_ = 0;
        bool m_exit_ = false;
        unsigned m_frame_ = 0;
        std::time_t m_last_activity_note_ = 0;

        // toast and modals
        SecureString m_toast_;
        bool m_toast_error_ = true;
        std::time_t m_toast_until_ = 0;
        bool m_menu_open_ = false;
        bool m_type_picker_open_ = false;
        SecureString m_confirm_text_;
        std::function<void()> m_confirm_action_;

        // login
        int m_server_ = 0;    // 0 bitwarden.com, 1 bitwarden.eu, 2 self-hosted
        SecureString m_base_url_;
        SecureString m_email_;
        SecureString m_password_;
        SecureString m_code_;
        bool m_code_is_device_ = false;

        // vault
        struct Filter {
            SecureString m_label;
            SecureString m_filter;
            SecureString m_value;
            int m_indent = 0;
            bool m_section = false;
        };
        std::vector<Filter> m_filters_;
        Filter m_filter_;
        Json m_schema_;
        Json m_folders_;
        Json m_organizations_;
        bool m_extended_types_ = false;
        SecureString m_profile_email_;
        SecureString m_search_;
        Json m_items_;
        bool m_items_loading_ = false;

        // item
        Json m_item_;
        std::set<SecureString> m_revealed_;
        bool m_show_history_ = false;
        Json m_totp_;
        bool m_totp_loading_ = false;

        // editor
        Json m_draft_;
        std::vector<std::pair<SecureString, SecureString>> m_draft_fields_;
        std::vector<std::pair<SecureString, bool>> m_draft_secret_;
        SecureString m_draft_name_;
        SecureString m_draft_notes_;
        SecureString m_draft_uri_;
        SecureString m_draft_totp_;
        SecureString m_draft_folder_;
        bool m_draft_favorite_ = false;
        SecureString m_draft_type_;
        SecureString m_draft_id_;

        // sends
        Json m_sends_;
        Json m_send_;
        SecureString m_send_name_;
        SecureString m_send_text_;
        SecureString m_send_password_;
        SecureString m_send_max_views_;
        bool m_send_hidden_ = false;
        bool m_send_disabled_ = false;
        SecureString m_open_link_;
        SecureString m_open_password_;
        Json m_received_;
        SecureString m_open_message_;
        bool m_received_revealed_ = false;

        // generator and settings
        int m_gen_mode_ = 0;    // 0 password, 1 passphrase, 2 PIN
        int m_gen_length_ = 20;
        int m_gen_words_ = 5;
        int m_gen_digits_ = 6;
        bool m_gen_upper_ = true;
        bool m_gen_numbers_ = true;
        bool m_gen_symbols_ = true;
        SecureString m_generated_;
        Json m_settings_;
    };
}
