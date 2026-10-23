#pragma once
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#include "utils/secure_string/secure_string.h"

/*
 * Runs vault calls on a worker thread (they reach the network or derive keys, which takes
 * seconds on the Wii) and hands results back to the UI thread, which collects them with
 * poll() once a frame. Events the vault raises by itself are queued the same way.
 */
namespace clientwarden::console::ui {
    struct Reply {
        bool m_ok = false;
        Json m_result;
        SecureString m_error;
    };

    class BridgeClient {
    public:
        using Callback = std::function<void(Reply&)>;

        BridgeClient();
        ~BridgeClient();

        /**
         * @brief Queues a call; the callback runs on the UI thread during poll().
         */
        void call(std::string_view method, Json args, Callback callback = nullptr);

        /**
         * @brief Runs finished calls' callbacks.
         *
         * @param on_event Gets each vault event ({"event":"state",...})
         */
        void poll(const std::function<void(const Json&)>& on_event);

        /**
         * @brief Whether a call is queued or running.
         */
        bool busy();

        /**
         * @brief Called with every failed call's method and error (test builds log these).
         */
        std::function<void(std::string_view, std::string_view)> m_on_error;

    private:
        struct Job {
            SecureString m_method;
            SecureString m_args;
            Callback m_callback;
            Reply m_reply;
        };

        void run_(std::stop_token stop);

        std::mutex m_mutex_;
        std::condition_variable_any m_wake_;
        std::deque<Job> m_pending_;
        std::deque<Job> m_done_;
        std::deque<SecureString> m_events_;
        int m_running_ = 0;
        std::jthread m_worker_;
    };
}
