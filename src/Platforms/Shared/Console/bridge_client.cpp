#include "bridge_client.h"

#include "JsonBridge/JsonBridge.h"

namespace clientwarden::console::ui {
    BridgeClient::BridgeClient() {
        bridge::JsonBridge::shared().onEvent([this](SecureString event) {
            std::lock_guard<std::mutex> lock(m_mutex_);
            m_events_.push_back(std::move(event));
        });
        m_worker_ = std::jthread([this](std::stop_token stop) { run_(stop); });
    }

    BridgeClient::~BridgeClient() {
        bridge::JsonBridge::shared().onEvent(nullptr);
        m_worker_.request_stop();
        m_wake_.notify_all();
    }

    void BridgeClient::call(std::string_view method, Json args, Callback callback) {
        {
            std::lock_guard<std::mutex> lock(m_mutex_);
            m_pending_.push_back({ SecureString(method), args.is_null() ? SecureString("{}") : args.dump(),
                std::move(callback), Reply() });
        }
        m_wake_.notify_one();
    }

    bool BridgeClient::busy() {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_running_ > 0 || !m_pending_.empty();
    }

    void BridgeClient::run_(std::stop_token stop) {
        while (!stop.stop_requested()) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(m_mutex_);
                if (!m_wake_.wait(lock, stop, [this]() { return !m_pending_.empty(); })) {
                    return;
                }
                job = std::move(m_pending_.front());
                m_pending_.pop_front();
                m_running_++;
            }

            SecureString response = bridge::JsonBridge::shared().call(job.m_method, job.m_args);
            Json parsed = Json::parse(response.begin(), response.end(), nullptr, false);
            if (parsed.is_object() && at(parsed, "ok") == true) {
                job.m_reply.m_ok = true;
                job.m_reply.m_result = at(parsed, "result");
            } else {
                job.m_reply.m_error = parsed.is_object() ? stringAt(parsed, "error") : SecureString("bad response");
                if (job.m_reply.m_error.empty()) {
                    job.m_reply.m_error = "Something went wrong";
                }
            }

            std::lock_guard<std::mutex> lock(m_mutex_);
            m_running_--;
            m_done_.push_back(std::move(job));
        }
    }

    void BridgeClient::poll(const std::function<void(const Json&)>& on_event) {
        std::deque<Job> done;
        std::deque<SecureString> events;
        {
            std::lock_guard<std::mutex> lock(m_mutex_);
            done.swap(m_done_);
            events.swap(m_events_);
        }
        for (Job& job : done) {
            if (!job.m_reply.m_ok && m_on_error) {
                m_on_error(job.m_method, job.m_reply.m_error);
            }
            if (job.m_callback) {
                job.m_callback(job.m_reply);
            }
        }
        for (SecureString& event : events) {
            Json parsed = Json::parse(event.begin(), event.end(), nullptr, false);
            if (parsed.is_object()) {
                on_event(parsed);
            }
        }
    }
}
