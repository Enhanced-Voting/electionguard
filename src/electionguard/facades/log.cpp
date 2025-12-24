#include "electionguard/log.h"

#include "log.hpp"
#include "spdlog/sinks/base_sink.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"

#include <memory>
#include <mutex>

using std::make_shared;
using std::mutex;
using std::shared_ptr;

namespace electionguard
{
    /**
     * @brief Custom spdlog sink that forwards log messages to a C callback function
     * 
     * This sink is thread-safe and can be used alongside other sinks.
     */
    template <typename Mutex> class callback_sink : public spdlog::sinks::base_sink<Mutex>
    {
      public:
        explicit callback_sink(eg_log_callback_t callback) : callback_(callback) {}

        void set_callback(eg_log_callback_t callback) { callback_ = callback; }

      protected:
        void sink_it_(const spdlog::details::log_msg &msg) override
        {
            if (callback_ == nullptr) {
                return;
            }

            // Format the message using the sink's formatter
            spdlog::memory_buf_t formatted;
            spdlog::sinks::base_sink<Mutex>::formatter_->format(msg, formatted);

            // Convert to null-terminated string
            std::string message(formatted.data(), formatted.size());

            // Call the C# callback with the log level and message
            int level = static_cast<int>(msg.level);
            callback_(level, message.c_str());
        }

        void flush_() override
        {
            // Nothing to flush for callback sink
        }

      private:
        eg_log_callback_t callback_;
    };

    using callback_sink_mt = callback_sink<std::mutex>;
    using callback_sink_st = callback_sink<spdlog::details::null_mutex>;

    /**
     * @brief Manages the callback sink instance
     */
    class CallbackSinkManager
    {
      private:
        CallbackSinkManager() : callback_sink_(nullptr) {}

      public:
        static CallbackSinkManager &instance()
        {
            static CallbackSinkManager _instance;
            return _instance;
        }

        shared_ptr<callback_sink_mt> get_or_create()
        {
            if (callback_sink_ == nullptr) {
                callback_sink_ = make_shared<callback_sink_mt>(nullptr);
                callback_sink_->set_pattern("[%H:%M:%S:%e %z] [p: %P] [t: %t] [%l] :: %v");
            }
            return callback_sink_;
        }

        void set_callback(eg_log_callback_t callback)
        {
            auto sink = get_or_create();
            sink->set_callback(callback);

            // Add to logger if not already added
            auto logger = spdlog::default_logger();
            if (logger) {
                // Check if this sink is already in the logger
                bool found = false;
                for (const auto &existing_sink : logger->sinks()) {
                    if (existing_sink == sink) {
                        found = true;
                        break;
                    }
                }

                // Add the sink if it's not already there
                if (!found) {
                    logger->sinks().push_back(sink);
                }
            }
        }

        void clear_callback()
        {
            if (callback_sink_) {
                callback_sink_->set_callback(nullptr);

                // Optionally remove from logger
                auto logger = spdlog::default_logger();
                if (logger) {
                    auto &sinks = logger->sinks();
                    sinks.erase(std::remove(sinks.begin(), sinks.end(), callback_sink_),
                                sinks.end());
                }
            }
        }

      private:
        shared_ptr<callback_sink_mt> callback_sink_;
    };

} // namespace electionguard

extern "C" {

using namespace electionguard;

EG_API eg_electionguard_status_t eg_log_set_callback(eg_log_callback_t callback)
{
    try {
        if (callback == nullptr) {
            CallbackSinkManager::instance().clear_callback();
        } else {
            CallbackSinkManager::instance().set_callback(callback);
        }
        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error("eg_log_set_callback", e);
        return ELECTIONGUARD_STATUS_ERROR_RUNTIME_ERROR;
    }
}

EG_API eg_electionguard_status_t eg_log_set_level(eg_log_level_t level)
{
    try {
        auto logger = spdlog::default_logger();
        if (logger == nullptr) {
            return ELECTIONGUARD_STATUS_ERROR_BAD_ACCESS;
        }

        // Map eg_log_level_t to spdlog::level::level_enum
        spdlog::level::level_enum spdlog_level;
        switch (level) {
            case EG_LOG_LEVEL_TRACE:
                spdlog_level = spdlog::level::trace;
                break;
            case EG_LOG_LEVEL_DEBUG:
                spdlog_level = spdlog::level::debug;
                break;
            case EG_LOG_LEVEL_INFO:
                spdlog_level = spdlog::level::info;
                break;
            case EG_LOG_LEVEL_WARN:
                spdlog_level = spdlog::level::warn;
                break;
            case EG_LOG_LEVEL_ERROR:
                spdlog_level = spdlog::level::err;
                break;
            case EG_LOG_LEVEL_CRITICAL:
                spdlog_level = spdlog::level::critical;
                break;
            case EG_LOG_LEVEL_OFF:
                spdlog_level = spdlog::level::off;
                break;
            default:
                return ELECTIONGUARD_STATUS_ERROR_INVALID_ARGUMENT;
        }

        logger->set_level(spdlog_level);
        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error("eg_log_set_level", e);
        return ELECTIONGUARD_STATUS_ERROR_RUNTIME_ERROR;
    }
}

EG_API eg_electionguard_status_t eg_log_set_file(const char *filepath)
{
    try {
        if (filepath == nullptr) {
            return ELECTIONGUARD_STATUS_ERROR_INVALID_ARGUMENT;
        }

        auto logger = spdlog::default_logger();
        if (logger == nullptr) {
            return ELECTIONGUARD_STATUS_ERROR_BAD_ACCESS;
        }

        // Create a file sink with the same pattern as other sinks
        auto file_sink = make_shared<spdlog::sinks::basic_file_sink_mt>(filepath, true);
        file_sink->set_pattern("[%H:%M:%S:%e %z] [p: %P] [t: %t] [%l] :: %v");

        // Add the file sink to the logger
        logger->sinks().push_back(file_sink);

        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error("eg_log_set_file", e);
        return ELECTIONGUARD_STATUS_ERROR_IO_ERROR;
    }
}

EG_API eg_electionguard_status_t eg_log_clear_callback(void)
{
    return eg_log_set_callback(nullptr);
}

EG_API eg_electionguard_status_t eg_log_get_level(eg_log_level_t *out_level)
{
    try {
        if (out_level == nullptr) {
            return ELECTIONGUARD_STATUS_ERROR_INVALID_ARGUMENT;
        }

        auto logger = spdlog::default_logger();
        if (logger == nullptr) {
            return ELECTIONGUARD_STATUS_ERROR_BAD_ACCESS;
        }

        // Map spdlog::level::level_enum to eg_log_level_t
        spdlog::level::level_enum level = logger->level();
        switch (level) {
            case spdlog::level::trace:
                *out_level = EG_LOG_LEVEL_TRACE;
                break;
            case spdlog::level::debug:
                *out_level = EG_LOG_LEVEL_DEBUG;
                break;
            case spdlog::level::info:
                *out_level = EG_LOG_LEVEL_INFO;
                break;
            case spdlog::level::warn:
                *out_level = EG_LOG_LEVEL_WARN;
                break;
            case spdlog::level::err:
                *out_level = EG_LOG_LEVEL_ERROR;
                break;
            case spdlog::level::critical:
                *out_level = EG_LOG_LEVEL_CRITICAL;
                break;
            case spdlog::level::off:
                *out_level = EG_LOG_LEVEL_OFF;
                break;
            default:
                *out_level = EG_LOG_LEVEL_INFO;
                break;
        }

        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error("eg_log_get_level", e);
        return ELECTIONGUARD_STATUS_ERROR_RUNTIME_ERROR;
    }
}

} // extern "C"
