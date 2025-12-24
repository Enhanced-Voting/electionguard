#ifndef __ELECTIONGUARD_CPP_LOG_H_INCLUDED__
#define __ELECTIONGUARD_CPP_LOG_H_INCLUDED__

#include "export.h"
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Log level enumeration matching spdlog levels
 */
typedef enum eg_log_level_e {
    EG_LOG_LEVEL_TRACE = 0,
    EG_LOG_LEVEL_DEBUG = 1,
    EG_LOG_LEVEL_INFO = 2,
    EG_LOG_LEVEL_WARN = 3,
    EG_LOG_LEVEL_ERROR = 4,
    EG_LOG_LEVEL_CRITICAL = 5,
    EG_LOG_LEVEL_OFF = 6
} eg_log_level_t;

/**
 * @brief Callback function type for receiving log messages
 * @param level The log level (eg_log_level_t)
 * @param message The formatted log message (null-terminated C string)
 */
typedef void (*eg_log_callback_t)(int level, const char *message);

/**
 * @brief Register a callback function to receive log messages from the native library
 * 
 * This allows C# or other languages to receive log messages via P/Invoke.
 * The callback will be invoked on the same thread that generates the log message,
 * so it should be thread-safe and return quickly.
 * 
 * @param callback Function pointer to receive log messages, or NULL to disable
 * @return ELECTIONGUARD_STATUS_SUCCESS if successful
 */
EG_API eg_electionguard_status_t eg_log_set_callback(eg_log_callback_t callback);

/**
 * @brief Set the minimum log level
 * 
 * Only messages at or above this level will be logged.
 * 
 * @param level The minimum log level (0=trace, 1=debug, 2=info, 3=warn, 4=error, 5=critical, 6=off)
 * @return ELECTIONGUARD_STATUS_SUCCESS if successful
 */
EG_API eg_electionguard_status_t eg_log_set_level(eg_log_level_t level);

/**
 * @brief Configure logging to also write to a file
 * 
 * This adds a file sink in addition to any existing sinks (console, callback, etc.)
 * 
 * @param filepath Path to the log file (null-terminated C string)
 * @return ELECTIONGUARD_STATUS_SUCCESS if successful, error code otherwise
 */
EG_API eg_electionguard_status_t eg_log_set_file(const char *filepath);

/**
 * @brief Clear the callback (same as calling eg_log_set_callback(NULL))
 * 
 * @return ELECTIONGUARD_STATUS_SUCCESS if successful
 */
EG_API eg_electionguard_status_t eg_log_clear_callback(void);

/**
 * @brief Get the current log level
 * 
 * @param out_level Pointer to receive the current log level
 * @return ELECTIONGUARD_STATUS_SUCCESS if successful
 */
EG_API eg_electionguard_status_t eg_log_get_level(eg_log_level_t *out_level);

#ifdef __cplusplus
}
#endif

#endif /* __ELECTIONGUARD_CPP_LOG_H_INCLUDED__ */
