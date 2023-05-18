//
// Created by gzhuadmin on 23-5-15.
//
#include "io/daily_logger.hpp"

std::shared_ptr<DailyLogger> DailyLogger::getInstance() {
    static std::weak_ptr<DailyLogger> instance;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    auto ptr = instance.lock();
    if (!ptr) {
        ptr.reset(new DailyLogger());
        instance = ptr;
    }
    return ptr;
}

void DailyLogger::info(const char *format, std::string args) {
    logger_->info(format, args);
}

void DailyLogger::debug(char const *format, const std::string& args) {
    logger_->debug<>(format, args);
}

void DailyLogger::error(const char *format, std::string args) {
    std::cout << "\033[31m==============================================\n";
    std::cout << "An error has occurred, please check log files.\n";
    std::cout << "==============================================\033[0m \n";
    logger_->error(format, args);
}

void DailyLogger::warn(const char *format, std::string args) {
    logger_->warn(format, args);
}

DailyLogger::DailyLogger() {
    spdlog::set_pattern("[%D %T] [%^%L%$] %v");

    auto info_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/info/log.txt", 0, 0);
    auto debug_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/debug/log.txt", 0, 0);
    auto error_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/error/log.txt", 0, 0);
    auto warn_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/warn/log.txt", 0, 0);
    info_sink->set_level(spdlog::level::info);
    debug_sink->set_level(spdlog::level::debug);
    error_sink->set_level(spdlog::level::err);
    warn_sink->set_level(spdlog::level::warn);

    std::vector<spdlog::sink_ptr> sinks{info_sink, debug_sink, error_sink, warn_sink};
    logger_ = std::make_shared<spdlog::logger>("logger", begin(sinks), end(sinks));
    logger_->flush_on(spdlog::level::warn);
    logger_->set_level(spdlog::level::debug);
}
