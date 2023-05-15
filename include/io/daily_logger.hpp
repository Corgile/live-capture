//
// Created by gzhuadmin on 23-5-15.
//

#ifndef LIVE_CAPTURE_DAILY_LOGGER_HPP
#define LIVE_CAPTURE_DAILY_LOGGER_HPP


#include <memory>
#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>

class DailyLogger {
public:
    static std::shared_ptr<DailyLogger> getInstance();

    void info(const char *format, std::string args);

    void debug(const char* fmt, const std::string & args);

    void error(const char *format, std::string args);

    void warn(const char *format, std::string args);


private:
    DailyLogger();

    std::shared_ptr<spdlog::logger> logger_;

    static std::shared_ptr<DailyLogger> instance;

};


#endif //LIVE_CAPTURE_DAILY_LOGGER_HPP
