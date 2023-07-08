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
    /**
    * @brief 一个日志记录器，会根据日志的等级（debug,info,warn,error,fatal）
    * 创建独立的日志文件，并且每天的日志会自动放在不同的目录
    * @return
    */
    static std::shared_ptr<DailyLogger> getInstance();

    /**
    * @brief 日志的info等级，下同
    * @param format 日志每一行(字符串)的格式
    * @param args 要写进日志的其他参数值
    */
    void info(const char *format, std::string args);

    void debug(const char *fmt, const std::string &args);

    void error(const char *format, std::string args);

    void warn(const char *format, std::string args);


private:
    /**
    * @brief 日志记录器的构造函数
    */
    DailyLogger();

    /**
    * @brief 日志记录器的核心
    */
    std::shared_ptr<spdlog::logger> logger_;

    /**
    * @brief 采用的是单例模式，保证全局使用的日志记录器都是同一个，
    * 这样可以保证再写入文件的时候只有一个实例进行文件操作
    */
    static std::shared_ptr<DailyLogger> instance;

};


#endif //LIVE_CAPTURE_DAILY_LOGGER_HPP
