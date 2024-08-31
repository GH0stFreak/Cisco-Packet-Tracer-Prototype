#pragma once
#include "common.h"

class StringCaptureSink : public spdlog::sinks::base_sink<std::mutex> {
public:
	std::string captured_log;

protected:
	void sink_it_(const spdlog::details::log_msg& msg) override {
		// Format the message using the existing formatter
		spdlog::memory_buf_t formatted;
		formatter_->format(msg, formatted);

		// Store the formatted message in captured_log
		captured_log = fmt::to_string(formatted);
	}

	void flush_() override {
		// No-op
	}
};

// Loggable class definition
class Loggable {
public:
	Loggable(const Loggable& other) {
		logger = other.logger;
		captureSink = std::make_shared<StringCaptureSink>();
		logger->sinks().push_back(captureSink);
	}

	Loggable(std::string_view sv) {
		consoleSink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
		captureSink = std::make_shared<StringCaptureSink>();

		logger = std::make_shared<spdlog::logger>(sv.data());
		logger->sinks().push_back(consoleSink);
		logger->sinks().push_back(captureSink);
		logger->set_pattern("[%T] [%=16n] [%^%l%$] %v");
	}

	Loggable(std::shared_ptr<spdlog::logger> logger) {
		this->logger = logger;
		captureSink = std::make_shared<StringCaptureSink>();
		logger->sinks().push_back(consoleSink);
		logger->sinks().push_back(captureSink);
	}

	std::string get_captured_log() const {
		return captureSink ? captureSink->captured_log : "";
	}

	std::shared_ptr<spdlog::logger> logger;

protected:
	static std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> consoleSink;
	std::shared_ptr<StringCaptureSink> captureSink;
};
