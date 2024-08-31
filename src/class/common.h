#pragma once
#include <algorithm>
#include <atomic>
#include <bitset>
#include <cctype>
#include <chrono>
#include <codecvt>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <future>
#include <iomanip>
#include <ios>
#include <iostream>
#include <iterator>
#include <list>
#include <locale>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <semaphore>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>
#include <wchar.h>

#ifndef UNICODE
#define UNICODE
#endif 

#include <cstdio>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winuser.h>

#include <fmt\format.h>
#include <spdlog\spdlog.h>
#include <spdlog\sinks\base_sink.h>
#include <spdlog\pattern_formatter.h>
#include <spdlog\sinks\stdout_color_sinks.h>

int is_little_endian() {
    unsigned int i = 1;
    char* c = (char*)&i;
    return *c;
}


#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
    #define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define IS_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#else
    #define IS_LITTLE_ENDIAN (is_little_endian() != 0)
    #define IS_BIG_ENDIAN (!IS_LITTLE_ENDIAN)
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Target Windows 10
#elif _WIN32_WINNT < 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Ensure it targets at least Windows 10
#endif



