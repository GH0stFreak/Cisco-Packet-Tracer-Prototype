#pragma once

#include <condition_variable>
#include <mutex>

extern std::condition_variable cv;
extern std::mutex cv_m;
extern bool paused;

std::condition_variable cv;
std::mutex cv_m;
bool paused = false;