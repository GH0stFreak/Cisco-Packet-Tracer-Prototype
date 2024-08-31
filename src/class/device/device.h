#pragma once

class Device {
public:
	virtual ~Device() = default; // Ensure a virtual destructor for proper cleanup
	virtual void ShowWindow() = 0; // Pure virtual function to be overridden
};


