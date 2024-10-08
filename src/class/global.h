#pragma once
#ifndef GLOBAL_H
#define GLOBAL_H

//#include "common.h"
#include <windows.h>
#include <vector>

#define ENTER_COMMAND 2

class Client;
class Switch;
class Router;
class Dhcp;

// Register the window class.
WNDCLASS mainWindowClass = { };
WNDCLASS clientWindowClass = { };
WNDCLASS switchWindowClass = { };
WNDCLASS routerWindowClass = { };
WNDCLASS dhcpWindowClass = { };

std::vector<Client*> allClients = {};
std::vector<Router*> allRouter = {};
std::vector<Dhcp*> allDhcp = {};
std::vector<Switch*> allSwitches = {};

const wchar_t MAIN_CLASS_NAME[] = L"Main Class";
const wchar_t CLIENT_CLASS_NAME[] = L"Client Class";
const wchar_t SWITCH_CLASS_NAME[] = L"Switch Class";
const wchar_t ROUTER_CLASS_NAME[] = L"Router Class";
const wchar_t DHCP_CLASS_NAME[] = L"Dhcp Class";

#endif