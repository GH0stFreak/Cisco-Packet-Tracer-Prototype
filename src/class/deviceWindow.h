#pragma once
#ifndef DEVICEWINDOW_H
#define DEVICEWINDOW_H

#include "common.h"
#include "helper.h"
#include "utils.h"
#include "global.h"


inline std::string ConvertWideCharToString(const wchar_t* wstr)
{
    // Get the required buffer size for the conversion
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, NULL, NULL);

    // Allocate a string of the appropriate size
    std::string str(bufferSize, 0);

    // Perform the conversion
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], bufferSize, NULL, NULL);

    // Remove the null-terminator at the end
    str.resize(bufferSize - 1);

    return str;
}

class DeviceWindowBase {
public:
    virtual ~DeviceWindowBase() = default;
    virtual void showWindow() = 0;
    virtual void handleButtonPress() = 0;
    virtual void addData(const std::string& newData) = 0;
};

template <class Device>
class DeviceWindow : public DeviceWindowBase {
public: 
    int val;
    HWND wnd;
    HWND hEdit;
    HWND hBtn;
    HWND hConsole;
    Device* user_;
    std::mutex windowMutex;

    DeviceWindow(Device* user, int v, WNDCLASS& wc, const wchar_t className[]) : val(v), user_(user) {

        // Converting string hostname into wchar_t
        const char* hostname = (user->hostname).c_str();

        size_t size = strlen(hostname) + 1;

        wchar_t* wcstring = new wchar_t[size];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, wcstring, size, hostname, _TRUNCATE);

        wchar_t temp[100];
        swprintf_s(temp, L"%s", wcstring);


        wnd = CreateWindowEx(
            0,                                  // Optional window styles.
            className,                          // Window class
            temp,                          // Window text
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,         // Window style

            // Size and position
            CW_USEDEFAULT, CW_USEDEFAULT, 500, 700,

            NULL,               // Parent window    
            NULL,               // Menu
            wc.hInstance,       // Instance handle
            NULL                // Additional application data
        );

        delete[] wcstring;
        //ShowWindow(wnd, SW_SHOWDEFAULT);


        CreateWindow(L"Static", L"Enter Command: ", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, 10, 10, 70, 40, wnd, NULL, NULL, NULL);
        hEdit = CreateWindow(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL, 85, 10, 330, 40, wnd, NULL, NULL, NULL);

        hBtn = CreateWindow(L"Button", L"Send", WS_VISIBLE | WS_CHILD | WS_BORDER, 420, 10, 60, 40, wnd, (HMENU)ENTER_COMMAND, NULL, NULL);
        SetWindowLongPtr(hBtn, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(static_cast<DeviceWindowBase*>(this)));

        hConsole = CreateWindow(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL, 10, 60, 470, 590, wnd, NULL, NULL, NULL);
    
    }

    void handleButtonPress() override {
        // Get the text from hEdit
        wchar_t editText[1024];
        GetWindowText(hEdit, editText, sizeof(editText) / sizeof(editText[0]));
        //GetWindowTextA(hEdit, text, sizeof(text) / sizeof(text[0]))

        std::string command = ConvertWideCharToString(editText);

        std::vector<std::string> splitCommand = splitString(command);

        if (splitCommand.size() == 0) {
            spdlog::warn("Enter a valid Command");
        }
        else {
            Instruction perform = checkCommandWindow(splitCommand);

            switch (perform) {
            case IPCONFIG: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    spdlog::warn("Incorrect command");
                }
                else {
                    if (splitCommand.size() == 1) {
                        user_->IpConfig();
                    }
                    else {
                        spdlog::warn("Incorrect command");
                    }
                }
                break;
            }
            case IPRELEASE: {
                if constexpr (std::is_same<Device, Switch>::value || std::is_same<Device, Router>::value) {
                    spdlog::warn("Incorrect command");
                }
                else {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->iface.setIPV4(0);
                        user_->iface.setSUBNET_MASK(0);
                        user_->iface.setGATEWAY(0);
                    }
                }
                break;
            }
            case IPRENEW: {
                if constexpr (std::is_same<Device, Client>::value) {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->sendDHCPDiscover();
                    }
                }
                else {
                    spdlog::warn("Incorrect command");
                }
                break;
            }
            case PING: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    spdlog::warn("Incorrect command");
                }
                else if constexpr (std::is_same<Device, Router>::value) {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        //spdlog::warn("Ip {} Incorrect", splitCommand[2]);

                        user_->ifaces[0].sendICMPEchoRequest(ip);
                    }
                }
                else {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        //spdlog::warn("Ip {} Incorrect", splitCommand[2]);

                        user_->sendICMPEchoRequest(ip);
                    }
                }
                break;
            }
            case ARP: {
                if constexpr (std::is_same<Device, Client>::value) {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        user_->sendARPRequest(ip);
                    }
                }
                else {
                    spdlog::warn("Incorrect command");
                }
                break;
            }
            case HOSTNAME: {
                if(splitCommand.size()>2) {
                    spdlog::warn("Incorrect command");
                }
                else {
                    user_->setHostname(splitCommand[1]);
                    std::wstring wNewData(splitCommand[1].begin(), splitCommand[1].end());
                    SetWindowText(wnd, wNewData.c_str());
                }
                break;
            }
            case SHOW_ROUTE_TABLE: {
                if constexpr (std::is_same<Device, Router>::value) {
                    user_->routing_table->DisplayTree();
                }
                else {
                    spdlog::warn("Incorrect command");
                }
                break;
            }
            case SHOW_ARP_TABLE: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    spdlog::warn("Incorrect command");
                }
                else if constexpr (std::is_same<Device, Router>::value) {
                    user_->arp_table->display();
                }
                else {
                    user_->arp_table.display();
                }
                break;
            }
            case SHOW_MAC_TABLE: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    if (splitCommand.size() > 3) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->shared_mac_table->display();
                    }
                }
                else {
                    spdlog::warn("Incorrect command");
                }
                break;
            }
            case SHOW_STP: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    user_->logger->info("Root Bridge: {}", user_->root_bridge);
                    user_->printIfaceStateStatus();
                }
                else {
                    spdlog::warn("Incorrect command");
                }
                break;
            }
            case BUFFER_COUNT: {
                if constexpr (std::is_same<Device, Router>::value) {
                    spdlog::warn("Incorrect command");
                }
                else {
                    user_->ShowPacketCount();
                }
                break;
            }
            case SET_HELLO_TIMER:{
                if constexpr (std::is_same<Device, Switch>::value) {
                    if (splitCommand.size() > 5) {
                        spdlog::warn("Incorrect command");
                        break;
                    }
                    uint16_t hello_time = stringToUint16(splitCommand[4], 2);
                    user_->setHelloTimer(hello_time);
                }
                else {
                    spdlog::warn("Incorrect command");
                    break;
                }
                break;
            }
            case SET_FORWARD_DELAY: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    if (splitCommand.size() > 5) {
                        spdlog::warn("Incorrect command");
                        break;
                    }
                    uint16_t forward_delay = stringToUint16(splitCommand[4], 15);
                    user_->setForwardDelay(forward_delay);
                }
                else {
                    spdlog::warn("Incorrect command");
                    break;
                }
                break;
            }
            case SET_MAX_AGE: {
                if constexpr (std::is_same<Device, Switch>::value) {
                    if (splitCommand.size() > 5) {
                        spdlog::warn("Incorrect command");
                        break;
                    }
                    uint16_t max_age = stringToUint16(splitCommand[4], 20);
                    user_->setMaxAge(max_age);
                }
                else {
                    spdlog::warn("Incorrect command");
                    break;
                }
                break;
            }
            case INSTRUCTION_ERROR:
                spdlog::warn("Command {} Incorrect", splitCommand[0]);
                break;
            default:
                spdlog::warn("Command {} Incorrect", splitCommand[0]);
                break;
            }

            /*
            if (std::is_same<Device, Client>::value) {
                switch (perform) {
                case IPCONFIG:
                    if (splitCommand.size() == 1) {
                        user_->IpConfig();
                    }
                    else {
                        spdlog::warn("Incorrect command");
                    }
                    break;
                case IPRELEASE:
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->iface.setIPV4(0);
                        user_->iface.setSUBNET_MASK(0);
                        user_->iface.setGATEWAY(0);
                    }
                    break;
                case IPRENEW: {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->sendDHCPDiscover();
                    }
                    break;
                }
                case PING: {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        //spdlog::warn("Ip {} Incorrect", splitCommand[2]);

                        user_->sendICMPEchoRequest(ip);
                    }
                    break;
                }
                case ARP: {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        user_->sendARPRequest(ip);
                    }
                    break;
                }
                case SHOW_ARP_TABLE: {
                    user_->arp_table.display();
                    break;
                }
                case BUFFER_COUNT: {

                    user_->ShowPacketCount();
                    break;
                }
                case INSTRUCTION_ERROR:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                default:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                }
            }
            else if (std::is_same<Device, Switch>::value) {
                switch (perform) {

                case SHOW_MAC_TABLE: {
                    if (splitCommand.size() > 3) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        user_->shared_mac_table->display();
                    }
                    break;
                }
                case BUFFER_COUNT: {

                    user_->ShowPacketCount();
                    break;
                }
                case SHOW_STP:

                    user_->logger->info("Root Bridge: {}",user_->root_bridge);
                    user_->printIfaceStateStatus();
                    break;
                case INSTRUCTION_ERROR:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                default:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                }
            }
            else if (std::is_same<Device, Router>::value) {
                switch (perform)
                {
                case IPCONFIG:
                {
                    if (splitCommand.size() == 1) {
                        user_->IpConfig();
                    }
                    else {
                        spdlog::warn("Incorrect command");
                    }
                    break;
                }
                case IPRELEASE:
                    spdlog::warn("Router Ip can't be released");
                    break;
                case IPRENEW:
                    spdlog::warn("Router Ip can't be renewed as static Ip");
                    break;
                case PING: {
                    uint32_t ip = ipToUint32(splitCommand[1]);
                    user_->ifaces[0].sendICMPEchoRequest(ip);
                    break;
                }
                case SHOW_ROUTE_TABLE: {
                    user_->routing_table->DisplayTree();
                    break;
                }
                case SHOW_ARP_TABLE: {
                    user_->arp_table->display();
                    break;
                }
                case INSTRUCTION_ERROR:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                default:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                }

            }
            else if (std::is_same<Device, Dhcp>::value) {
                switch (perform) {
                case IPCONFIG:
                {
                    if (splitCommand.size() == 1) {
                        user_->IpConfig();
                    }
                    else {
                        spdlog::warn("Incorrect command");
                    }
                    break;
                }
                case IPRELEASE:
                    spdlog::warn("Router Ip can't be released");
                    break;
                case IPRENEW:
                    spdlog::warn("Router Ip can't be renewed as static Ip");
                    break;
                case PING: {
                    if (splitCommand.size() > 2) {
                        spdlog::warn("Incorrect command");
                    }
                    else {
                        uint32_t ip = ipToUint32(splitCommand[1]);
                        user_->sendICMPEchoRequest(ip);
                    }
                    break;
                }
                case SHOW_ARP_TABLE: {
                    user_->arp_table.display();
                    break;
                }
                case BUFFER_COUNT: {

                    user_->ShowPacketCount();
                    break;
                }
                case INSTRUCTION_ERROR:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                default:
                    spdlog::warn("Command {} Incorrect", splitCommand[0]);
                    break;
                }
            }
            else {
                spdlog::info("Incorrect device in command!!");
            }*/
        }
    }

    void addData(const std::string& newData) override {
        std::lock_guard<std::mutex> lock(windowMutex);

        // Convert newData to wide string
        std::wstring wNewData(newData.begin(), newData.end());
        // Set the selection to the end of the text
        SendMessage(hConsole, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
        // Append new data
        SendMessage(hConsole, EM_REPLACESEL, FALSE, (LPARAM)wNewData.c_str());
        // Scoll to the bottom
        SendMessage(hConsole, EM_LINESCROLL, 0, (LPARAM)1);

        //InvalidateRect(hConsole, NULL, TRUE);
        //UpdateWindow(hConsole);
    }

    void showWindow() override {
        ::ShowWindow(wnd, SW_SHOW);
    }
};

template<class T>
void createControls(HWND hwnd,std::vector<T*> &pointerArray,int&x,int &y) {

    for (int i = 0; i < pointerArray.size(); ++i) {
        std::shared_ptr<DeviceWindow<T>> wnd = pointerArray[i]->wndClass;

        // Converting string hostname into wchar_t
        const char* hostname = (pointerArray[i]->hostname).c_str();

        size_t size = strlen(hostname) + 1;

        wchar_t* wcstring = new wchar_t[size];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, wcstring, size, hostname, _TRUNCATE);

        wchar_t temp[100];
        swprintf_s(temp, L"%s", wcstring);

        CreateWindow(L"Static", temp, WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 130, 20, hwnd, NULL, NULL, NULL);
        delete[] wcstring;


        std::shared_ptr<DeviceWindowBase> baseWnd = wnd;
        DeviceWindowBase* rawBaseWnd = baseWnd.get(); // Get the raw pointer

        // Create a button for each device and store a pointer to the device window in the button's userdata
        HWND hButton = CreateWindow(L"Button", L"Show", WS_VISIBLE | WS_CHILD | WS_BORDER, (x + 150), y, 130, 20, hwnd, (HMENU)wnd->val, NULL, NULL);
        SetWindowLongPtr(hButton, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(rawBaseWnd));

        y += 30;
    }
}

inline void addControls(HWND hwnd) {
    int x = 10;
    int y = 40;

    //HWND desc = CreateWindow(L"Static", L"Clients", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);
    CreateWindow(L"Static", L"Clients", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);

    CreateWindow(L"Static", L"Clients", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);
    y += 50;
    createControls(hwnd, allClients, x, y);
    y = 40;
    x += 340;
    CreateWindow(L"Static", L"Switches", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);
    y += 50;
    createControls(hwnd, allSwitches, x, y);
    y = 40;
    x += 340;
    CreateWindow(L"Static", L"Routers", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);
    y += 50;
    createControls(hwnd, allRouter, x, y);
    y = 40;
    x += 340;
    CreateWindow(L"Static", L"Servers", WS_VISIBLE | WS_CHILD | WS_BORDER | SS_CENTER, x, y, 280, 40, hwnd, NULL, NULL, NULL);
    y += 50;
    createControls(hwnd, allDhcp, x, y);

}

template<class T>
void removeWindow(HWND hwnd, std::vector<T*>& pointerArray) {

    for (int i = 0; i < pointerArray.size(); ++i) {
        std::shared_ptr<DeviceWindow<T>> wndPtr = pointerArray[i]->wndClass;
        SendMessage(wndPtr->wnd, WM_CLOSE, 0, 0);
    }
}

LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        removeWindow(hwnd, allClients);
        removeWindow(hwnd, allSwitches);
        removeWindow(hwnd, allRouter);
        removeWindow(hwnd,allDhcp);
        PostQuitMessage(0);
        return 0;
        
    case WM_COMMAND: {
        // Check if the message is from a button
        if (HIWORD(wParam) == BN_CLICKED) {
            // lParam contains the handle of the control that sent the message
            HWND hButton = (HWND)lParam;

            //if (auto currentWindow = dynamic_cast<DeviceWindow<Client>*>(GetWindowLongPtr(hButton, GWLP_USERDATA)) {
            //    if (currentWindow && currentWindow->wnd) {
            //        // Show the associated window for the current Apple object
            //        ShowWindow(currentWindow->wnd, SW_SHOW);
            //    }
            //}
            // Retrieve the associated object from the button's userdata
            DeviceWindowBase* currentWindow = reinterpret_cast<DeviceWindowBase*>(GetWindowLongPtr(hButton, GWLP_USERDATA));

            if (currentWindow) {
                // Show the associated window for the current Apple object
                currentWindow->showWindow();
            }
        }
        break;
    }
    case WM_KEYDOWN: {
        //wchar_t title[100];
        //GetWindowTextW(hEdit, title, 100);
        //SetWindowTextW(hwnd, title);
        break;
    }
        
    case WM_CREATE: {
        addControls(hwnd);
        break;
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // All painting occurs here, between BeginPaint and EndPaint.
         // Draw the text centered within the static control

        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

        //DrawText(hdc, L"Switch", -1, &ps.rcPaint, DT_CENTER | DT_VCENTER);
        //static const TCHAR* HelloWorld = TEXT("Hello, World!");
        //TextOut(hdc, 5, 5, HelloWorld, _tcslen(HelloWorld));


        EndPaint(hwnd, &ps);
        return 0;
    }

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK ClientWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CLOSE: {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_CREATE: {
        break;
    }
    case WM_PAINT:
    {

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // All painting occurs here, between BeginPaint and EndPaint.

        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_COMMAND:
    {
        switch (wParam) {
        case ENTER_COMMAND:
        {

            HWND hButton = (HWND)lParam;

            DeviceWindowBase* currentWindow = reinterpret_cast<DeviceWindowBase*>(GetWindowLongPtr(hButton, GWLP_USERDATA));

            if (currentWindow) {
                // Show the associated window for the current Apple object
                currentWindow->handleButtonPress();
            }
        }

        break;
        }
        break;
    }

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK SwitchWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CLOSE: {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_CREATE: {
        break;
    }
    case WM_PAINT:
    {

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // All painting occurs here, between BeginPaint and EndPaint.

        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_COMMAND:
    {
        switch (wParam) {
        case ENTER_COMMAND:
        {

            HWND hButton = (HWND)lParam;

            DeviceWindowBase* currentWindow = reinterpret_cast<DeviceWindowBase*>(GetWindowLongPtr(hButton, GWLP_USERDATA));

            if (currentWindow) {
                // Show the associated window for the current Apple object
                currentWindow->handleButtonPress();
            }
        }

        break;
        }
        break;
    }

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK RouterWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CLOSE: {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_CREATE: {
        break;
    }
    case WM_PAINT:
    {

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // All painting occurs here, between BeginPaint and EndPaint.

        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_COMMAND:
    {
        switch (wParam) {
        case ENTER_COMMAND:
        {

            HWND hButton = (HWND)lParam;

            DeviceWindowBase* currentWindow = reinterpret_cast<DeviceWindowBase*>(GetWindowLongPtr(hButton, GWLP_USERDATA));

            if (currentWindow) {
                // Show the associated window for the current Apple object
                currentWindow->handleButtonPress();
            }
        }
        }
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK DhcpWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CLOSE: {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_CREATE: {
        break;
    }
    case WM_PAINT:
    {

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // All painting occurs here, between BeginPaint and EndPaint.

        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_COMMAND:
    {
        switch (wParam) {
        case ENTER_COMMAND:
        {

            HWND hButton = (HWND)lParam;

            DeviceWindowBase* currentWindow = reinterpret_cast<DeviceWindowBase*>(GetWindowLongPtr(hButton, GWLP_USERDATA));

            if (currentWindow) {
                // Show the associated window for the current Apple object
                currentWindow->handleButtonPress();
            }
        }

        break;
        }
        break;
    }

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
#endif