
// Define endianness macros if not already defined
#include "class\common.h"
#include "class\client\client.h"
#include "class\switch\switch.h"
#include "class\dhcp\dhcp.h"
#include "class\router\router.h"
#include "class\helper.h"
#include "class\deviceWindow.h"

uint8_t Iface::count1 = 0;
uint8_t Iface::count2 = 0;
uint8_t Iface::count3 = 0;
uint8_t Iface::count4 = 0;
uint8_t Iface::count5 = 0;
uint8_t Iface::count6 = 0;

uint8_t Client::counter = 0;
uint8_t Switch::counter = 0;
uint8_t Router::counter = 0;
uint8_t Dhcp::counter = 0;

std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> Loggable::consoleSink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PWSTR pCmdLine, _In_ int nCmdShow)
{


	mainWindowClass.lpfnWndProc = MainWindowProc;
	mainWindowClass.hInstance = hInstance;
	mainWindowClass.lpszClassName = MAIN_CLASS_NAME;
	mainWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	mainWindowClass.hbrBackground = (HBRUSH)COLOR_3DHIGHLIGHT;

	RegisterClass(&mainWindowClass);

	clientWindowClass.lpfnWndProc = ClientWindowProc;
	clientWindowClass.hInstance = hInstance;
	clientWindowClass.lpszClassName = CLIENT_CLASS_NAME;
	clientWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	clientWindowClass.hbrBackground = (HBRUSH)COLOR_3DHIGHLIGHT;

	RegisterClass(&clientWindowClass);

	switchWindowClass.lpfnWndProc = SwitchWindowProc;
	switchWindowClass.hInstance = hInstance;
	switchWindowClass.lpszClassName = SWITCH_CLASS_NAME;
	switchWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	switchWindowClass.hbrBackground = (HBRUSH)COLOR_3DHIGHLIGHT;

	RegisterClass(&switchWindowClass);

	routerWindowClass.lpfnWndProc = RouterWindowProc;
	routerWindowClass.hInstance = hInstance;
	routerWindowClass.lpszClassName = ROUTER_CLASS_NAME;
	routerWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	routerWindowClass.hbrBackground = (HBRUSH)COLOR_3DHIGHLIGHT;

	RegisterClass(&routerWindowClass);

	dhcpWindowClass.lpfnWndProc = DhcpWindowProc;
	dhcpWindowClass.hInstance = hInstance;
	dhcpWindowClass.lpszClassName = DHCP_CLASS_NAME;
	dhcpWindowClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	dhcpWindowClass.hbrBackground = (HBRUSH)COLOR_3DHIGHLIGHT;

	RegisterClass(&dhcpWindowClass);



	// Allocate a console for input/output
	if (AllocConsole()) {
		// Redirect standard input/output to the console
		FILE* fp;
		freopen_s(&fp, "CONIN$", "r", stdin);
		freopen_s(&fp, "CONOUT$", "w", stdout);
		freopen_s(&fp, "CONOUT$", "w", stderr);

		std::cout << "Console initialized successfully." << std::endl;
	}
	else {
		MessageBox(NULL, L"Failed to create console.", L"Error", MB_OK | MB_ICONERROR);
	}

	std::string command = "Karan";

	Client c1;
	Client c2;
	Client c3;
	Client c4;

	IpPool pool1(	ipToUint32("192.168.0.0"),
								ipToUint32("255.255.128.0"),
								ipToUint32("192.168.10.0"),
								ipToUint32("1.1.1.1"),
								std::chrono::hours(8));
	IpPool pool2(	ipToUint32("192.168.128.0"),
								ipToUint32("255.255.128.0"),
								ipToUint32("192.168.138.0"),
								ipToUint32("1.1.1.1"),
								std::chrono::hours(6));
	std::vector<IpPool> dhcp1IpPools {pool1,pool2};

	// Dhcp takes the first ip of the first ip pool and assigns that to the interface of it.
	Dhcp d1{dhcp1IpPools};
	
	Switch s1;

	IpPool routerIfaceIp1(ipToUint32("192.168.10.0"),
												ipToUint32("255.255.128.0"),
												ipToUint32("100.100.100.100"),
												ipToUint32("1.1.1.1"));
	IpPool routerIfaceIp2(ipToUint32("192.170.10.0"),
												ipToUint32("255.255.128.0"),
												ipToUint32("100.100.100.100"),
												ipToUint32("1.1.1.1"));

	std::vector<IpPool> routerIfaceIps {routerIfaceIp1,routerIfaceIp2};
	std::vector<uint32_t> routerIfaceIp { ipToUint32("192.168.10.0"), ipToUint32("192.170.10.0") };

	Router r1 {routerIfaceIps};

	Switch s2;

	IpPool pool3(	ipToUint32("192.170.0.0"),
								ipToUint32("255.255.128.0"),
								ipToUint32("192.170.10.0"),
								ipToUint32("1.1.1.1"),
								std::chrono::hours(8));
	IpPool pool4(	ipToUint32("192.170.128.0"),
								ipToUint32("255.255.128.0"),
								ipToUint32("192.170.138.0"),
								ipToUint32("1.1.1.1"),
								std::chrono::hours(6));
	std::vector<IpPool> dhcp2IpPools {pool3,pool4};

	Dhcp d2{dhcp2IpPools};
	

	allClients.push_back(&c1);
	allClients.push_back(&c2);
	allClients.push_back(&c3);
	allClients.push_back(&c4);
	
	allSwitches.push_back(&s1);
	allSwitches.push_back(&s2);

	allRouter.push_back(&r1);

	allDhcp.push_back(&d1);
	allDhcp.push_back(&d2);

	// Mac Address for the interfaces
	// c1: 1
	// c2: 2
	// c3: 3
	// c4: 4
	// d1: 5
	// s1: 6,7,8,9
	// r1: a,b,c,d
	// s2: e,f,11,12
	// d2: 13
	


	// c1.iface.link = &s1.ifaces[0];
	// c2.iface.link = &s1.ifaces[1];
	// c3.iface.link = &s1.ifaces[2];
	// d1.iface.link = &s1.ifaces[3];

	// s1.ifaces[0].link = &c1.iface;
	// s1.ifaces[1].link = &c2.iface;
	// s1.ifaces[2].link = &c3.iface;
	// s1.ifaces[3].link = &d1.iface;


	/*======================================*/
	/*============ Device Links ============*/
	/*======================================*/
	c1.iface.link = &s1.ifaces[0];
	c2.iface.link = &s1.ifaces[1];

	c3.iface.link = &s2.ifaces[0];
	c4.iface.link = &s2.ifaces[1];

	d1.iface.link = &s1.ifaces[2];
	d2.iface.link = &s2.ifaces[2];

	r1.ifaces[0].link = &s1.ifaces[3];
	r1.ifaces[1].link = &s2.ifaces[3];

	s1.ifaces[0].link = &c1.iface;
	s1.ifaces[1].link = &c2.iface;
	s1.ifaces[2].link = &d1.iface;
	s1.ifaces[3].link = &r1.ifaces[0];

	s2.ifaces[0].link = &c3.iface;
	s2.ifaces[1].link = &c4.iface;
	s2.ifaces[2].link = &d2.iface;
	s2.ifaces[3].link = &r1.ifaces[1];
	

	// c1.iface.link = &d1.iface;
	// d1.iface.link = &c1.iface;

	// Create the main window.
	HWND hwnd = CreateWindowEx(
		0,                                      // Optional window styles.
		MAIN_CLASS_NAME,                        // Window class
		L"Main Window",                         // Window text
		WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CAPTION | WS_SYSMENU,			// Window style

		// Size and position
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

		NULL,       // Parent window    
		NULL,       // Menu
		hInstance,  // Instance handle
		NULL        // Additional application data
	);

	if (hwnd == NULL)
	{
		return 0;
	}

	ShowWindow(hwnd, nCmdShow);

	// Run the message loop.
	MSG msg = { };
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// Close the console window
	FreeConsole();

	return 0;
}


