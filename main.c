#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lm.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "winspool.lib")

#define SMB_PORT 445
#define TIMEOUT_MS 3000
#define MIN_HOST 100
#define MAX_HOST 110
#define MAX_IP_LENGTH 16
#define MAX_PRINTERS 100

CRITICAL_SECTION cs;

typedef struct {
    char ip[MAX_IP_LENGTH];
    char shareName[256];
} Printer;

Printer printers[MAX_PRINTERS];
int printerCount = 0;

void cleanExit() {
    DeleteCriticalSection(&cs);
    printf("\nPress any key to exit...\n");
    getchar();
    exit(0);
}

void addPrinter(const char *ip, const char *shareName) {
    EnterCriticalSection(&cs);
    if (printerCount >= MAX_PRINTERS) {
        LeaveCriticalSection(&cs);
        return;
    }
    strcpy(printers[printerCount].ip, ip);
    strcpy(printers[printerCount].shareName, shareName);
    printerCount++;
    LeaveCriticalSection(&cs);
}

int isPrinterShared(const char *ip, const char *shareName) {
    return strstr(shareName, "Print") != NULL;
}

void getBaseIP(char *baseIP) {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    DWORD status = GetAdaptersInfo(adapterInfo, &bufLen);

    if (status != ERROR_SUCCESS) return;

    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    while (pAdapter) {
        const char* ip = pAdapter->IpAddressList.IpAddress.String;
        if (strncmp(ip, "192.168.", 8) == 0) {
            strcpy(baseIP, ip);
            return;
        }
        pAdapter = pAdapter->Next;
    }
}

int hasSMB(const char *ip) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in addr;
    int result;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SMB_PORT);
    addr.sin_addr.s_addr = inet_addr(ip);

    DWORD timeout = TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    closesocket(sock);
    WSACleanup();

    return result == 0;
}

void scanHost(void *arg) {
    char *ip = (char *)arg;

    if (!hasSMB(ip)) {
        free(ip);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "powershell -NoProfile -Command "
             "\"Get-WmiObject -Class Win32_Share -ComputerName %s | "
             "Where-Object { $_.Type -eq 0 -or $_.Type -eq 1 } | "
             "ForEach-Object { $_.Name }\"", ip);

    FILE *fp = _popen(cmd, "r");
    if (!fp) {
        free(ip);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // 移除换行符
        line[strcspn(line, "\r\n")] = '\0';

        // 过滤 IPC$，仅添加有效共享名
        if (strlen(line) > 0 &&
        strcmp(line, "IPC$") != 0 &&
        strcmp(line, "print$") != 0) {

        addPrinter(ip, line);  // line 是有效共享打印机名
        }
    }

    _pclose(fp);
    free(ip);
}

int connectPrinter(const char *fullPath) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rundll32 printui.dll,PrintUIEntry /in /n \"%s\"", fullPath);
    return system(cmd);
}

int setDefaultPrinter(const char *fullPath) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rundll32 printui.dll,PrintUIEntry /y /n \"%s\"", fullPath);
    return system(cmd);
}

int main() {
    printf("Starting to scan for shared printers in the local network...\n");

    char baseIP[16] = "";
    getBaseIP(baseIP);
    if (strlen(baseIP) == 0) {
        printf("No valid local IP found\n");
        cleanExit();
    }

    printf("Using IP prefix: %s\n", baseIP);

    char prefix[16];
    int a, b, c, d;
    sscanf(baseIP, "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(prefix, sizeof(prefix), "%d.%d.%d", a, b, c);

    InitializeCriticalSection(&cs);

    for (int i = MIN_HOST; i <= MAX_HOST; i++) {
        char *ip = (char *)malloc(MAX_IP_LENGTH);
        snprintf(ip, MAX_IP_LENGTH, "%s.%d", prefix, i);
        _beginthread(scanHost, 0, ip);
        Sleep(30);
    }

    Sleep(5000);

    if (printerCount == 0) {
        printf("No shared printers found.\n");
        cleanExit();
    }

    printf("Discovered printers list:\n");
    for (int i = 0; i < printerCount; i++) {
        printf("%d. \\\\%s\\%s\n", i + 1, printers[i].ip, printers[i].shareName);
    }

    Printer *selected = &printers[0];
    char fullPath[512];
    snprintf(fullPath, sizeof(fullPath), "\\\\%s\\%s", selected->ip, selected->shareName);

    printf("Automatically selecting first printer: %s\n", fullPath);

    if (connectPrinter(fullPath) != 0) {
        printf("Failed to connect to printer\n");
        cleanExit();
    }

    if (setDefaultPrinter(fullPath) != 0) {
        printf("Failed to set default printer\n");
        cleanExit();
    }

    printf("Successfully connected and set %s as default printer!\n", fullPath);
    cleanExit();
}
