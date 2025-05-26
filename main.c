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
    printf("\n按任意键退出...\n");
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
    // 检查共享名中是否包含 "Print"
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
        // 只选择 192.168.*.* 地址
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

    // 设置超时
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
    snprintf(cmd, sizeof(cmd), "net view \\\\%s", ip);

    FILE *fp = _popen(cmd, "r");
    if (!fp) {
        free(ip);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Print") || strstr(line, "打印")) {
            char shareName[256] = "";
            sscanf(line, "%255s", shareName);
            if (strlen(shareName) > 0 && strcmp(shareName, "IPC$") != 0) {
                addPrinter(ip, shareName);
            }
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
    SetConsoleOutputCP(65001); // 设置控制台编码为UTF-8
    printf("开始扫描局域网中的共享打印机...\n");

    char baseIP[16] = "";
    getBaseIP(baseIP);
    if (strlen(baseIP) == 0) {
        printf("未找到有效的本地IP\n");
        cleanExit();
    }

    printf("使用IP前缀: %s\n", baseIP);

    char prefix[16];
    int a, b, c, d;
    sscanf(baseIP, "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(prefix, sizeof(prefix), "%d.%d.%d", a, b, c);

    InitializeCriticalSection(&cs);

    for (int i = MIN_HOST; i <= MAX_HOST; i++) {
        char *ip = (char *)malloc(MAX_IP_LENGTH);
        snprintf(ip, MAX_IP_LENGTH, "%s.%d", prefix, i);
        _beginthread(scanHost, 0, ip);
        Sleep(30); // 控制线程速率
    }

    Sleep(5000); // 简单等待线程结束（可优化为同步）

    if (printerCount == 0) {
        printf("未找到任何共享打印机。\n");
        cleanExit();
    }

    printf("发现打印机列表：\n");
    for (int i = 0; i < printerCount; i++) {
        printf("%d. \\\\%s\\%s\n", i + 1, printers[i].ip, printers[i].shareName);
    }

    Printer *selected = &printers[0];
    char fullPath[512];
    snprintf(fullPath, sizeof(fullPath), "\\\\%s\\%s", selected->ip, selected->shareName);

    printf("自动选择第一个打印机: %s\n", fullPath);

    if (connectPrinter(fullPath) != 0) {
        printf("连接打印机失败\n");
        cleanExit();
    }

    if (setDefaultPrinter(fullPath) != 0) {
        printf("设置默认打印机失败\n");
        cleanExit();
    }

    printf("成功连接并设置 %s 为默认打印机！\n", fullPath);
    cleanExit();
}
