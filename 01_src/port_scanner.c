#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "port_scanner.h"
#include "common.h"

#ifndef COLOR_MAGENTA
#define COLOR_MAGENTA 5
#endif

#define MAX_THREADS 64
#define MAX_PORTS_PER_THREAD 64
#define CONNECT_TIMEOUT_MS 300

typedef struct {
    int *open_ports;
    int open_count;
    int *closed_ports;
    int closed_count;
    int total_ports;
    int *progress;
    HANDLE progress_mutex;
} ScanResult;

typedef struct {
    const char *target_ip;
    const int *ports;
    int num_ports;
    FILE *out;
    HANDLE mutex;
    ScanResult *result;
} ScanTask;

static int is_valid_ipv4(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

static int is_valid_hostname(const char *hostname) {
    if (!hostname || strlen(hostname) > 253) return 0;
    for (const char *p = hostname; *p; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '-' || *p == '.')) return 0;
    }
    return 1;
}

int resolve_hostname(const char *hostname, char *ip, size_t ip_size) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) return 0;
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    strncpy(ip, inet_ntoa(addr->sin_addr), ip_size - 1);
    ip[ip_size - 1] = '\0';
    freeaddrinfo(res);
    return 1;
}

// Fast non-blocking connect with timeout
static int fast_connect(const char *ip, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 0;

    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (res == 0) {
        closesocket(sock);
        return 1;
    }
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        res = select(0, NULL, &writefds, NULL, &tv);
        if (res > 0) {
            int err = 0;
            int len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            closesocket(sock);
            return err == 0;
        }
    }
    closesocket(sock);
    return 0;
}

DWORD WINAPI scan_ports_thread(LPVOID param) {
    ScanTask *task = (ScanTask *)param;
    for (int i = 0; i < task->num_ports; ++i) {
        int port = task->ports[i];
        int is_open = fast_connect(task->target_ip, port, CONNECT_TIMEOUT_MS);

        WaitForSingleObject(task->mutex, INFINITE);
        if (is_open) {
            task->result->open_ports[task->result->open_count++] = port;
        } else {
            task->result->closed_ports[task->result->closed_count++] = port;
        }
        ReleaseMutex(task->mutex);

        WaitForSingleObject(task->result->progress_mutex, INFINITE);
        (*task->result->progress)++;
        int percent = (int)(((*task->result->progress) * 100.0) / task->result->total_ports);
        printf("\rProgress: [%-50.*s] %3d%%", percent / 2, "==================================================", percent);
        fflush(stdout);
        ReleaseMutex(task->result->progress_mutex);
    }
    return 0;
}

void print_ascii_box(FILE *out, const char *title, const int *ports, int count) {
    fprintf(out, "+-------------------------------+\n");
    fprintf(out, "| %-29s |\n", title);
    fprintf(out, "+-------------------------------+\n");
    for (int i = 0; i < count; ++i) {
        fprintf(out, "| Port: %-22d |\n", ports[i]);
    }
    if (count == 0) {
        fprintf(out, "| %-29s |\n", "None");
    }
    fprintf(out, "+-------------------------------+\n");
}

void scan_ports_parallel(const char *target_ip, const int *ports, int num_ports, FILE *out) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    int cpu_threads = (int)sysinfo.dwNumberOfProcessors;
    int n_threads = (num_ports + MAX_PORTS_PER_THREAD - 1) / MAX_PORTS_PER_THREAD;
    if (n_threads > cpu_threads * 2) n_threads = cpu_threads * 2;
    if (n_threads > MAX_THREADS) n_threads = MAX_THREADS;

    HANDLE threads[MAX_THREADS];
    ScanTask tasks[MAX_THREADS];
    HANDLE mutex = CreateMutex(NULL, FALSE, NULL);

    int *open_ports = (int *)malloc(num_ports * sizeof(int));
    int *closed_ports = (int *)malloc(num_ports * sizeof(int));
    int progress = 0;
    HANDLE progress_mutex = CreateMutex(NULL, FALSE, NULL);

    ScanResult result = { open_ports, 0, closed_ports, 0, num_ports, &progress, progress_mutex };

    for (int t = 0; t < n_threads; ++t) {
        int start = t * MAX_PORTS_PER_THREAD;
        int count = (start + MAX_PORTS_PER_THREAD > num_ports) ? (num_ports - start) : MAX_PORTS_PER_THREAD;
        tasks[t].target_ip = target_ip;
        tasks[t].ports = ports + start;
        tasks[t].num_ports = count;
        tasks[t].out = out;
        tasks[t].mutex = mutex;
        tasks[t].result = &result;
        threads[t] = CreateThread(NULL, 0, scan_ports_thread, &tasks[t], 0, NULL);
    }
    WaitForMultipleObjects(n_threads, threads, TRUE, INFINITE);
    printf("\n");
    for (int t = 0; t < n_threads; ++t) CloseHandle(threads[t]);
    CloseHandle(mutex);
    CloseHandle(progress_mutex);

    fprintf(out, "\n");
    print_ascii_box(out, "OPEN PORTS", open_ports, result.open_count);
    fprintf(out, "\n");
    print_ascii_box(out, "CLOSED PORTS", closed_ports, result.closed_count);

    free(open_ports);
    free(closed_ports);
}

static void ascii_banner(void) {
    set_color(COLOR_CYAN);
    printf("\n");
    printf("==============================================================\n");
    printf("   FUTURISTIC PORT SCANNER                                    \n");
    printf("   ------------------------                                   \n");
    printf("   |\\     /|(  ___  )(       )(  ____ \\|\\     /|\n");
    printf("   | )   ( || (   ) || () () || (    \\/| )   ( |\n");
    printf("   | |   | || |   | || || || || (__    | |   | |\n");
    printf("   | |   | || |   | || |(_)| ||  __)   | |   | |\n");
    printf("   | |   | || |   | || |   | || (      | |   | |\n");
    printf("   | (___) || (___) || )   ( || (____/\\| (___) |\n");
    printf("   (_______)(_______)|/     \\|(_______/(_______)\n");
    printf("==============================================================\n");
    set_color(COLOR_RESET);
}

void port_scanner_menu(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        set_color(COLOR_RED); printf("WSAStartup failed.\n"); set_color(COLOR_RESET);
        return;
    }

    char input[256], target_ip[256];
    FILE *out = fopen("scan_report.txt", "w");
    if (!out) {
        set_color(COLOR_RED); perror("Error opening scan_report.txt"); set_color(COLOR_RESET);
        WSACleanup();
        return;
    }

    ascii_banner();
    print_banner(out);
    print_timestamp(out);

    set_color(COLOR_WHITE);
    printf("\n[ Futuristic Port Scanner ]\n");
    printf("--------------------------------------------\n");
    printf("Enter a target IPv4 address or hostname to scan.\n");
    set_color(COLOR_RESET);

    printf("\n[Target] > ");
    if (!fgets(input, sizeof(input), stdin)) {
        set_color(COLOR_RED); printf("Input error.\n"); set_color(COLOR_RESET);
        fclose(out); WSACleanup(); return;
    }
    input[strcspn(input, "\n")] = '\0';

    if (is_valid_ipv4(input)) {
        strncpy(target_ip, input, sizeof(target_ip) - 1);
        target_ip[sizeof(target_ip) - 1] = '\0';
        fprintf(out, "\nTarget: %s\n", target_ip);
    } else if (is_valid_hostname(input) && resolve_hostname(input, target_ip, sizeof(target_ip))) {
        set_color(COLOR_GREEN);
        printf("Resolved '%s' to -> %s\n", input, target_ip);
        set_color(COLOR_RESET);
        fprintf(out, "\nTarget: %s (%s)\n", input, target_ip);
    } else {
        set_color(COLOR_RED);
        printf("Error: Invalid input. '%s' is not a valid hostname or IPv4 address.\n", input);
        set_color(COLOR_RESET);
        fclose(out); WSACleanup(); return;
    }

    set_color(COLOR_MAGENTA);
    printf("\n[ SCAN MODES ]\n");
    printf("--------------------------------------------\n");
    printf("  1. Fast Scan      (Top 22 common ports)\n");
    printf("  2. Custom Range   (Specify port range)\n");
    set_color(COLOR_RESET);

    int mode = get_int("[Mode] > ", 1, 2);

    if (mode == 1) {
        int fast_ports[] = {20, 21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080};
        int num_ports = sizeof(fast_ports) / sizeof(fast_ports[0]);
        scan_ports_parallel(target_ip, fast_ports, num_ports, out);
    } else {
        int start_port = get_int("[Start Port] > ", 1, 65535);
        int end_port = get_int("[End Port]   > ", start_port, 65535);
        int n_ports = end_port - start_port + 1;
        int *ports = (int *)malloc(n_ports * sizeof(int));
        if (!ports) {
            set_color(COLOR_RED); printf("Error: Memory allocation failed.\n"); set_color(COLOR_RESET);
            fclose(out); WSACleanup(); return;
        }
        for (int i = 0; i < n_ports; ++i) ports[i] = start_port + i;
        scan_ports_parallel(target_ip, ports, n_ports, out);
        free(ports);
    }

    set_color(COLOR_CYAN);
    printf("\n--------------------------------------------\n");
    printf("Scan complete. Report saved to scan_report.txt\n");
    printf("--------------------------------------------\n");
    set_color(COLOR_RESET);
    fclose(out);
    WSACleanup();
}