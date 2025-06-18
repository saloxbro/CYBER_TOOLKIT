#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "dns_lookup.h"
#include "common.h"

#ifndef DNS_TYPE_TXT
#define DNS_TYPE_TXT 16
#endif

#ifndef MAX_OUTPUT_SIZE
#define MAX_OUTPUT_SIZE 4096
#endif

// --- Strict domain validation ---
int is_valid_domain(const char *domain) {
    size_t len = strlen(domain);
    if (len == 0 || len > 253) return 0;
    if (isspace(domain[0]) || isspace(domain[len-1])) return 0;
    int label_len = 0;
    int dot = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = domain[i];
        if (c == '.') {
            if (i == 0 || i == len-1) return 0;
            if (dot) return 0; // no consecutive dots
            if (label_len == 0 || label_len > 63) return 0;
            label_len = 0;
            dot = 1;
            continue;
        }
        dot = 0;
        if (!(isalnum((unsigned char)c) || c == '-')) return 0;
        if ((i > 0 && domain[i-1] == '-') || (i < len-1 && domain[i+1] == '-')) {
            if (c == '-') return 0; // no leading/trailing hyphens in a label
        }
        label_len++;
    }
    if (label_len == 0 || label_len > 63) return 0;
    return 1;
}

static void safe_strcat(char *dest, size_t dest_size, const char *src) {
    strncat(dest, src, dest_size - strlen(dest) - 1);
}

static void print_record_row(char *output, size_t outsize, const char *type, const char *value) {
    char row[256];
    snprintf(row, sizeof(row), "| %-5s | %-63s |\n", type, value);
    safe_strcat(output, outsize, row);
}

static void format_ipv6(const BYTE *ip6, char *buf, size_t buflen) {
    struct in6_addr addr;
    memcpy(&addr, ip6, 16);
    DWORD addrlen = (DWORD)buflen;
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_addr = addr;
    if (WSAAddressToStringA((LPSOCKADDR)&sa6, sizeof(sa6), NULL, buf, &addrlen) == 0) {
        char *pct = strchr(buf, '%');
        if (pct) *pct = 0;
    } else {
        snprintf(buf, buflen,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
            ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
    }
}

int perform_dns_query(const char *domain, WORD record_type, char *output, int *records_added) {
    PDNS_RECORD pResult = NULL;
    DNS_STATUS status = DnsQuery_A(domain, record_type, DNS_QUERY_STANDARD, NULL, &pResult, NULL);
    *records_added = 0;
    if (status == DNS_ERROR_RCODE_NAME_ERROR) {
        return DNS_ERROR_RCODE_NAME_ERROR;
    }
    if (status != ERROR_SUCCESS) {
        return status;
    }

    PDNS_RECORD pRec = pResult;
    while (pRec) {
        char value[256] = {0};
        switch (pRec->wType) {
            case DNS_TYPE_A:
                snprintf(value, sizeof(value), "%s", inet_ntoa(*(struct in_addr *)&pRec->Data.A.IpAddress));
                print_record_row(output, MAX_OUTPUT_SIZE, "A", value);
                (*records_added)++;
                break;
            case DNS_TYPE_AAAA: {
                char ipv6[128] = {0};
                format_ipv6(pRec->Data.AAAA.Ip6Address.IP6Byte, ipv6, sizeof(ipv6));
                print_record_row(output, MAX_OUTPUT_SIZE, "AAAA", ipv6);
                (*records_added)++;
                break;
            }
            case DNS_TYPE_MX:
                snprintf(value, sizeof(value), "Pref: %u, %s", pRec->Data.MX.wPreference, pRec->Data.MX.pNameExchange);
                print_record_row(output, MAX_OUTPUT_SIZE, "MX", value);
                (*records_added)++;
                break;
            case DNS_TYPE_CNAME:
                snprintf(value, sizeof(value), "%s", pRec->Data.CNAME.pNameHost);
                print_record_row(output, MAX_OUTPUT_SIZE, "CNAME", value);
                (*records_added)++;
                break;
            case DNS_TYPE_TXT: {
                for (DWORD i = 0; i < pRec->Data.TXT.dwStringCount; ++i) {
                    snprintf(value, sizeof(value), "%s", pRec->Data.TXT.pStringArray[i]);
                    print_record_row(output, MAX_OUTPUT_SIZE, "TXT", value);
                    (*records_added)++;
                }
                break;
            }
            case DNS_TYPE_NS:
                snprintf(value, sizeof(value), "%s", pRec->Data.NS.pNameHost);
                print_record_row(output, MAX_OUTPUT_SIZE, "NS", value);
                (*records_added)++;
                break;
            default:
                break;
        }
        pRec = pRec->pNext;
    }
    DnsRecordListFree(pResult, DnsFreeRecordList);
    return ERROR_SUCCESS;
}

void print_dns_banner(void) {
    set_color(COLOR_CYAN);
    const char* banner_art =
" \n\
   ____  _   _ ____   ____   ___  _   _ \n\
  |  _ \\| \\ | |  _ \\ / ___| / _ \\| \\ | |\n\
  | | | |  \\| | | | | |  _ | | | |  \\| |\n\
  | |_| | |\\  | |_| | |_| || |_| | |\\  |\n\
  |____/|_| \\_|____/ \\____(_)___/|_| \\_|\n\
";
    printf("%s", banner_art);
    set_color(COLOR_RESET);
}

void log_dns_results(const char *domain, const char *output) {
    FILE *log_file = fopen("dns_results.log", "a");
    if (!log_file) {
        set_color(COLOR_RED);
        perror("Error opening dns_results.log");
        set_color(COLOR_RESET);
        return;
    }
    fprintf(log_file, "Domain: %s\nResults:\n%s\n", domain, output);
    fclose(log_file);
}

void dns_lookup_menu(void) {
    char domain[256] = "";
    char output[MAX_OUTPUT_SIZE];

    while (1) {
        clear_screen();
        print_dns_banner();

        time_t now = time(NULL);
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        set_color(COLOR_GRAY);
        printf("  DNS Reconnaissance Interface v2.4 | Status: Online | %s \n", time_str);
        set_color(COLOR_WHITE);
        printf("+------------------------------------------------------------------------------+\n");
        printf("|                        --:: MENU ::--                                        |\n");
        printf("+------------------------------------------------------------------------------+\n");

        if (strlen(domain) > 0) {
            printf("| Current Target: ");
            set_color(COLOR_YELLOW);
            printf("%-59s", domain);
            set_color(COLOR_WHITE);
            printf("|\n");
        } else {
            printf("| Current Target: %-59s |\n", "None Selected");
        }

        printf("+------------------------------------------------------------------------------+\n");
        printf("| "); set_color(COLOR_CYAN); printf("[1]"); set_color(COLOR_WHITE); printf(" Set Target Domain      | "); set_color(COLOR_CYAN); printf("[4]"); set_color(COLOR_WHITE); printf(" CNAME Lookup         | "); set_color(COLOR_CYAN); printf("[7]"); set_color(COLOR_WHITE); printf(" Query All      |\n");
        printf("| "); set_color(COLOR_CYAN); printf("[2]"); set_color(COLOR_WHITE); printf(" A (IPv4) Lookup        | "); set_color(COLOR_CYAN); printf("[5]"); set_color(COLOR_WHITE); printf(" TXT Lookup           | "); set_color(COLOR_CYAN); printf("               "); set_color(COLOR_WHITE); printf("|\n");
        printf("| "); set_color(COLOR_CYAN); printf("[3]"); set_color(COLOR_WHITE); printf(" AAAA (IPv6) Lookup     | "); set_color(COLOR_CYAN); printf("[6]"); set_color(COLOR_WHITE); printf(" NS Lookup            | "); set_color(COLOR_RED); printf("[0]"); set_color(COLOR_WHITE); printf(" Return to Main Menu |\n");
        printf("+------------------------------------------------------------------------------+\n");

        char choice_str[10] = {0};
        set_color(COLOR_YELLOW);
        safe_input("\n  [ > ] ", choice_str, sizeof(choice_str));
        set_color(COLOR_RESET);

        if (strlen(choice_str) != 1 || !isdigit((unsigned char)choice_str[0])) {
            set_color(COLOR_RED);
            printf("\n  [ERROR] Invalid selection. Enter a number (0-7).\n");
            set_color(COLOR_RESET);
            Sleep(1500);
            continue;
        }

        int choice = atoi(choice_str);

        if (choice == 1) {
            set_color(COLOR_YELLOW);
            char input_buf[256] = {0};
            safe_input("  Enter new target domain: ", input_buf, sizeof(input_buf));
            size_t in_len = strlen(input_buf);
            if (in_len == 0 || in_len > 253) goto domain_invalid;
            size_t start = 0, end = in_len - 1;
            while (start < in_len && isspace((unsigned char)input_buf[start])) ++start;
            while (end > start && isspace((unsigned char)input_buf[end])) --end;
            char trimmed[256] = {0};
            strncpy(trimmed, input_buf + start, end - start + 1);
            trimmed[end - start + 1] = '\0';

            if (!is_valid_domain(trimmed)) goto domain_invalid;
            strcpy(domain, trimmed);
            continue;
        domain_invalid:
            set_color(COLOR_RED);
            printf("\n  [ERROR] Invalid domain name format. Target reset.\n");
            set_color(COLOR_RESET);
            Sleep(2000);
            domain[0] = '\0';
            continue;
        }

        if (choice == 0) break;

        if (strlen(domain) == 0 && (choice >= 2 && choice <= 7)) {
            set_color(COLOR_RED);
            printf("\n  [ERROR] Please set a target domain first (Option 1).\n");
            set_color(COLOR_RESET);
            Sleep(2000);
            continue;
        }

        output[0] = '\0';
        const char* header = "+-------+---------------------------------------------------------------+\n"
                             "| Type  | Value                                                         |\n"
                             "+-------+---------------------------------------------------------------+\n";
        safe_strcat(output, MAX_OUTPUT_SIZE, header);

        int total_records = 0;
        int records_this_query = 0;
        DNS_STATUS status = 0;
        int found = 0;

        // Correct record type for each option!
        if (choice == 2) { // A
            status = perform_dns_query(domain, DNS_TYPE_A, output, &records_this_query);
            total_records = records_this_query;
            found = 1;
        } else if (choice == 3) { // AAAA
            status = perform_dns_query(domain, DNS_TYPE_AAAA, output, &records_this_query);
            total_records = records_this_query;
            found = 1;
        } else if (choice == 4) { // CNAME
            status = perform_dns_query(domain, DNS_TYPE_CNAME, output, &records_this_query);
            total_records = records_this_query;
            found = 1;
        } else if (choice == 5) { // TXT
            status = perform_dns_query(domain, DNS_TYPE_TXT, output, &records_this_query);
            total_records = records_this_query;
            found = 1;
        } else if (choice == 6) { // NS
            status = perform_dns_query(domain, DNS_TYPE_NS, output, &records_this_query);
            total_records = records_this_query;
            found = 1;
        } else if (choice == 7) { // Query all
            int types[] = { DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_MX, DNS_TYPE_CNAME, DNS_TYPE_TXT, DNS_TYPE_NS };
            for (int i = 0; i < 6; ++i) {
                records_this_query = 0;
                status = perform_dns_query(domain, types[i], output, &records_this_query);
                total_records += records_this_query;
                if (status == DNS_ERROR_RCODE_NAME_ERROR) {
                    total_records = -1;
                    break;
                }
            }
            found = 1;
        }

        if (!found) {
            set_color(COLOR_RED);
            printf("\n  [ERROR] Invalid selection. Try again.\n");
            set_color(COLOR_RESET);
            Sleep(1500);
            continue;
        }

        if (total_records == -1) {
            print_record_row(output, MAX_OUTPUT_SIZE, "ERROR", "Domain does not exist (NXDOMAIN).");
        } else if (total_records == 0) {
            print_record_row(output, MAX_OUTPUT_SIZE, "INFO", "No records found for that record type. Try another.");
        }

        const char* footer = "+-------+---------------------------------------------------------------+\n";
        safe_strcat(output, MAX_OUTPUT_SIZE, footer);

        set_color(COLOR_GREEN);
        printf("\n%s", output);
        set_color(COLOR_RESET);

        log_dns_results(domain, output);
        wait_for_enter();
    }
}
