#include <winsock2.h> // Include winsock2.h first
#include <windows.h>  // Include windows.h after winsock2.h
#include "common.h"
#include "port_scanner.h"
#include "password_cracker.h"
#include "dns_lookup.h"

void print_main_banner(void) {
    set_color(COLOR_CYAN);
    const char* banner_art =
" \n\
   ______      __           __         _______          __\n\
  / ____/_  __/ /_  _______/ /_       / ____(_)____    / /\n\
 / /   / / / / / / / / ___/ __/______/ /_  / / ___/   / / \n\
/ /___/ /_/ / / /_/ / /__/ /_/_______/ __/ / / /__    /_/  \n\
\\____/\\__,_/_/\\__,_/\\___/\\__/       /_/   /_/\\___/   (_)   \n\
               CYBERSECURITY TOOLKIT v1.1 Made by AuthMatrix\n\
";
    printf("%s", banner_art);
    set_color(COLOR_RESET);
}

// --- Main Program Loop ---
int main(void) {
    // Initialize Winsock for tools requiring network functionality
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Fatal Error: WSAStartup failed.\n");
        return 1;
    }

    while (1) {
        clear_screen();
        print_main_banner();

        time_t now = time(NULL);
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        set_color(COLOR_GRAY);
        printf("  System Time: %s | Status: Operational\n", time_str);
        set_color(COLOR_WHITE);

        printf("+--------------------------------------------------------------------+\n");
        printf("|                        --:: TOOL SELECTION ::--                      |\n");
        printf("+--------------------------------------------------------------------+\n");
        printf("| "); set_color(COLOR_CYAN); printf("[1]"); set_color(COLOR_WHITE); printf(" Port Scanner         | Scans a target for open TCP ports.     |\n");
        printf("| "); set_color(COLOR_CYAN); printf("[2]"); set_color(COLOR_WHITE); printf(" DNS Lookup           | Performs DNS reconnaissance on a domain.   |\n");
        printf("| "); set_color(COLOR_CYAN); printf("[3]"); set_color(COLOR_WHITE); printf(" MD5 Cracker/Hasher   | Cracks or generates MD5 hashes.          |\n");
        printf("+--------------------------------------------------------------------+\n");
        printf("| "); set_color(COLOR_RED); printf("[0]"); set_color(COLOR_WHITE); printf(" Exit Toolkit         | Close the application.                   |\n");
        printf("+--------------------------------------------------------------------+\n");

        char choice_str[10];
        set_color(COLOR_YELLOW);
        safe_input("\n  [ > ] ", choice_str, sizeof(choice_str));
        set_color(COLOR_RESET);

        long choice = (strlen(choice_str) == 1 && isdigit(choice_str[0])) ? strtol(choice_str, NULL, 10) : -1;

        switch (choice) {
            case 1:
                port_scanner_menu(); // Call the port scanner menu
                break;
            case 2:
                dns_lookup_menu(); // Call the DNS lookup menu
                break;
            case 3:
                password_cracker_menu(); // Call the password cracker menu
                break;
            case 0:
                clear_screen();
                printf("Exiting Cyber Toolkit. Goodbye!\n");
                WSACleanup(); // Clean up Winsock before exiting
                return 0;
            default:
                set_color(COLOR_RED);
                printf("\n  [ERROR] Invalid selection. Please try again.\n");
                set_color(COLOR_RESET);
                Sleep(1500);
                break;
        }
    }

    WSACleanup();
    return 0;
}