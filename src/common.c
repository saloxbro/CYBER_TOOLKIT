#include "common.h"

// Sets the console text color.
void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// Clears the console screen.
void clear_screen(void) {
    system("cls");
}

// Gets user input safely.
void safe_input(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    if (fgets(buf, (int)size, stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
    } else {
        buf[0] = '\0';
    }
}

// Pauses execution and waits for the user to press Enter.
void wait_for_enter(void) {
    set_color(COLOR_YELLOW);
    printf("\n\n  [ Press Enter to continue ]");
    set_color(COLOR_RESET);
    // Clear the input buffer before waiting
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    // Wait for the final Enter press
    getchar();
}

void print_banner(FILE *out) {
    fprintf(out, "Port Scanner Report\n");
}

void print_timestamp(FILE *out) {
    time_t now = time(NULL);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(out, "Timestamp: %s\n", time_str);
}

int get_int(const char *prompt, int min, int max) {
    char input[10];
    int value;
    while (1) {
        safe_input(prompt, input, sizeof(input));
        value = atoi(input);
        if (value >= min && value <= max) {
            return value;
        }
        printf("Invalid input. Please enter a number between %d and %d.\n", min, max);
    }
}


