#ifndef COMMON_H
#define COMMON_H

// --- Standard Library Includes ---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <ctype.h>
#include <time.h>

// --- Color Definitions ---
#define COLOR_RESET   7
#define COLOR_GREEN   10
#define COLOR_RED     12
#define COLOR_YELLOW  14
#define COLOR_CYAN    11
#define COLOR_WHITE   15
#define COLOR_GRAY    8

// --- Function Declarations (Prototypes) ---

// Sets the console text color.
void set_color(int color);

// Clears the console screen.
void clear_screen(void);

// Gets user input safely.
void safe_input(const char *prompt, char *buf, size_t size);

// Pauses execution and waits for the user to press Enter.
void wait_for_enter(void);

// Prints a banner to the specified output stream.
void print_banner(FILE *out);

// Prints the current timestamp to the specified output stream.
void print_timestamp(FILE *out);

// Gets an integer from the user with input validation.
int get_int(const char *prompt, int min, int max);

// Prints the main banner.
void print_main_banner(void);

#endif // COMMON_H
