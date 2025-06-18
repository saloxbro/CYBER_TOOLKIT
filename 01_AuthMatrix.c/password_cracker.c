#include "password_cracker.h"
#include "common.h"
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT_LEN 255

// Strict check: must be exactly 32 lowercase hex chars
static int is_valid_md5_hash(const char *s) {
    if (!s || strlen(s) != 32) return 0;
    for (int i = 0; i < 32; ++i)
        if (!isxdigit((unsigned char)s[i]) || (isalpha((unsigned char)s[i]) && !islower((unsigned char)s[i])))
            return 0;
    return 1;
}

// Only allow passwords with visible ASCII (no spaces, no non-printable)
static int is_valid_password(const char *s) {
    size_t len = strlen(s);
    if (len == 0 || len > MAX_INPUT_LEN) return 0;
    for (size_t i = 0; i < len; ++i)
        if (!isgraph((unsigned char)s[i])) return 0; // isgraph: printable, not space
    return 1;
}

void password_cracker_menu(void) {
    while (1) {
        clear_screen();
        print_main_banner();

        set_color(COLOR_WHITE);
        printf("Please choose a function from the menu below:\n\n");
        printf("   [1] "); set_color(COLOR_CYAN); printf("Password -> MD5 Hash Generator\n"); set_color(COLOR_RESET);
        printf("   [2] "); set_color(COLOR_CYAN); printf("MD5 Hash -> Dictionary Cracker\n\n"); set_color(COLOR_RESET);
        printf("   [0] "); set_color(COLOR_RED); printf("Return to Main Menu\n\n"); set_color(COLOR_RESET);

        char choice_str[10] = {0};
        set_color(COLOR_YELLOW);
        safe_input("Selection > ", choice_str, sizeof(choice_str));
        set_color(COLOR_RESET);

        // Strict: Only accept 1 char and 0-2
        if (strlen(choice_str) != 1 || !isdigit(choice_str[0])) {
            set_color(COLOR_RED);
            printf("\n[ERROR] Invalid selection. Enter 0, 1, or 2.\n");
            set_color(COLOR_RESET);
            Sleep(1500);
            continue;
        }
        int choice = atoi(choice_str);
        if (choice < 0 || choice > 2) {
            set_color(COLOR_RED);
            printf("\n[ERROR] Invalid selection. Enter 0, 1, or 2.\n");
            set_color(COLOR_RESET);
            Sleep(1500);
            continue;
        }

        switch (choice) {
            case 1:
                run_hash_mode();
                break;
            case 2:
                run_cracker_mode();
                break;
            case 0:
                return;
        }
    }
}

void run_hash_mode(void) {
    char input[MAX_INPUT_LEN + 1] = {0};
    set_color(COLOR_YELLOW);
    safe_input("Enter a string to hash (no spaces, max 255 chars): ", input, sizeof(input));
    set_color(COLOR_RESET);

    // Strict: check for valid password
    if (!is_valid_password(input)) {
        set_color(COLOR_RED);
        printf("\n[ERROR] Invalid password string. Must be 1-255 visible chars, no spaces.\n");
        set_color(COLOR_RESET);
        wait_for_enter();
        return;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("Error initializing hash context");
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        perror("Error computing hash");
        EVP_MD_CTX_free(ctx);
        return;
    }

    printf("MD5 Hash: ");
    for (unsigned int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    EVP_MD_CTX_free(ctx);
    wait_for_enter();
}

void run_cracker_mode(void) {
    char hash[40] = {0};
    set_color(COLOR_YELLOW);
    safe_input("Enter the MD5 hash to crack (32 lowercase hex chars): ", hash, sizeof(hash));
    set_color(COLOR_RESET);

    // Strict: Only accept exactly 32 lowercase hex
    if (!is_valid_md5_hash(hash)) {
        set_color(COLOR_RED);
        printf("\n[ERROR] Invalid MD5 hash. Must be exactly 32 lowercase hex characters.\n");
        set_color(COLOR_RESET);
        wait_for_enter();
        return;
    }

    const char *wordlist_path = "wordlist.txt";
    FILE *wordlist = fopen(wordlist_path, "r");
    if (!wordlist) {
        set_color(COLOR_RED);
        perror("[ERROR] Failed to open wordlist file");
        set_color(COLOR_RESET);
        wait_for_enter();
        return;
    }

    char word[MAX_INPUT_LEN + 4];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        set_color(COLOR_RED);
        perror("[ERROR] Failed to initialize hash context");
        set_color(COLOR_RESET);
        fclose(wordlist);
        wait_for_enter();
        return;
    }

    int found = 0;
    while (fgets(word, sizeof(word), wordlist)) {
        word[strcspn(word, "\r\n")] = '\0'; // Remove newline

        // Strict: Check valid candidate word from wordlist
        if (!is_valid_password(word)) continue;

        if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, word, strlen(word)) != 1 ||
            EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
            set_color(COLOR_RED);
            perror("[ERROR] Failed to compute hash");
            set_color(COLOR_RESET);
            continue;
        }

        char computed_hash[33];
        for (unsigned int i = 0; i < digest_len; i++)
            sprintf(&computed_hash[i * 2], "%02x", digest[i]);
        computed_hash[32] = '\0';

        if (strcmp(hash, computed_hash) == 0) {
            set_color(COLOR_GREEN);
            printf("\nMatch found: %s\n", word);
            set_color(COLOR_RESET);
            found = 1;
            break;
        }
    }

    if (!found) {
        set_color(COLOR_YELLOW);
        printf("\nNo match found.\n");
        set_color(COLOR_RESET);
    }

    EVP_MD_CTX_free(ctx);
    fclose(wordlist);
    wait_for_enter();
}
