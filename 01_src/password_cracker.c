#include "password_cracker.h"
#include "common.h"
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// Remove `static` from these declarations
void run_hash_mode(void);
void run_cracker_mode(void);

// Helper: Check if string is a valid 32-char lowercase hex MD5 hash
static int is_valid_md5_hash(const char *s) {
    if (strlen(s) != 32) return 0;
    for (int i = 0; i < 32; ++i) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
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

        char choice_str[10];
        set_color(COLOR_YELLOW);
        safe_input("Selection > ", choice_str, sizeof(choice_str));
        set_color(COLOR_RESET);

        if (strlen(choice_str) == 1 && isdigit(choice_str[0])) {
            int choice = atoi(choice_str);
            switch (choice) {
                case 1:
                    run_hash_mode();
                    break;
                case 2:
                    run_cracker_mode();
                    break;
                case 0:
                    return;
                default:
                    set_color(COLOR_RED);
                    printf("\n[ERROR] Invalid selection. Please try again.");
                    set_color(COLOR_RESET);
                    Sleep(1500);
                    break;
            }
        }
    }
}

void run_hash_mode(void) {
    char input[256];
    printf("Enter a string to hash: ");
    safe_input("", input, sizeof(input));

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
    char hash[33];
    printf("Enter the MD5 hash to crack: ");
    safe_input("", hash, sizeof(hash));

    const char *wordlist_path = "wordlist.txt";

    FILE *wordlist = fopen(wordlist_path, "r");
    if (!wordlist) {
        set_color(COLOR_RED);
        perror("[ERROR] Failed to open wordlist file");
        set_color(COLOR_RESET);
        wait_for_enter();
        return;
    }

    char word[256];
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

    while (fgets(word, sizeof(word), wordlist)) {
        word[strcspn(word, "\r\n")] = '\0'; // Remove newline characters

        if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, word, strlen(word)) != 1 ||
            EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
            set_color(COLOR_RED);
            perror("[ERROR] Failed to compute hash");
            set_color(COLOR_RESET);
            continue;
        }

        char computed_hash[33];
        for (unsigned int i = 0; i < digest_len; i++) {
            sprintf(&computed_hash[i * 2], "%02x", digest[i]);
        }

        if (strcmp(hash, computed_hash) == 0) {
            set_color(COLOR_GREEN);
            printf("\nMatch found: %s\n", word);
            set_color(COLOR_RESET);
            EVP_MD_CTX_free(ctx);
            fclose(wordlist);
            wait_for_enter();
            return;
        }
    }

    set_color(COLOR_YELLOW);
    printf("\nNo match found.\n");
    set_color(COLOR_RESET);
    EVP_MD_CTX_free(ctx);
    fclose(wordlist);
    wait_for_enter();
}
