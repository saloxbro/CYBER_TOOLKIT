#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

#include <windows.h> // For WORD type

void dns_lookup_menu(void);
void print_dns_banner(void);
int is_valid_domain(const char *domain);
int perform_dns_query(const char *domain, WORD record_type, char *output, int *records_added);
void log_dns_results(const char *domain, const char *output);

#endif // DNS_LOOKUP_H
