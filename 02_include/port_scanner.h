#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <stddef.h> // For size_t
#include <stdio.h>  // For FILE

// This declares the main function for the port scanner,
// making it available to other parts of our toolkit.
void port_scanner_menu(void);
int resolve_hostname(const char *hostname, char *ip, size_t ip_size);
void scan_ports(const char *target_ip, const int *ports, int num_ports, FILE *out);

#endif // PORT_SCANNER_H