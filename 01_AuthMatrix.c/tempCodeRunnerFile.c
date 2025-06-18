MAX_OUTPUT_SIZE) {
                strcat(output_buffer, line_buffer);
                (*records_added)++;
            }
        }
    }
    DnsRecordListFree(pResult, DnsFreeRecordList);
    return ERROR_SUCCESS;
}

void dns_lookup_menu(void) {
    char domain[256] = "";
    char output[MAX_OUTPUT_SIZE