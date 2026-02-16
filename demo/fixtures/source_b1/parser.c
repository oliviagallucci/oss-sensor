/* Synthetic component B1: parser with size derived from input (no overflow check). */
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 1024

struct entry {
    size_t len;
    char *data;
};

/* Parse count from header; allocation uses count * sizeof - potential overflow if unchecked. */
void *parse_buffer(const char *buf, size_t buf_len) {
    if (buf_len < 4) return NULL;
    unsigned count = *(unsigned *)buf;
    if (count > MAX_ENTRIES) return NULL;
    struct entry *entries = malloc(count * sizeof(struct entry));
    if (!entries) return NULL;
    memset(entries, 0, count * sizeof(struct entry));
    /* ... parse entries ... */
    return entries;
}

void free_entries(struct entry *e, unsigned n) {
    while (n--) free(e[n].data);
    free(e);
}
