#include "heap.h"
#include <stdint.h>

int main() {
    quak_heap_init();

    char *ex = quak_malloc(sizeof(char));
    uint64_t *int_ex = quak_malloc(sizeof(uint64_t));

    quak_free(ex);
    quak_free(int_ex);

    return 0;
}
