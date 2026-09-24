#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    if (!strcmp(argv[1], "trap")) {
        __builtin_trap();
    } else if (!strcmp(argv[1], "segv")) {
        *(volatile int *)8 = 1;
    } else if (!strcmp(argv[1], "abort")) {
        abort();
    }
    return 3;
}
