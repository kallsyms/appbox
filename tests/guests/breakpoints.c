// Calls add_one a few times, for a debugger to stop at.
#include <stdio.h>

volatile int start;

__attribute__((noinline)) int add_one(int x) {
    return x + 1;
}

int main(void) {
    int value = start;
    for (int i = 0; i < 3; i++) {
        value = add_one(value);
    }
    printf("value=%d\n", value);
    return 0;
}
