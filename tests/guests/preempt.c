#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

static atomic_int ready;
static atomic_long spins;

static void *worker(void *arg) {
    (void)arg;
    atomic_store(&ready, 1);
    return NULL;
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker, NULL);
    // No syscalls in here, so only preemption lets the worker run.
    while (!atomic_load(&ready)) {
        atomic_fetch_add_explicit(&spins, 1, memory_order_relaxed);
    }
    pthread_join(thread, NULL);
    printf("worker ran while main spun: %s\n", atomic_load(&spins) > 0 ? "yes" : "no");
    return 0;
}
