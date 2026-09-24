#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>

#define THREADS 4
#define ITERS 10000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static long counter;
static int ready;
static __thread long tls;
static mach_port_t ports[THREADS];

static void *worker(void *arg) {
    long id = (long)arg;
    tls = id;
    ports[id] = pthread_mach_thread_np(pthread_self());

    pthread_mutex_lock(&lock);
    while (!ready) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void *)(tls * 10);
}

int main(void) {
    pthread_t threads[THREADS];
    for (long i = 0; i < THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)i);
    }
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);

    long sum = 0;
    for (int i = 0; i < THREADS; i++) {
        void *ret;
        pthread_join(threads[i], &ret);
        sum += (long)ret;
    }
    int distinct_ports = 1;
    for (int i = 0; i < THREADS; i++) {
        for (int j = i + 1; j < THREADS; j++) {
            distinct_ports &= ports[i] != ports[j] && ports[i] != MACH_PORT_NULL;
        }
    }
    printf("counter=%ld/%d joins=%ld/60 distinct_ports=%d\n", counter, THREADS * ITERS, sum,
           distinct_ports);
    return counter == THREADS * ITERS && sum == 60 && distinct_ports ? 0 : 1;
}
