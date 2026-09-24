#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void handler(int sig) { (void)sig; }

int main(void) {
    struct sigaction sa = {0}, old;
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR1, NULL, &old);
    printf("handler readback: %s\n",
           old.sa_handler == handler && old.sa_flags == SA_RESTART ? "ok" : "WRONG");

    signal(SIGPIPE, SIG_IGN);
    int fds[2];
    pipe(fds);
    close(fds[0]);
    ssize_t written = write(fds[1], "x", 1);
    printf("write to closed pipe: %s\n", written < 0 && errno == EPIPE ? "EPIPE ok" : "WRONG");

    printf("catch SIGKILL: %s\n",
           sigaction(SIGKILL, &sa, NULL) == -1 && errno == EINVAL ? "EINVAL ok" : "WRONG");
    return 0;
}
