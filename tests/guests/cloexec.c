#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *names[] = {"O_CLOEXEC", "plain", "FD_CLOEXEC set", "pipe", "F_DUPFD_CLOEXEC"};
#define COUNT 5

int main(int argc, char **argv) {
    if (argc == COUNT + 2 && !strcmp(argv[1], "check")) {
        for (int i = 0; i < COUNT; i++) {
            int fd = atoi(argv[i + 2]);
            printf("%s: %s\n", names[i], fcntl(fd, F_GETFD) < 0 ? "closed" : "open");
        }
        return 0;
    }

    int pipe_fds[2];
    pipe(pipe_fds);
    fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
    int fds[COUNT] = {
        open("/dev/null", O_RDONLY | O_CLOEXEC),
        open("/dev/null", O_RDONLY),
        pipe_fds[0],
        pipe_fds[1],
        fcntl(pipe_fds[1], F_DUPFD_CLOEXEC, 0),
    };
    char args[COUNT][16];
    char *exec_argv[COUNT + 3] = {argv[0], "check"};
    for (int i = 0; i < COUNT; i++) {
        snprintf(args[i], sizeof(args[i]), "%d", fds[i]);
        exec_argv[i + 2] = args[i];
    }
    execv(argv[0], exec_argv);
    perror("execv");
    return 1;
}
