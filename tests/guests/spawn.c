#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
extern char **environ;

static int run(const char *path, char *const argv[]) {
    pid_t pid;
    int err = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (err) {
        printf("posix_spawn(%s) failed: %d\n", path, err);
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(void) {
    char *echo[] = {"echo", "child says hi", NULL};
    char *f[] = {"false", NULL};
    printf("echo exited %d\n", run("/bin/echo", echo));
    printf("false exited %d\n", run("/usr/bin/false", f));
    fflush(stdout);
    return 3;
}
