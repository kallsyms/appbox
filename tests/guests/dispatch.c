#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ITEMS 100

static atomic_int done;

static void check(const char *what, long result) {
    printf("%s: %s\n", what, result ? "timed out" : "ok");
    fflush(stdout);
}

int main(void) {
    dispatch_queue_t global = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC);

    dispatch_async(global, ^{
        dispatch_semaphore_signal(sem);
    });
    check("dispatch_async", dispatch_semaphore_wait(sem, deadline));

    dispatch_group_t group = dispatch_group_create();
    for (int i = 0; i < ITEMS; i++) {
        dispatch_group_async(group, global, ^{
            atomic_fetch_add(&done, 1);
        });
    }
    long waited = dispatch_group_wait(group, deadline);
    printf("group: %d/%d\n", atomic_load(&done), ITEMS);
    check("dispatch_group", waited);

    dispatch_queue_t serial = dispatch_queue_create("appbox.serial", NULL);
    __block int order = 0, in_order = 1;
    for (int i = 0; i < 10; i++) {
        dispatch_async(serial, ^{
            in_order &= order++ == i;
        });
    }
    dispatch_sync(serial, ^{});
    printf("serial order: %s\n", in_order && order == 10 ? "ok" : "wrong");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC), global, ^{
        dispatch_semaphore_signal(sem);
    });
    check("dispatch_after", dispatch_semaphore_wait(sem, deadline));

    __block int ticks = 0;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, serial);
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 5 * NSEC_PER_MSEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        if (++ticks == 3) {
            dispatch_source_cancel(timer);
            dispatch_semaphore_signal(sem);
        }
    });
    dispatch_resume(timer);
    check("timer source", dispatch_semaphore_wait(sem, deadline));

    int fds[2];
    pipe(fds);
    int read_fd = fds[0];
    dispatch_source_t reader =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fds[0], 0, serial);
    __block char got = 0;
    dispatch_source_set_event_handler(reader, ^{
        read(read_fd, &got, 1);
        dispatch_source_cancel(reader);
        dispatch_semaphore_signal(sem);
    });
    dispatch_resume(reader);
    write(fds[1], "x", 1);
    check("read source", dispatch_semaphore_wait(sem, deadline));
    printf("read: %c\n", got);

    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    dispatch_source_t receiver =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0, serial);
    __block mach_msg_id_t received_id = 0;
    dispatch_source_set_event_handler(receiver, ^{
        struct {
            mach_msg_header_t header;
            mach_msg_trailer_t trailer;
        } message;
        if (mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message), port,
                     0, MACH_PORT_NULL) == KERN_SUCCESS) {
            received_id = message.header.msgh_id;
        }
        dispatch_source_cancel(receiver);
        dispatch_semaphore_signal(sem);
    });
    dispatch_resume(receiver);
    mach_msg_header_t message = {
        .msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0),
        .msgh_size = sizeof(message),
        .msgh_remote_port = port,
        .msgh_id = 1234,
    };
    mach_msg(&message, MACH_SEND_MSG, sizeof(message), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    check("mach receive source", dispatch_semaphore_wait(sem, deadline));
    printf("mach message id: %d\n", received_id);

    dispatch_async(dispatch_get_main_queue(), ^{
        printf("main queue: ok\n");
        fflush(stdout);
        exit(0);
    });
    dispatch_main();
}
