#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

struct event {
    __u32 pid;
    __u32 fd;
    __u64 len;
    char buf[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(void *ctx)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;

    // Read syscall arguments
    bpf_probe_read(&e->fd, sizeof(e->fd), ctx + 16);  // offset for fd
    bpf_probe_read(&e->len, sizeof(e->len), ctx + 32);  // offset for count

    if (e->fd != 1 && e->fd != 2) {  // Only trace stdout (1) and stderr (2)
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    void *buf_ptr;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), ctx + 24);  // offset for buf
    bpf_probe_read_user(e->buf, sizeof(e->buf), buf_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
