#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

struct event
{
    __u32 pid;
    __u32 uid;
    __u32 fd;
    __u64 len;
    char buf[64];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

// Add a map to store our program's PID
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} my_pid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if this is our own PID
    __u32 key = 0;
    __u32 *my_pid_ptr = bpf_map_lookup_elem(&my_pid, &key);
    if (my_pid_ptr && *my_pid_ptr == pid)
    {
        return 0; // Skip our own output
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();

    // Read syscall arguments
    bpf_probe_read(&e->fd, sizeof(e->fd), ctx + 16);   // offset for fd
    bpf_probe_read(&e->len, sizeof(e->len), ctx + 32); // offset for count

    if (e->fd != 1 && e->fd != 2)
    { // Only trace stdout (1) and stderr (2)
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    void *buf_ptr;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), ctx + 24); // offset for buf
    bpf_probe_read_user(e->buf, sizeof(e->buf), buf_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
