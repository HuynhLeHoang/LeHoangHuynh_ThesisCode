#!/usr/bin/env python3
from bcc import BPF
from ctypes import *

TASK_COMM_LEN = 16
PATH_LEN = 256

EDGE_OPEN   = 1
EDGE_READ   = 2
EDGE_WRITE  = 3
EDGE_EXEC   = 4
EDGE_DELETE = 5

class FileEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("edge", c_uint),
        ("inode", c_ulonglong),
        ("dev", c_uint),
        ("ts", c_ulonglong),
        ("comm", c_char * TASK_COMM_LEN),
        ("path", c_char * PATH_LEN),
    ]

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/stat.h>

#define PATH_LEN 256

enum file_edge_t {
    EDGE_OPEN   = 1,
    EDGE_READ   = 2,
    EDGE_WRITE  = 3,
    EDGE_EXEC   = 4,
    EDGE_DELETE = 5,
};

struct file_event_t {
    u32 pid;
    u32 uid;
    u32 edge;
    u64 inode;
    u32 dev;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
};

BPF_PERF_OUTPUT(file_events);

static __always_inline void submit_file(
    void *ctx,
    struct file *file,
    const char *path,
    u32 edge)
{
    struct inode *inode = NULL;
    umode_t mode = 0;

    if (!file)
        return;

    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return;

    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    if (!S_ISREG(mode))
        return;

    struct file_event_t e = {};

    e.pid   = bpf_get_current_pid_tgid() >> 32;
    e.uid   = bpf_get_current_uid_gid();
    e.edge  = edge;
    u64 ino = 0;
    dev_t dev = 0;
    struct super_block *sb = NULL;

    bpf_probe_read(&ino, sizeof(ino), &inode->i_ino);
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (sb)
        bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);

    e.inode = ino;
    e.dev   = dev;
    e.ts    = bpf_ktime_get_ns();

    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    if (path)
        bpf_probe_read_user_str(e.path, sizeof(e.path), path);

    file_events.perf_submit(ctx, &e, sizeof(e));
}

/* ========= OPEN / CREATE ========= */
int trace_security_file_open(struct pt_regs *ctx, struct file *file)
{
    submit_file(ctx, file, NULL, EDGE_OPEN);
    return 0;
}

/* ========= READ ========= */
int trace_vfs_read(struct pt_regs *ctx, struct file *file)
{
    submit_file(ctx, file, NULL, EDGE_READ);
    return 0;
}

/* ========= WRITE ========= */
int trace_vfs_write(struct pt_regs *ctx, struct file *file)
{
    submit_file(ctx, file, NULL, EDGE_WRITE);
    return 0;
}

/* ========= EXEC ========= */
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    struct file_event_t e = {};

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.uid  = bpf_get_current_uid_gid();
    e.edge = EDGE_EXEC;
    e.ts   = bpf_ktime_get_ns();

    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), ctx->filename);

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ========= DELETE ========= */
int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *ctx)
{
    struct file_event_t e = {};

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.uid  = bpf_get_current_uid_gid();
    e.edge = EDGE_DELETE;
    e.ts   = bpf_ktime_get_ns();

    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), ctx->pathname);

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

b = BPF(text=program)

b.attach_kprobe(event="security_file_open", fn_name="trace_security_file_open")
b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")

b.attach_tracepoint("syscalls:sys_enter_execve", "trace_execve")
b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")

print("Tracing file provenance events... Ctrl-C to stop.")

def print_event(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents
    edge = {
        EDGE_OPEN: "OPEN",
        EDGE_READ: "READ",
        EDGE_WRITE: "WRITE",
        EDGE_EXEC: "EXEC",
        EDGE_DELETE: "DELETE"
    }.get(e.edge, "?")

    print(f"[{edge}] pid={e.pid} uid={e.uid} "
          f"inode={e.inode} dev={e.dev} "
          f"path={e.path.decode(errors='ignore')} "
          f"comm={e.comm.decode(errors='ignore')}")

b["file_events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
