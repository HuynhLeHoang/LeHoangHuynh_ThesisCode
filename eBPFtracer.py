from bcc import BPF
from ctypes import *
import sys
from queue import Queue
from threading import Thread
import time
event_queue = Queue(maxsize=1000000)
running = True

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128
PATH_LEN = 256

EDGE_OPEN   = 1
EDGE_READ   = 2
EDGE_WRITE  = 3
EDGE_EXEC   = 4
EDGE_DELETE = 5

# =======================
# Python-side structures
# =======================

#basic attributes
class ProcAttr(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("euid", c_uint),
        ("egid", c_uint),
        ("ts", c_ulonglong),
    ]

#extension attributes for Execve like Event
class ExecEvent(Structure):
    _fields_ = [
        ("attr", ProcAttr),
        ("syscall", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]

#extension attributes for Fork like Event
class ForkEvent(Structure):
    _fields_ = [
        ("parent", ProcAttr),
        ("child_pid", c_uint),
        ("type", c_uint),
    ]

#attributes for File-Node event
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
# =======================
# eBPF program
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>

#define PATH_LEN 256
#define TASK_COMM_LEN 16

enum file_edge_t {
    EDGE_OPEN   = 1,
    EDGE_READ   = 2,
    EDGE_WRITE  = 3,
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

/* ========= MAPS ========= */

/* perf output */
BPF_PERF_OUTPUT(file_events);

/* cache: file* -> path */
BPF_HASH(file_path_cache, u64, char[PATH_LEN]);

/* ========= HELPERS ========= */

static __always_inline int fill_file_event(
    struct file_event_t *e,
    struct file *file,
    u32 edge)
{
    struct inode *inode = NULL;
    struct super_block *sb = NULL;
    umode_t mode = 0;

    if (!file)
        return -1;

    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return -1;

    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    if (!S_ISREG(mode))
        return -1;

    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->uid  = bpf_get_current_uid_gid();
    e->edge = edge;
    e->ts   = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read(&e->inode, sizeof(e->inode), &inode->i_ino);

    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (sb)
        bpf_probe_read(&e->dev, sizeof(e->dev), &sb->s_dev);

    return 0;
}

/* ========= OPEN ========= */

int trace_security_file_open(struct pt_regs *ctx, struct file *file)
{
    struct file_event_t e = {};
    char path[PATH_LEN];
    u64 key;

    if (fill_file_event(&e, file, EDGE_OPEN) < 0)
        return 0;

    /* resolve path */
    if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0)
        return 0;

    __builtin_memcpy(e.path, path, sizeof(e.path));

    /* cache path */
    key = (u64)file;
    file_path_cache.update(&key, &path);

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ========= READ ========= */

int trace_vfs_read(struct pt_regs *ctx, struct file *file)
{
    struct file_event_t e = {};
    u64 key;
    char *path;

    if (fill_file_event(&e, file, EDGE_READ) < 0)
        return 0;

    key = (u64)file;
    path = file_path_cache.lookup(&key);
    if (path)
        __builtin_memcpy(e.path, path, sizeof(e.path));

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ========= WRITE ========= */

int trace_vfs_write(struct pt_regs *ctx, struct file *file)
{
    struct file_event_t e = {};
    u64 key;
    char *path;

    if (fill_file_event(&e, file, EDGE_WRITE) < 0)
        return 0;

    key = (u64)file;
    path = file_path_cache.lookup(&key);
    if (path)
        __builtin_memcpy(e.path, path, sizeof(e.path));

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

/* ========= CLOSE ========= */

int trace_security_file_free(struct pt_regs *ctx, struct file *file)
{
    u64 key = (u64)file;
    file_path_cache.delete(&key);
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

# =======================
# Load BPF
# =======================

b = BPF(text=program)

b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
b.attach_tracepoint(tp="syscalls:sys_enter_execveat", fn_name="trace_execveat")
b.attach_tracepoint(tp="syscalls:sys_exit_fork", fn_name="trace_fork_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_vfork", fn_name="trace_vfork_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_clone", fn_name="trace_clone_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_clone3", fn_name="trace_clone3_exit")
b.attach_kprobe(event="security_file_open", fn_name="trace_security_file_open")
b.attach_kprobe(event="vfs_read", fn_name="trace_vfs_read")
b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
b.attach_tracepoint("syscalls:sys_enter_execve", "trace_execve")
b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")

print("Tracing provenance ... Ctrl-C to stop.\n")

# =======================
# Save node to provenance tree
# =======================

def writer_thread():
    with open("Provenance.log", "a") as f:
        while running or not event_queue.empty():
            try:
                line = event_queue.get(timeout=0.5)
                f.write(line + "\n")
                event_queue.task_done()
            except:
                pass

def provstorage(outputstr):
    try:
        event_queue.put_nowait(outputstr)
    except:
        # queue đầy → bỏ event (chấp nhận được)
        pass

# =======================
# Event handlers
# =======================

def handle_exec(cpu, data, size):
    e = cast(data, POINTER(ExecEvent)).contents
    if e.argc == 0:
        return

    argv0 = e.argv[0].value
#    if argv0 not in (b"sudo", b"/usr/bin/sudo"):
#       return

    syscall = "execve" if e.syscall == 1 else "execveat"

    cmdline = " ".join(
        e.argv[i].value.decode(errors="replace")
        for i in range(e.argc)
    )
    outputstr = "EXEC" + "|" + str(syscall) + "|" + str(e.attr.ts) + "|" + str(e.attr.pid) + "|" + str(e.attr.ppid) + "|" + str(e.attr.euid) + "|" + str(e.comm.decode(errors='replace').strip(chr(0))) + "|" + str(cmdline)
    #print(outputstr)
    provstorage(outputstr)
    #print(f"[EXEC] {syscall}")
    #print(f"  TIMESTAMP={e.attr.ts}")
    #print(f"  PID={e.attr.pid} PPID={e.attr.ppid} EUID={e.attr.euid}")
    #print(f"  COMM={e.comm.decode(errors='replace').strip(chr(0))}")
    #print(f"  CMD={cmdline}")

def handle_fork(cpu, data, size):
    e = cast(data, POINTER(ForkEvent)).contents
    t = {1:"fork", 2:"vfork", 3:"clone", 4:"clone3"}[e.type]
    outputstr = str(t.upper()) + "|" + str(e.child_pid) + "|" + str(e.parent.pid) + "|" + str(e.parent.ts)
    #print(outputstr)
    provstorage(outputstr)
    #print(f"[{t.upper()}] {e.parent.pid} -> {e.child_pid}")
    #print(f"  TIMESTAMP={e.parent.ts}")

def handle_file(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents
    edge = {
        EDGE_OPEN: "OPEN",
        EDGE_READ: "READ",
        EDGE_WRITE: "WRITE",
        EDGE_EXEC: "EXEC",
        EDGE_DELETE: "DELETE"
    }.get(e.edge, "?")
    outputstr = str(edge) + "|" + str(e.uid) + "|" + str(e.pid) + "|" + str(e.dev) + "|" + str(e.path.decode(errors='ignore')) + "|" + str(e.comm.decode(errors='ignore'))
    #print(outputstr)
    if "python3" not in e.comm.decode(errors='ignore'):
        provstorage(outputstr)
    #print(f"[{edge}] pid={e.pid} uid={e.uid} "
    #      f"inode={e.inode} dev={e.dev} "
    #      f"path={e.path.decode(errors='ignore')} "
    #      f"comm={e.comm.decode(errors='ignore')}")


b["exec_events"].open_perf_buffer(handle_exec)
b["fork_events"].open_perf_buffer(handle_fork)
b["file_events"].open_perf_buffer(handle_file, page_cnt=64)

# =======================
# Main loop
# =======================

t = Thread(target=writer_thread, daemon=True)
t.start()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        running = False
        event_queue.join()
        print("Stopping tracer...")
