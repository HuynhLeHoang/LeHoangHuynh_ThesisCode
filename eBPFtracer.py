from bcc import BPF
from ctypes import *
from queue import Queue
from threading import Thread
import time


TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128
PATH_LEN = 256

EDGE_CREATE   = 1
EDGE_ATTR   = 2
EDGE_EXEC  = 3

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
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define PATH_LEN 256
#define MAX_ARGS 20
#define ARG_LEN 128

//system process ID 
#define MIN_PID 1000
//bit rate 
#define RATE_LIMIT_NS 100000000
BPF_HASH(rate_limiter, u32, u64, 10240);

//basic attribute for a process node
struct proc_attr_t {
    u32 pid;
    u32 ppid;
    u32 euid;
    u32 egid;
    u64 ts;
};
struct exec_event_t {
    struct proc_attr_t attr;

    u32 syscall;    // 1=execve, 2=execveat
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};
struct fork_event_t {
    struct proc_attr_t parent;
    u32 child_pid;
    u32 type;   // fork/vfork/clone/clone3
};

//basic attribute for a file node
enum file_edge_t {
    EDGE_CREATE = 1,
    EDGE_ATTR   = 2,
    EDGE_EXEC   = 3,
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

BPF_PERCPU_ARRAY(exec_storage, struct exec_event_t, 1);
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(fork_events);
BPF_PERF_OUTPUT(file_events);
struct open_info_t {
    char path[PATH_LEN];
    int flags;
};

BPF_HASH(open_map, u32, struct open_info_t);
BPF_PERCPU_ARRAY(file_storage, struct file_event_t, 1);
/* =========== Function definition area for process node ==============*/



//helper for credential
static __always_inline int fill_proc_attr(struct proc_attr_t *a)
{
    struct task_struct *task;

    a->pid = bpf_get_current_pid_tgid() >> 32;
    //system process filter apply
    if (a->pid < MIN_PID){
        return 1;
    }
    //rate limit apply
    u64 now = bpf_ktime_get_ns();
    u32 pid = a->pid;
    u64 *last_time = rate_limiter.lookup(&pid);
    
    if (last_time && (now - *last_time) < RATE_LIMIT_NS) {
        return 1;
    }
    rate_limiter.update(&pid, &now);

    task = (struct task_struct *)bpf_get_current_task();
    a->ppid = task->real_parent->tgid;

    u64 uidgid = bpf_get_current_uid_gid();
    a->euid = uidgid & 0xffffffff;
    a->egid = uidgid >> 32;

    a->ts = bpf_ktime_get_ns();
    return 0;
}

/* =======================
 * execve
 * ======================= */
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if(fill_proc_attr(&e->attr)){
        return 0;
    }

    e->syscall = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->argv[i], ARG_LEN, argp);
        e->argc = i + 1;
    }

    exec_events.perf_submit(ctx, e, sizeof(*e));
    return 0;
}

/* =======================
 * execveat
 * ======================= */
int trace_execveat(struct tracepoint__syscalls__sys_enter_execveat *ctx)
{
    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if(fill_proc_attr(&e->attr)){
        return 0;
    }

    e->syscall = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->argv[i], ARG_LEN, argp);
        e->argc = i + 1;
    }

    exec_events.perf_submit(ctx, e, sizeof(*e));
    return 0;
}

/* =======================
 * fork / vfork / clone / clone3
 * ======================= */

int trace_fork_exit(struct tracepoint__syscalls__sys_exit_fork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 1;
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    
    e.child_pid = ctx->ret;
    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_vfork_exit(struct tracepoint__syscalls__sys_exit_vfork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 2;
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    e.child_pid = ctx->ret;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone_exit(struct tracepoint__syscalls__sys_exit_clone *ctx)
{

    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 3;
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    e.child_pid = ctx->ret;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone3_exit(struct tracepoint__syscalls__sys_exit_clone3 *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 4;
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    e.child_pid = ctx->ret;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < MIN_PID)
        return 0;

    struct open_info_t info = {};
    info.flags = args->flags;

    bpf_probe_read_user_str(info.path, sizeof(info.path),
                            args->filename);

    open_map.update(&pid, &info);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < MIN_PID)
        return 0;

    int ret = args->ret;
    if (ret < 0)
        goto cleanup;

    struct open_info_t *info;
    info = open_map.lookup(&pid);
    if (!info)
        return 0;

    if (!(info->flags & O_CREAT))
        goto cleanup;

    int zero = 0;
    struct file_event_t *e = file_storage.lookup(&zero);
    if (!e)
        goto cleanup;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();
    e->edge = EDGE_CREATE;
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(&e->path, info->path, sizeof(e->path));

    file_events.perf_submit(args, e, sizeof(*e));

cleanup:
    open_map.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat)
{
    struct file_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    if (e.pid < MIN_PID) return 0;

    e.uid = bpf_get_current_uid_gid();
    e.edge = EDGE_ATTR;
    e.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), args->filename);

    file_events.perf_submit(args, &e, sizeof(e));
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

print("Tracing provenance ... Ctrl-C to stop.\n")

# =======================
# Save node to provenance tree
# =======================


def provstorage(outputstr):

    with open("Provenance.log", "a") as f:
        f.write(outputstr + "\n")

# =======================
# Event handlers
# =======================

def handle_exec(cpu, data, size):
    e = cast(data, POINTER(ExecEvent)).contents
    if e.argc == 0:
        return

    argv0 = e.argv[0].value


    syscall = "execve" if e.syscall == 1 else "execveat"

    cmdline = " ".join(
        e.argv[i].value.decode(errors="replace")
        for i in range(e.argc)
    )
    outputstr = "EXEC" + "|" + str(syscall) + "|" + str(e.attr.ts) + "|" + str(e.attr.pid) + "|" + str(e.attr.ppid) + "|" + str(e.attr.euid) + "|" + str(e.comm.decode(errors='replace').strip(chr(0))) + "|" + str(cmdline)

    provstorage(outputstr)


def handle_fork(cpu, data, size):
    e = cast(data, POINTER(ForkEvent)).contents
    t = {1:"fork", 2:"vfork", 3:"clone", 4:"clone3"}[e.type]
    outputstr = str(t.upper()) + "|" + str(e.child_pid) + "|" + str(e.parent.pid) + "|" + str(e.parent.ts)

    provstorage(outputstr)



def handle_file(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents
    edge = {
        EDGE_CREATE: "FILE_CREATE",
        EDGE_ATTR: "ATTR",
        EDGE_EXEC: "EXEC"
    }.get(e.edge, "?")
    outputstr = str(edge) + "|" + str(e.uid) + "|" + str(e.pid) + "|" + str(e.inode) + "|" + str(e.dev) + "|" + str(e.path.decode(errors='ignore')) + "|" + str(e.comm.decode(errors='ignore'))
    #print(outputstr)
    if ("python3" not in e.comm.decode(errors='ignore')) and ("/dev/shm" not in outputstr):
        provstorage(outputstr)



b["exec_events"].open_perf_buffer(handle_exec)
b["fork_events"].open_perf_buffer(handle_fork)
b["file_events"].open_perf_buffer(handle_file, page_cnt=64)

# =======================
# Main loop
# =======================


while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
        #running = False
        #event_queue.join()
        #print("Stopping tracer...")

