from bcc import BPF
from ctypes import *
import sys

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128

# =======================
# Python-side structures
# =======================

class ExecEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("uid", c_uint),
        ("syscall", c_uint),   # 1=execve, 2=execveat
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]

class ForkEvent(Structure):
    _fields_ = [
        ("parent_pid", c_uint),
        ("child_pid", c_uint),
        ("uid", c_uint),
        ("type", c_uint),  # 1=fork, 2=vfork, 3=clone
    ]


# =======================
# eBPF program
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGS 20
#define ARG_LEN 128

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 syscall;
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};

struct fork_event_t {
    u32 parent_pid;
    u32 child_pid;
    u32 uid;
    u32 type;
};

BPF_PERCPU_ARRAY(exec_storage, struct exec_event_t, 1);
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(fork_events);

/* =======================
 * execve
 * ======================= */
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->syscall = 1;
    e->argc = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = task->real_parent->tgid;

    e->uid = bpf_get_current_uid_gid();
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

    e->syscall = 2;
    e->argc = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = task->real_parent->tgid;

    e->uid = bpf_get_current_uid_gid();
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
    e.parent_pid = bpf_get_current_pid_tgid() >> 32;
    e.child_pid = ctx->ret;
    e.uid = bpf_get_current_uid_gid();
    e.type = 1;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_vfork_exit(struct tracepoint__syscalls__sys_exit_vfork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.parent_pid = bpf_get_current_pid_tgid() >> 32;
    e.child_pid = ctx->ret;
    e.uid = bpf_get_current_uid_gid();
    e.type = 2;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone_exit(struct tracepoint__syscalls__sys_exit_clone *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.parent_pid = bpf_get_current_pid_tgid() >> 32;
    e.child_pid = ctx->ret;
    e.uid = bpf_get_current_uid_gid();
    e.type = 3;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone3_exit(struct tracepoint__syscalls__sys_exit_clone3 *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.parent_pid = bpf_get_current_pid_tgid() >> 32;
    e.child_pid = ctx->ret;
    e.uid = bpf_get_current_uid_gid();
    e.type = 4;

    fork_events.perf_submit(ctx, &e, sizeof(e));
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

print("Tracing provenance (fork/vfork/clone + execve)... Ctrl-C to stop.\n")

# =======================
# Event handlers
# =======================

def handle_exec(cpu, data, size):
    print("enter exec")
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

    print(f"[EXEC] {syscall}")
    print(f"  PID={e.pid} PPID={e.ppid} UID={e.uid}")
    print(f"  COMM={e.comm.decode(errors='replace').strip(chr(0))}")
    print(f"  CMD={cmdline}")
    print()

def handle_fork(cpu, data, size):
    print("enter fork")
    e = cast(data, POINTER(ForkEvent)).contents
    t = {1:"fork", 2:"vfork", 3:"clone", 4:"clone3"}[e.type]
    print(f"[{t.upper()}] {e.parent_pid} -> {e.child_pid}")

b["exec_events"].open_perf_buffer(handle_exec)
b["fork_events"].open_perf_buffer(handle_fork)

# =======================
# Main loop
# =======================

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
