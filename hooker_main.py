from bcc import BPF
from ctypes import *
import sys

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128

# =======================
# Python-side structures
# =======================

class ProcAttr(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("euid", c_uint),
        ("egid", c_uint),
        ("ts", c_ulonglong),
    ]


class ExecEvent(Structure):
    _fields_ = [
        ("attr", ProcAttr),
        ("syscall", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]

class ForkEvent(Structure):
    _fields_ = [
        ("parent", ProcAttr),
        ("child_pid", c_uint),
        ("type", c_uint),
    ]

# =======================
# eBPF program
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGS 20
#define ARG_LEN 128

//basic attribute for a node
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


BPF_PERCPU_ARRAY(exec_storage, struct exec_event_t, 1);
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(fork_events);

//helper for credential
static __always_inline void fill_proc_attr(struct proc_attr_t *a)
{
    struct task_struct *task;

    a->pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    a->ppid = task->real_parent->tgid;

    u64 uidgid = bpf_get_current_uid_gid();
    a->euid = uidgid & 0xffffffff;
    a->egid = uidgid >> 32;

    a->ts = bpf_ktime_get_ns();
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

    fill_proc_attr(&e->attr);

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

    fill_proc_attr(&e->attr);

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
    fill_proc_attr(&e.parent);
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
    fill_proc_attr(&e.parent);
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
    fill_proc_attr(&e.parent);
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
    fill_proc_attr(&e.parent);
    e.child_pid = ctx->ret;

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
# Save node to provenance tree
# =======================

def provstorage(outputstr):
    with open('Provenance.log', 'a') as f:
        f.write(outputstr)
        f.write('\n')

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
    outputstr = "EXEC" + "|" + str(syscall) + "|" + str(e.attr.ts) + "|" + str(e.attr.pid) + "|" + str(e.attr.ppid) + "|" + str(e.attr.euid) + "|" + str(e.comm.decode(errors='replace').strip(chr(0))) + "|" + str(cmdline)
    print(outputstr)
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
    print(outputstr)
    provstorage(outputstr)
    #print(f"[{t.upper()}] {e.parent.pid} -> {e.child_pid}")
    #print(f"  TIMESTAMP={e.parent.ts}")


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
