from bcc import BPF
from ctypes import *
import sys

TASK_COMM_LEN = 16

# =======================
# Python-side structure
# =======================

class PrivEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("uid", c_uint),
        ("syscall", c_uint),
        ("arg1", c_uint),
        ("ret", c_int),
        ("comm", c_char * TASK_COMM_LEN),
    ]

# =======================
# eBPF program
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define SYSCALL_SETUID     1
#define SYSCALL_SETREUID   2
#define SYSCALL_SETRESUID  3
#define SYSCALL_SETGID     4
#define SYSCALL_SETREGID   5
#define SYSCALL_SETRESGID  6
#define SYSCALL_CAPSET     7

struct priv_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 syscall;
    u32 arg1;
    int ret;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(tmp_arg, u32, u32);
BPF_PERF_OUTPUT(priv_events);

/* helpers */
static __always_inline u32 get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return task->real_parent->tgid;
}

/* =======================
 * ENTER
 * ======================= */

int enter_setuid(struct tracepoint__syscalls__sys_enter_setuid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->uid;
    tmp_arg.update(&pid, &v);
    return 0;
}

int enter_setreuid(struct tracepoint__syscalls__sys_enter_setreuid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->euid;
    tmp_arg.update(&pid, &v);
    return 0;
}

int enter_setresuid(struct tracepoint__syscalls__sys_enter_setresuid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->euid;
    tmp_arg.update(&pid, &v);
    return 0;
}


int enter_setgid(struct tracepoint__syscalls__sys_enter_setgid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->gid;
    tmp_arg.update(&pid, &v);
    return 0;
}

int enter_setregid(struct tracepoint__syscalls__sys_enter_setregid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->egid;
    tmp_arg.update(&pid, &v);
    return 0;
}

int enter_setresgid(struct tracepoint__syscalls__sys_enter_setresgid *ctx) {
    u32 pid = get_pid();
    u32 v = (u32)ctx->egid;
    tmp_arg.update(&pid, &v);
    return 0;
}

/* =======================
 * EXIT
 * ======================= */

int exit_setuid(struct tracepoint__syscalls__sys_exit_setuid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETUID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_setreuid(struct tracepoint__syscalls__sys_exit_setreuid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETREUID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_setresuid(struct tracepoint__syscalls__sys_exit_setresuid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETRESUID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_setgid(struct tracepoint__syscalls__sys_exit_setgid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETGID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_setregid(struct tracepoint__syscalls__sys_exit_setregid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETREGID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_setresgid(struct tracepoint__syscalls__sys_exit_setresgid *ctx) {
    if (ctx->ret != 0)
        goto cleanup;

    u32 pid = get_pid();
    u32 *arg = tmp_arg.lookup(&pid);
    if (!arg)
        goto cleanup;

    struct priv_event_t e = {};
    e.pid = pid;
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_SETRESGID;
    e.arg1 = *arg;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));

cleanup:
    tmp_arg.delete(&pid);
    return 0;
}

int exit_capset(struct tracepoint__syscalls__sys_exit_capset *ctx) {
    if (ctx->ret != 0)
        return 0;

    struct priv_event_t e = {};
    e.pid = get_pid();
    e.ppid = get_ppid();
    e.uid = bpf_get_current_uid_gid();
    e.syscall = SYSCALL_CAPSET;
    e.ret = ctx->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    priv_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# =======================
# Load & attach
# =======================

b = BPF(text=program)

b.attach_tracepoint("syscalls:sys_enter_setuid", "enter_setuid")
b.attach_tracepoint("syscalls:sys_exit_setuid",  "exit_setuid")

b.attach_tracepoint("syscalls:sys_enter_setreuid", "enter_setreuid")
b.attach_tracepoint("syscalls:sys_exit_setreuid",  "exit_setreuid")

b.attach_tracepoint("syscalls:sys_enter_setresuid", "enter_setresuid")
b.attach_tracepoint("syscalls:sys_exit_setresuid",  "exit_setresuid")

b.attach_tracepoint("syscalls:sys_enter_setgid", "enter_setgid")
b.attach_tracepoint("syscalls:sys_exit_setgid",  "exit_setgid")

b.attach_tracepoint("syscalls:sys_enter_setregid", "enter_setregid")
b.attach_tracepoint("syscalls:sys_exit_setregid",  "exit_setregid")

b.attach_tracepoint("syscalls:sys_enter_setresgid", "enter_setresgid")
b.attach_tracepoint("syscalls:sys_exit_setresgid",  "exit_setresgid")

b.attach_tracepoint("syscalls:sys_exit_capset", "exit_capset")

print("Tracing privilege-granting syscalls only... Ctrl-C to stop.\n")

# =======================
# Event handler
# =======================

SYSCALL_NAME = {
    1: "setuid",
    2: "setreuid",
    3: "setresuid",
    4: "setgid",
    5: "setregid",
    6: "setresgid",
    7: "capset",
}

def handle_priv(cpu, data, size):
    e = cast(data, POINTER(PrivEvent)).contents
    name = SYSCALL_NAME[e.syscall]
    print(f"[PRIV] {name}")
    print(f"  PID={e.pid} PPID={e.ppid} UID={e.uid}")
    if e.syscall != 7:
        print(f"  ARG={e.arg1}")
    print()

b["priv_events"].open_perf_buffer(handle_priv)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)
