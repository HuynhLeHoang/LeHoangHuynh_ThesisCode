from bcc import BPF
from ctypes import *

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define __NR_setuid        105
#define __NR_setgid        106
#define __NR_setreuid     113
#define __NR_setregid     114
#define __NR_setresuid   117
#define __NR_setresgid   119
#define __NR_capset      126

struct event_t {
    u32 pid;
    u32 uid;
    u32 syscall;
    u64 arg0;
    u64 arg1;
    u64 arg2;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u32 id = args->id;

    if (id != __NR_setuid &&
        id != __NR_setgid &&
        id != __NR_setreuid &&
        id != __NR_setregid &&
        id != __NR_setresuid &&
        id != __NR_setresgid &&
        id != __NR_capset)
        return 0;

    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();
    e.syscall = id;
    e.arg0 = args->args[0];
    e.arg1 = args->args[1];
    e.arg2 = args->args[2];

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

class Event(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("syscall", c_uint),
        ("arg0", c_ulonglong),
        ("arg1", c_ulonglong),
        ("arg2", c_ulonglong),
    ]

syscall_names = {
    105: "setuid",
    106: "setgid",
    113: "setreuid",
    114: "setregid",
    117: "setresuid",
    119: "setresgid",
    126: "capset",
}

def print_event(cpu, data, size):
    e = cast(data, POINTER(Event)).contents
    name = syscall_names.get(e.syscall, "unknown")
    print(f"[PID {e.pid}] UID={e.uid} syscall={name}({e.arg0}, {e.arg1}, {e.arg2})")

b = BPF(text=bpf_program)
b["events"].open_perf_buffer(print_event)

print("Tracing setuid/setgid/capset syscalls... Ctrl-C to stop.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

