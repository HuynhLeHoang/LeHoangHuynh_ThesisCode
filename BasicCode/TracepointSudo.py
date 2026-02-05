from bcc import BPF
from ctypes import *

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128

class Data(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("uid", c_uint),
        ("syscall", c_uint),   # 1=execve, 2=execveat
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* define maximun number of arguments */
#define MAX_ARGS 20
/* define maximun length of arguments */
#define ARG_LEN 128

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 syscall;   // 1=execve, 2=execveat
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};

BPF_PERCPU_ARRAY(data_storage, struct data_t, 1);
BPF_PERF_OUTPUT(events);

/* ===== execve ===== */
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *args)
{
    int zero = 0;
    struct data_t *data = data_storage.lookup(&zero);
    if (!data)
        return 0;

    data->syscall = 1;
    data->argc = 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &args->argv[i]);
        if (!argp)
            break;

        bpf_probe_read_user_str(data->argv[i], ARG_LEN, argp);
        data->argc = i + 1;
    }

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}

/* ===== execveat ===== */
int trace_execveat(struct tracepoint__syscalls__sys_enter_execveat *args)
{
    int zero = 0;
    struct data_t *data = data_storage.lookup(&zero);
    if (!data)
        return 0;

    data->syscall = 2;
    data->argc = 0;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &args->argv[i]);
        if (!argp)
            break;

        bpf_probe_read_user_str(data->argv[i], ARG_LEN, argp);
        data->argc = i + 1;
    }

    events.perf_submit(args, data, sizeof(*data));
    return 0;
}
"""

b = BPF(text=program)

# attach tracepoints (KHÔNG dùng kprobe)

b.attach_tracepoint(tp="syscalls:sys_enter_execve",
                    fn_name="trace_execve")

b.attach_tracepoint(tp="syscalls:sys_enter_execveat",
                    fn_name="trace_execveat")

print("Tracing sudo via tracepoints... Ctrl-C to stop.\n")

def handle_event(cpu, data, size):
    event = cast(data, POINTER(Data)).contents
    if event.argc == 0:
        return
    argv0 = event.argv[0].value
    if argv0 not in (b"sudo", b"/usr/bin/sudo"):
        return
    syscall = "execve" if event.syscall == 1 else "execveat"
    print(syscall)
    print("\n========== SUDO DETECTED ==========")
    print("PID:", event.pid)
    print("PPID:", event.ppid)
    print("UID:", event.uid)
    print("SYSCALL:", syscall)
    print("COMM:", event.comm.decode(errors="replace").strip("\x00"))

    print("COMMAND:", end=" ")
    cmdline = " ".join(
        event.argv[i].value.decode(errors="replace")
        for i in range(event.argc)
    )

    print(cmdline, end= " ")
    print("\n=================================\n")

b["events"].open_perf_buffer(handle_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
