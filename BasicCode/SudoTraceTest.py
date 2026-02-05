from bcc import BPF
from ctypes import *

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128

class Data(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
        # Define char[128] array type
        ("argv", (c_char * ARG_LEN) * MAX_ARGS), # Corrected line: (c_char * 128) * 20
        ("argc", c_int)
    ]

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGS 20
#define ARG_LEN 128

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};

BPF_PERCPU_ARRAY(data_storage, struct data_t, 1);
BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
               const char __user *const __user *argv) {

    int zero = 0;
    struct data_t *data = data_storage.lookup(&zero);
    if (!data)
        return 0;

    // Clear manually (NO memset, NO large stack!)
    data->pid = 0;
    data->uid = 0;
    data->comm[0] = 0;
    data->argc = 0;

    // Clear arg array
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        data->argv[i][0] = 0;
    }

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Read argv
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = 0;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;

        bpf_probe_read_user_str(&data->argv[i], ARG_LEN, argp);
        data->argc = i + 1;
    }

    events.perf_submit(ctx, data, sizeof(*data));
    return 0;
}
"""

b = BPF(text=program)
# attach execve
sys_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=sys_execve, fn_name="trace_execve")

# attach execveat (rất nhiều sudo dùng execveat)
sys_execveat = b.get_syscall_fnname("execveat")
b.attach_kprobe(event=sys_execveat, fn_name="trace_execve")

print("Tracing sudo ... Ctrl-C to stop.\n")

def handle_event(cpu, data, size):
    # Use the manually defined Data structure
    event = cast(data, POINTER(Data)).contents

    if b"sudo" not in event.comm:
        return

    print("\n========== SUDO DETECTED ==========")
    print("PID:", event.pid)
    print("UID:", event.uid)
    print("COMM:", event.comm.decode().strip('\x00')) # Decode and remove null bytes

    print("COMMAND:", end=" ")
    for i in range(event.argc):
        # Access the array of arrays and decode
        # arg is a c_char_Array_128, call .value to get bytes and then decode
        print(event.argv[i].value.decode(errors="replace"), end=" ")
    print("\n===================================\n")

b["events"].open_perf_buffer(handle_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
