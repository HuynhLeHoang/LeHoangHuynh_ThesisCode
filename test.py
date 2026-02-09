from bcc import BPF
import time

program = r"""
#include <uapi/linux/ptrace.h>

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    bpf_trace_printk("openat fired\\n");
    return 0;
}
"""

b = BPF(text=program)
print("attached, waiting...")
while True:
    time.sleep(1)
