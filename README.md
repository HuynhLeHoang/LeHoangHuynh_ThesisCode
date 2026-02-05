# Source code of Real-time Privilege Attack Detector

- hooker_main.py: hooker at syscall process tracepoints.
- filehooker_main.py: hooker at syscall process tracepoints.
- eBPFtracer.py: currently the combination of hooker_main.py and filehooker_main.py.
- trace_privi.py: trigger at privilege related tracepoint.
- Provenance.Log: Provenance data is saved here.

# How to run
- This code can be run with python3 without installing any specific enviroments.
- sudo python3 hooker_main.py / sydo python3 filehooker_main.py : the code will trace data from syscall and display to terminal
- sudo python eBPFtracer.py: collect both process and file provenance from system and save to Provenance.Log. However, this code is currently stucked with a problem: eBPF programs inside kernel is pushing overwhelm data to the part at userspace. So that a lot of traffic is lost. I am trying to solve this problem.

