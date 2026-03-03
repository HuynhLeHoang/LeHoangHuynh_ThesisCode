import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

LOG_FILE = "Provenance.log"


def parse_log(file_path):
    parent_map = {}
    children_map = defaultdict(set)
    all_edges = []
    labels = {}

    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if not parts:
                continue

            event = parts[0]

            # ===== CLONE / CLONE3 =====
            if event in ("CLONE", "CLONE3"):
                child = parts[1]
                parent = parts[2]

                parent_map[child] = parent
                children_map[parent].add(child)

                all_edges.append((parent, child, "fork"))

            # ===== EXEC =====
            elif event == "EXEC":
                # EXEC|execve|timestamp|pid|ppid|uid|comm|cmd
                pid = parts[3]
                ppid = parts[4]
                comm = parts[6]
                cmd = parts[7]

                parent_map[pid] = ppid
                children_map[ppid].add(pid)

                labels[pid] = f"{comm}\n{cmd}"

                all_edges.append((ppid, pid, "exec"))

    return parent_map, children_map, all_edges, labels


def trace_lineage(pid, parent_map):
    lineage = []
    current = pid

    while current in parent_map:
        lineage.append(current)
        parent = parent_map[current]

        if parent == current:
            break

        current = parent

    return lineage


def build_expanded_graph(target_pid, parent_map, children_map, all_edges):
    G = nx.DiGraph()

    lineage = trace_lineage(target_pid, parent_map)
    lineage_set = set(lineage)

    # 1️⃣ Thêm lineage chain
    for node in lineage:
        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="lineage")

    # 2️⃣ Với mỗi node trong lineage → thêm toàn bộ edges cấp 1
    for node in lineage:

        # Thêm parent edge
        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="neighbor")

        # Thêm tất cả child edges
        if node in children_map:
            for child in children_map[node]:
                G.add_edge(node, child, type="neighbor")

    return G


def draw_graph(G, labels,pid):
    pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
    plt.figure(figsize=(14, 12))
    output= str(pid) + ".png"
    nx.draw(
        G,
        pos,
        with_labels=False,
        node_size=2500,
        node_color="#A7C7E7",
        arrows=True
    )

    draw_labels = {}
    for node in G.nodes():
        if node in labels:
            draw_labels[node] = f"{node}\n{labels[node]}"
        else:
            draw_labels[node] = node

    nx.draw_networkx_labels(G, pos, draw_labels, font_size=8)

    plt.title("Provenance Graph (Top-Down Hierarchical)")
    plt.savefig(output, dpi=300)
    print(f"Saved to {output}")
    plt.show()

if __name__ == "__main__":
    parent_map, children_map, all_edges, labels = parse_log(LOG_FILE)

    target_pid = input("PID: ").strip()
    checker = False
    if target_pid not in parent_map:
        print("PID not exist")
    else:
        SudoAuthenLog = ''.join(open("SudoAuthen.log","r").readlines())
    pid = target_pid
    while True:        
        for children in children_map[pid]:
            if str(children) in SudoAuthenLog:
                break
        try:
            pid = parent_map[pid]
        except:
            checker = True
            break
    if checker:    
        G = build_expanded_graph(target_pid, parent_map, children_map, all_edges)
        draw_graph(G, labels, target_pid)