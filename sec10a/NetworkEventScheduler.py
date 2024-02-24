import matplotlib.pyplot as plt
import networkx as nx
import heapq
import numpy as np
from collections import defaultdict

class NetworkEventScheduler:
    def __init__(self, log_enabled=False, verbose=False, stp_verbose=False, routing_verbose=False, nat_verbose=False, tcp_verbose=False):
        self.current_time = 0
        self.events = []
        self.event_id = 0
        self.packet_logs = {}
        self.log_enabled = log_enabled
        self.verbose = verbose
        self.stp_verbose = stp_verbose
        self.routing_verbose = routing_verbose
        self.nat_verbose = nat_verbose
        self.tcp_verbose = tcp_verbose
        self.graph = nx.Graph()

    def add_node(self, node_id, label, ip_addresses=None):
        self.graph.add_node(node_id, label=label, ip_addresses=ip_addresses)

    def add_link(self, node1_id, node2_id, label, bandwidth, delay):
        self.graph.add_edge(node1_id, node2_id, label=label, bandwidth=bandwidth, delay=delay)

    def draw(self):
        def get_edge_width(bandwidth):
            return np.log10(bandwidth) + 1

        def get_edge_color(delay):
            if delay <= 0.001:  # <= 1ms
                return 'green'
            elif delay <= 0.01:  # 1-10ms
                return 'yellow'
            else:  # >= 10ms
                return 'red'

        pos = nx.spring_layout(self.graph)

        edge_widths = [get_edge_width(self.graph[u][v]['bandwidth']) for u, v in self.graph.edges()]
        edge_colors = [get_edge_color(self.graph[u][v]['delay']) for u, v in self.graph.edges()]
        nx.draw_networkx_edges(self.graph, pos, width=edge_widths, edge_color=edge_colors)

        for node, data in self.graph.nodes(data=True):
            if 'Switch' in data['label']: # Switch
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='lightcoral', node_shape='s', node_size=250)
            elif 'Router' in data['label']: # Router
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='orange', node_shape='s', node_size=250)
            elif 'DNSServer' in data['label']: # DNS Server
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='forestgreen', node_shape='d', node_size=250)
            elif 'DHCPServer' in data['label']: # DHCP Server
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='limegreen', node_shape='d', node_size=250)
            else: # Node
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='royalblue', node_shape='o', node_size=250)

        nx.draw_networkx_labels(self.graph, pos, labels=nx.get_node_attributes(self.graph, 'label'), font_size=8)
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=nx.get_edge_attributes(self.graph, 'label'), font_size=8)
        plt.show()

    def draw_with_link_states(self, switches):
        pos = nx.spring_layout(self.graph)

        for u, v in self.graph.edges():
            link_state = self.get_link_state(u, v, switches)
            color = 'green' if link_state == 'forwarding' else 'red'
            nx.draw_networkx_edges(self.graph, pos, edgelist=[(u, v)], width=2, edge_color=color)

        for node, data in self.graph.nodes(data=True):
            if 'Switch' in data['label']:
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='red', node_shape='s', node_size=250)
            else:
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='lightblue', node_shape='o', node_size=250)

        nx.draw_networkx_labels(self.graph, pos, labels=nx.get_node_attributes(self.graph, 'label'), font_size=8)
        #nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=nx.get_edge_attributes(self.graph, 'label'), font_size=8)
        plt.show()

    def get_link_state(self, node1_id, node2_id, switches):
        for switch in switches:
            if switch.node_id == node1_id or switch.node_id == node2_id:
                for link in switch.links:
                    if (link.node_x.node_id == node1_id and link.node_y.node_id == node2_id) or \
                       (link.node_x.node_id == node2_id and link.node_y.node_id == node1_id):
                        return switch.link_states.get(link, 'unknown')
        return 'unknown'

    def schedule_event(self, event_time, callback, *args):
        event = (event_time, self.event_id, callback, args)
        heapq.heappush(self.events, event)
        self.event_id += 1

    def log_packet_info(self, packet, event_type, node_id=None):
        if self.log_enabled:
            if packet.id not in self.packet_logs:
                self.packet_logs[packet.id] = {
                    "packet_type": type(packet).__name__,  # パケットのクラス名を記録
                    "source_mac": packet.header["source_mac"],
                    "destination_mac": packet.header["destination_mac"],
                    "source_ip": packet.header["source_ip"],
                    "destination_ip": packet.header["destination_ip"],
                    "size": packet.size,
                    "creation_time": packet.creation_time,
                    "arrival_time": packet.arrival_time,
                    "events": []
                }

            if event_type == "arrived":
                self.packet_logs[packet.id]["arrival_time"] = self.current_time

            event_info = {
                "time": self.current_time,
                "event": event_type,
                "node_id": node_id,
                "packet_id": packet.id,
                "src": packet.header["source_ip"],
                "dst": packet.header["destination_ip"]
            }
            self.packet_logs[packet.id]["events"].append(event_info)

            if self.verbose:
                print(f"Time: {self.current_time} Node: {node_id}, Event: {event_type}, Packet: {packet.id}, Src: {packet.header['source_ip']}, Dst: {packet.header['destination_ip']}")

    def print_packet_logs(self):
        for packet_id, log in self.packet_logs.items():
            print(f"Packet ID: {packet_id} Src: {log['source_ip']} {log['creation_time']} -> Dst: {log['destination_ip']} {log['arrival_time']}")
            for event in log['events']:
                print(f"Time: {event['time']}, Event: {event['event']}")

    def generate_summary(self, packet_logs):
        # パケットタイプとソース宛先ペアでの集計データを保持するための辞書
        summary_data = defaultdict(lambda: defaultdict(lambda: {"sent_packets": 0, "sent_bytes": 0, "received_packets": 0, "received_bytes": 0, "total_delay": 0, "lost_packets": 0, "min_creation_time": float('inf'), "max_arrival_time": 0}))

        # ログエントリを反復処理してデータを集計
        for packet_id, log in packet_logs.items():
            packet_type = log["packet_type"]
            src_dst_pair = (log["source_ip"], log["destination_ip"])
            data = summary_data[packet_type][src_dst_pair]

            data["sent_packets"] += 1
            data["sent_bytes"] += log["size"]
            data["min_creation_time"] = min(data["min_creation_time"], log["creation_time"])

            if "arrival_time" in log and log["arrival_time"] is not None:
                data["received_packets"] += 1
                data["received_bytes"] += log["size"]
                data["total_delay"] += log["arrival_time"] - log["creation_time"]
                data["max_arrival_time"] = max(data["max_arrival_time"], log["arrival_time"])
            else:
                data["lost_packets"] += 1

        # 集計結果をパケットタイプごと、ソース宛先ペアごとに出力
        for packet_type, src_dst_data in summary_data.items():
            print(f"Packet Type: {packet_type} ###########################################")
            for src_dst, data in src_dst_data.items():
                print(f"  Src-Dst Pair: {src_dst}")
                print(f"    Total Sent Packets: {data['sent_packets']}")
                print(f"    Total Sent Bytes: {data['sent_bytes']}")
                print(f"    Total Received Packets: {data['received_packets']}")
                print(f"    Total Received Bytes: {data['received_bytes']}")
                avg_throughput = (data["received_bytes"] * 8 / (data["max_arrival_time"] - data["min_creation_time"])) if (data["max_arrival_time"] - data["min_creation_time"]) > 0 else 0
                avg_delay = data["total_delay"] / data["received_packets"] if data["received_packets"] > 0 else 0
                print(f"    Average Throughput (bps): {avg_throughput}")
                print(f"    Average Delay (s): {avg_delay}")
                print(f"    Lost Packets: {data['lost_packets']}\n")

    def generate_throughput_graph(self, packet_logs):
        time_slot = 1.0  # 時間スロットを1秒に固定

        max_time = max(log['arrival_time'] for log in packet_logs.values() if log['arrival_time'] is not None)
        min_time = min(log['creation_time'] for log in packet_logs.values())
        num_slots = int((max_time - min_time) / time_slot) + 1  # スロットの総数を計算

        throughput_data = defaultdict(list)
        for packet_id, log in packet_logs.items():
            if log['arrival_time'] is not None:
                src_dst_pair = (log['source_ip'], log['destination_ip'])
                slot_index = int((log['arrival_time'] - min_time) / time_slot)
                throughput_data[src_dst_pair].append((slot_index, log['size']))

        aggregated_throughput = defaultdict(lambda: defaultdict(int))
        for src_dst, packets in throughput_data.items():
            for slot_index in range(num_slots):
                slot_throughput = sum(size * 8 for i, size in packets if i == slot_index)
                aggregated_throughput[src_dst][slot_index] = slot_throughput / time_slot

        for src_dst, slot_data in aggregated_throughput.items():
            time_slots = list(range(num_slots))
            throughputs = [slot_data[slot] for slot in time_slots]
            times = [min_time + slot * time_slot for slot in time_slots]
            plt.step(times, throughputs, label=f'{src_dst[0]} -> {src_dst[1]}', where='post', linestyle='-', alpha=0.5, marker='o')

        plt.xlabel('Time (s)')
        plt.ylabel('Throughput (bps)')
        plt.title('Throughput over time')
        plt.xlim(0, max_time)
        plt.legend()
        plt.show()

    def generate_delay_histogram(self, packet_logs):
        delay_data = defaultdict(list)
        for packet_id, log in packet_logs.items():
            if log['arrival_time'] is not None:
                src_dst_pair = (log['source_ip'], log['destination_ip'])
                delay = log['arrival_time'] - log['creation_time']
                delay_data[src_dst_pair].append(delay)

        num_plots = len(delay_data)
        num_bins = 20
        fig, axs = plt.subplots(num_plots, figsize=(6, 2 * num_plots))
        max_delay = max(max(delays) for delays in delay_data.values())
        bin_width = max_delay / num_bins

        for i, (src_dst, delays) in enumerate(delay_data.items()):
            ax = axs[i] if num_plots > 1 else axs
            ax.hist(delays, bins=np.arange(0, max_delay + bin_width, bin_width), alpha=0.5, color='royalblue', label=f'{src_dst[0]} -> {src_dst[1]}')
            ax.set_xlabel('Delay (s)')
            ax.set_ylabel('Frequency')
            ax.set_title(f'Delay histogram for {src_dst[0]} -> {src_dst[1]}')
            ax.set_xlim(0, max_delay)
            ax.legend()

        plt.tight_layout()
        plt.show()

    def run(self):
        while self.events:
            event_time, _, callback, args = heapq.heappop(self.events)
            self.current_time = event_time
            callback(*args)

    def run_until(self, end_time):
        while self.events and self.events[0][0] <= end_time:
            event_time, event_id, callback, args = heapq.heappop(self.events)
            self.current_time = event_time
            callback(*args)
