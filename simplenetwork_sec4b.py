import matplotlib.pyplot as plt
import networkx as nx
import heapq
import uuid
import re
import random
import numpy as np
from collections import defaultdict

class NetworkEventScheduler:
    def __init__(self, log_enabled=False, verbose=False, stp_verbose=False):
        self.current_time = 0
        self.events = []
        self.event_id = 0
        self.packet_logs = {}
        self.log_enabled = log_enabled
        self.verbose = verbose
        self.stp_verbose = stp_verbose
        self.graph = nx.Graph()

    def add_node(self, node_id, label):
        self.graph.add_node(node_id, label=label)

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
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='red', node_shape='s', node_size=250)
            else: # Node
                nx.draw_networkx_nodes(self.graph, pos, nodelist=[node], node_color='lightblue', node_shape='o', node_size=250)

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
                    "source_mac": packet.header["source_mac"],
                    "destination_mac": packet.header["destination_mac"],
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
                "src": packet.header["source_mac"],
                "dst": packet.header["destination_mac"]
            }
            self.packet_logs[packet.id]["events"].append(event_info)

            if self.verbose:
                print(f"Time: {self.current_time} Node: {node_id}, Event: {event_type}, Packet: {packet.id}, Src: {packet.header['source_mac']}, Dst: {packet.header['destination_mac']}")

    def print_packet_logs(self):
        for packet_id, log in self.packet_logs.items():
            print(f"Packet ID: {packet_id} Src: {log['source_mac']} {log['creation_time']} -> Dst: {log['destination_mac']} {log['arrival_time']}")
            for event in log['events']:
                print(f"Time: {event['time']}, Event: {event['event']}")

    def generate_summary(self, packet_logs):
        summary_data = defaultdict(lambda: {"sent_packets": 0, "sent_bytes": 0, "received_packets": 0, "received_bytes": 0, "total_delay": 0, "lost_packets": 0, "min_creation_time": float('inf'), "max_arrival_time": 0})

        for packet_id, log in packet_logs.items():
            src_dst_pair = (log["source_mac"], log["destination_mac"])
            summary_data[src_dst_pair]["sent_packets"] += 1
            summary_data[src_dst_pair]["sent_bytes"] += log["size"]
            summary_data[src_dst_pair]["min_creation_time"] = min(summary_data[src_dst_pair]["min_creation_time"], log["creation_time"])

            if "arrival_time" in log and log["arrival_time"] is not None:
                summary_data[src_dst_pair]["received_packets"] += 1
                summary_data[src_dst_pair]["received_bytes"] += log["size"]
                summary_data[src_dst_pair]["total_delay"] += log["arrival_time"] - log["creation_time"]
                summary_data[src_dst_pair]["max_arrival_time"] = max(summary_data[src_dst_pair]["max_arrival_time"], log["arrival_time"])
            else:
                summary_data[src_dst_pair]["lost_packets"] += 1

        for src_dst, data in summary_data.items():
            sent_packets = data["sent_packets"]
            sent_bytes = data["sent_bytes"]
            received_packets = data["received_packets"]
            received_bytes = data["received_bytes"]
            total_delay = data["total_delay"]
            lost_packets = data["lost_packets"]
            min_creation_time = data["min_creation_time"]
            max_arrival_time = data["max_arrival_time"]

            traffic_duration = max_arrival_time - min_creation_time
            avg_throughput = (received_bytes * 8 / traffic_duration) if traffic_duration > 0 else 0
            avg_delay = total_delay / received_packets if received_packets > 0 else 0

            print(f"Src-Dst Pair: {src_dst}")
            print(f"Total Sent Packets: {sent_packets}")
            print(f"Total Sent Bytes: {sent_bytes}")
            print(f"Total Received Packets: {received_packets}")
            print(f"Total Received Bytes: {received_bytes}")
            print(f"Average Throughput (bps): {avg_throughput}")
            print(f"Average Delay (s): {avg_delay}")
            print(f"Lost Packets: {lost_packets}\n")

    def generate_throughput_graph(self, packet_logs):
        time_slot = 1.0  # 時間スロットを1秒に固定

        max_time = max(log['arrival_time'] for log in packet_logs.values() if log['arrival_time'] is not None)
        min_time = min(log['creation_time'] for log in packet_logs.values())
        num_slots = int((max_time - min_time) / time_slot) + 1  # スロットの総数を計算

        throughput_data = defaultdict(list)
        for packet_id, log in packet_logs.items():
            if log['arrival_time'] is not None:
                src_dst_pair = (log['source_mac'], log['destination_mac'])
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
                src_dst_pair = (log['source_mac'], log['destination_mac'])
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
            event_time, callback, args = heapq.heappop(self.events)
            self.current_time = event_time
            callback(*args)

class Node:
    def __init__(self, node_id, mac_address, network_event_scheduler):
        # MACアドレスが正しい形式であるか確認
        if not self.is_valid_mac_address(mac_address):
            raise ValueError("無効なMACアドレス形式です。")
            
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.mac_address = mac_address  # MACアドレス
        self.links = []
        label = f'Node {node_id}\n{mac_address}'
        self.network_event_scheduler.add_node(node_id, label)

    def is_valid_mac_address(self, mac_address):
        """MACアドレスが有効な形式かどうかをチェックする関数"""
        mac_format = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_format.match(mac_address))
        
    def add_link(self, link):
        if link not in self.links:
            self.links.append(link)

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)  # パケットロスをログに記録
            return
        if packet.header["destination_mac"] == self.mac_address:
            self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)  # パケット受信をログに記録
            packet.set_arrived(self.network_event_scheduler.current_time)
        else:
            self.network_event_scheduler.log_packet_info(packet, "received", self.node_id)  # パケット受信をログに記録
            # パケットの宛先が自分自身でない場合の処理
            pass

    def send_packet(self, packet):
        self.network_event_scheduler.log_packet_info(packet, "sent", self.node_id)  # パケット送信をログに記録
        if packet.header["destination_mac"] == self.mac_address:
            self.receive_packet(packet)
        else:
            for link in self.links:
                next_node = link.node_x if self != link.node_x else link.node_y
                link.enqueue_packet(packet, self)
                break

    def create_packet(self, destination_mac, header_size, payload_size):
        packet = Packet(source_mac=self.mac_address, destination_mac=destination_mac, header_size=header_size, payload_size=payload_size, network_event_scheduler=self.network_event_scheduler)
        self.network_event_scheduler.log_packet_info(packet, "created", self.node_id)  # パケット生成をログに記録
        self.send_packet(packet)

    def set_traffic(self, destination_mac, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0):
        end_time = start_time + duration
        def generate_packet():
            if self.network_event_scheduler.current_time < end_time:
                self.create_packet(destination_mac, header_size, payload_size)
                packet_size = header_size + payload_size
                interval = (packet_size * 8) / bitrate * burstiness
                self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + interval, generate_packet)

        self.network_event_scheduler.schedule_event(start_time, generate_packet)

    def __str__(self):
        connected_nodes = [link.node_x.node_id if self != link.node_x else link.node_y.node_id for link in self.links]
        connected_nodes_str = ', '.join(map(str, connected_nodes))
        return f"ノード(ID: {self.node_id}, MACアドレス: {self.mac_address}, 接続: {connected_nodes_str})"

class Switch:
    def __init__(self, node_id, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.links = []
        self.forwarding_table = {}
        self.link_states = {}
        self.root_id = node_id
        self.root_path_cost = 0
        self.is_root = True
        label = f'Switch {node_id}'
        self.network_event_scheduler.add_node(node_id, label)

    def add_link(self, link):
        if link not in self.links:
            self.links.append(link)
            self.link_states[link] = 'initial'
            self.send_bpdu()

    def update_link_state(self, link, state):
        self.link_states[link] = state

    def send_bpdu(self):
        for link in self.links:
            bpdu = BPDU(source_mac="00:00:00:00:00:00",
                      destination_mac="FF:FF:FF:FF:FF:FF",
                      root_id=self.root_id,
                      bridge_id=self.node_id,
                      path_cost=self.root_path_cost,
                      network_event_scheduler=self.network_event_scheduler)
            link.enqueue_packet(bpdu, self)

    def update_forwarding_table(self, source_address, link):
        self.forwarding_table[source_address] = link

    def receive_packet(self, packet, received_link):
        if isinstance(packet, BPDU):
            self.network_event_scheduler.log_packet_info(packet, "BPDU received", self.node_id)  # パケット受信をログに記録
            self.process_bpdu(packet, received_link)
        else:
            if packet.arrival_time == -1:
                self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)  # パケットが失われた場合の処理
                return
            self.network_event_scheduler.log_packet_info(packet, "received", self.node_id)  # パケット受信をログに記録

            source_address = packet.header["source_mac"]
            self.update_forwarding_table(source_address, received_link)  # フォワーディングテーブルを更新

            self.forward_packet(packet, received_link)

    def forward_packet(self, packet, received_link):
        destination_address = packet.header["destination_mac"]
        if destination_address in self.forwarding_table:
            link = self.forwarding_table[destination_address]
            if self.link_states[link] == 'forwarding':
                self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
                link.enqueue_packet(packet, self)
        else:
            for link in self.links:
                if link != received_link and self.link_states[link] == 'forwarding':
                    self.network_event_scheduler.log_packet_info(packet, "broadcast", self.node_id)
                    link.enqueue_packet(packet, self)

    def process_bpdu(self, bpdu, received_link):
        # ルートIDの更新とルートパスコストの計算
        new_root_id = bpdu.payload["root_id"]
        new_path_cost = bpdu.payload["path_cost"] + 1  # 受信リンクを通るコストを加算

        # ルート情報が変更されたかどうかを確認
        root_info_changed = new_root_id != self.root_id or new_path_cost < self.root_path_cost

        if self.network_event_scheduler.stp_verbose:
            current_time = self.network_event_scheduler.current_time
            print(f"Time: {current_time} - {self.node_id} processing BPDU: new_root_id={new_root_id}, current_root_id={self.root_id}, new_path_cost={new_path_cost}, current_root_path_cost={self.root_path_cost}")

        if new_root_id < self.root_id or (new_root_id == self.root_id and new_path_cost < self.root_path_cost):
            # ルート情報の更新
            self.root_id = new_root_id
            self.root_path_cost = new_path_cost
            self.is_root = False

        # リンク状態の更新（例：フォワーディング/ブロッキング）
        self.update_link_states(received_link, new_path_cost)

        # ルート情報が変更された場合のみBPDUを再送信
        if root_info_changed:
            self.send_bpdu()

    def update_link_states(self, received_link, received_bpdu_path_cost):
        if self.is_root:
            # ルートブリッジの場合、全てのポートをフォワーディング状態に設定
            for link in self.links:
                self.link_states[link] = 'forwarding'
        else:
            # 非ルートブリッジの場合、最小コストのリンクを選択してフォワーディングに設定
            best_path_cost = float('inf')
            best_link = None
            best_link_id = None

            for link in self.links:
                if self.is_link_between_switches(link):
                    link_path_cost = self.get_link_cost(link) + received_bpdu_path_cost
                    link_id = min(link.node_x.node_id, link.node_y.node_id)
                    if link_path_cost < best_path_cost or (link_path_cost == best_path_cost and link_id < best_link_id):
                        best_path_cost = link_path_cost
                        best_link = link
                        best_link_id = link_id

            for link in self.links:
                if link == best_link or not self.is_link_between_switches(link):
                    self.link_states[link] = 'forwarding'
                else:
                    self.link_states[link] = 'blocking'

            if self.network_event_scheduler.stp_verbose:
                print(f"{self.node_id} link states updated: {self.link_states}")

    def is_link_between_switches(self, link):
        return isinstance(link.node_x, Switch) and isinstance(link.node_y, Switch)

    def get_link_cost(self, link):
        min_cost = 0.000000001
        return max(min_cost, 1.0 / link.bandwidth)

    def print_forwarding_table(self):
        print(f"フォワーディングテーブル for Switch {self.node_id}:")
        for mac_address, link in self.forwarding_table.items():
            linked_node = link.node_x.node_id if link.node_x.node_id != self.node_id else link.node_y.node_id
            print(f"  MACアドレス: {mac_address} -> リンク先ノード: {linked_node}")

    def print_link_states(self):
        print(f"スイッチ {self.node_id} （root={self.is_root}）のリンク状態:")
        for link in self.links:
            state = self.link_states[link]
            connected_node = link.node_x if link.node_x != self else link.node_y
            print(f"  - リンク {self.node_id} - {connected_node.node_id}: 状態 {state}")

    def __str__(self):
        connected_nodes = [link.node_x.node_id if self.node_id != link.node_x.node_id else link.node_y.node_id for link in self.links]
        connected_nodes_str = ', '.join(map(str, connected_nodes))
        return f"スイッチ(ID: {self.node_id}, 接続: {connected_nodes_str})"


class Link:
    def __init__(self, node_x, node_y, bandwidth, delay, loss_rate, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.node_x = node_x
        self.node_y = node_y
        self.bandwidth = bandwidth
        self.delay = delay
        self.loss_rate = loss_rate
        self.packet_queue_xy = []
        self.packet_queue_yx = []
        self.current_queue_time_xy = 0
        self.current_queue_time_yx = 0
        node_x.add_link(self)
        node_y.add_link(self)
        label = f'{bandwidth/1000000} Mbps, {delay} s'
        self.network_event_scheduler.add_link(node_x.node_id, node_y.node_id, label, self.bandwidth, self.delay)

    def enqueue_packet(self, packet, from_node):
        if from_node == self.node_x:
            queue = self.packet_queue_xy
            current_queue_time = self.current_queue_time_xy
        else:
            queue = self.packet_queue_yx
            current_queue_time = self.current_queue_time_yx

        packet_transfer_time = (packet.size * 8) / self.bandwidth
        dequeue_time = self.network_event_scheduler.current_time + current_queue_time
        heapq.heappush(queue, (dequeue_time, packet, from_node))
        self.add_to_queue_time(from_node, packet_transfer_time)
        if len(queue) == 1:
            self.network_event_scheduler.schedule_event(dequeue_time, self.transfer_packet, from_node)

    def transfer_packet(self, from_node):
        if from_node == self.node_x:
            queue = self.packet_queue_xy
        else:
            queue = self.packet_queue_yx

        if queue:
            dequeue_time, packet, _ = heapq.heappop(queue)
            packet_transfer_time = (packet.size * 8) / self.bandwidth

            if random.random() < self.loss_rate:
                packet.set_arrived(-1)

            next_node = self.node_x if from_node != self.node_x else self.node_y
            self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + self.delay, next_node.receive_packet, packet, self)
            self.network_event_scheduler.schedule_event(dequeue_time + packet_transfer_time, self.subtract_from_queue_time, from_node, packet_transfer_time)

            if queue:
                next_packet_time = queue[0][0]
                self.network_event_scheduler.schedule_event(next_packet_time, self.transfer_packet, from_node)

    def add_to_queue_time(self, from_node, packet_transfer_time):
        if from_node == self.node_x:
            self.current_queue_time_xy += packet_transfer_time
        else:
            self.current_queue_time_yx += packet_transfer_time

    def subtract_from_queue_time(self, from_node, packet_transfer_time):
        if from_node == self.node_x:
            self.current_queue_time_xy -= packet_transfer_time
        else:
            self.current_queue_time_yx -= packet_transfer_time

    def __str__(self):
        return f"リンク({self.node_x.node_id} ↔ {self.node_y.node_id}, 帯域幅: {self.bandwidth}, 遅延: {self.delay}, パケットロス率: {self.packet_loss})"

class Packet:
    def __init__(self, source_mac, destination_mac, header_size, payload_size, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.id = str(uuid.uuid4())
        self.header = {
            "source_mac": source_mac,
            "destination_mac": destination_mac,
        }
        self.payload = 'X' * payload_size
        self.size = header_size + payload_size
        self.creation_time = self.network_event_scheduler.current_time
        self.arrival_time = None

    def set_arrived(self, arrival_time):
        self.arrival_time = arrival_time

    def __lt__(self, other):
        return False  # heapqでの比較のため

    def __str__(self):
        return f'パケット(送信元: {self.header["source_mac"]}, 宛先: {self.header["destination_mac"]}, ペイロード: {self.payload})'

class BPDU(Packet):
    def __init__(self, source_mac, destination_mac, root_id, bridge_id, path_cost, network_event_scheduler):
        # Packetクラスのコンストラクタを呼び出す
        super().__init__(source_mac, destination_mac, header_size=20, payload_size=50, network_event_scheduler=network_event_scheduler)
        # BPDU特有のペイロード情報を追加
        self.payload = {
            "root_id": root_id,
            "bridge_id": bridge_id,
            "path_cost": path_cost
        }

    def __str__(self):
        # BPDUの文字列表現をカスタマイズ
        return f'BPDU(送信元: {self.header["source_mac"]}, 宛先: {self.header["destination_mac"]}, ルートID: {self.payload["root_id"]}, ブリッジID: {self.payload["bridge_id"]}, パスコスト: {self.payload["path_cost"]})'




