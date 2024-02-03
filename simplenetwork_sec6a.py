import matplotlib.pyplot as plt
import networkx as nx
import heapq
import uuid
import io
import re
import random
import numpy as np
import ipaddress
from ipaddress import ip_network
from collections import defaultdict
from PIL import Image as PILImage
from IPython.display import display

class NetworkEventScheduler:
    def __init__(self, log_enabled=False, verbose=False, stp_verbose=False, routing_verbose=False):
        self.current_time = 0
        self.events = []
        self.event_id = 0
        self.packet_logs = {}
        self.log_enabled = log_enabled
        self.verbose = verbose
        self.stp_verbose = stp_verbose
        self.routing_verbose = routing_verbose
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

    def find_node_by_ip(self, ip_address):
        for node_id, data in self.graph.nodes(data=True):
            if ip_address in data.get('ip_addresses', []):
                return node_id
        return None



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
                "src": packet.header["source_mac"],
                "dst": packet.header["destination_mac"]
            }
            self.packet_logs[packet.id]["events"].append(event_info)

            if self.verbose:
                print(f"Time: {self.current_time} Node: {node_id}, Event: {event_type}, Packet: {packet.id}, Src: {packet.header['source_ip']}, Dst: {packet.header['destination_ip']}")

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
            event_time, event_id, callback, args = heapq.heappop(self.events)
            self.current_time = event_time
            callback(*args)

class Node:
    def __init__(self, node_id, mac_address, ip_address, network_event_scheduler, mtu=1500, default_route=None):
        # MACアドレスが正しい形式であるか確認
        if not self.is_valid_mac_address(mac_address):
            raise ValueError("無効なMACアドレス形式です。")

        # IPアドレスが正しいCIDR形式であるか確認
        if not self.is_valid_cidr_notation(ip_address):
            raise ValueError("無効なIPアドレス形式です。")

        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.mac_address = mac_address  # MACアドレス
        self.ip_address = ip_address  # IPアドレス
        self.links = []
        self.mtu = mtu  # Maximum Transmission Unit (MTU)
        self.fragmented_packets = {}  # フラグメントされたパケットの一時格納用
        self.default_route = default_route
        label = f'Node {node_id}\n{mac_address}'
        self.network_event_scheduler.add_node(node_id, label, ip_addresses=[ip_address])

    def is_valid_mac_address(self, mac_address):
        """MACアドレスが有効な形式かどうかをチェックする関数"""
        mac_format = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_format.match(mac_address))

    def is_valid_cidr_notation(self, ip_address):
        """CIDR表記のIPアドレスが有効かどうかをチェックする関数"""
        try:
            ip_network(ip_address, strict=False)
            return True
        except ValueError:
            return False

    def add_link(self, link, ip_address=None):
        if link not in self.links:
            self.links.append(link)

    def mark_ip_as_used(self, ip_address):
        # Nodeクラスではこのメソッドは何もしない
        pass

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            # パケットロスをログに記録
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)
            return

        if packet.header["destination_mac"] == self.mac_address:
            if packet.header["destination_ip"] == self.ip_address:
                # 宛先IPがこのノードの場合
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                # フラグメントされたパケットの処理
                if packet.header["fragment_flags"]["more_fragments"]:
                    self._store_fragment(packet)
                else:
                    self._reassemble_and_process_packet(packet)
            else:
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def _store_fragment(self, fragment):
        original_data_id = fragment.header["fragment_flags"]["original_data_id"]
        offset = fragment.header["fragment_offset"]

        if original_data_id not in self.fragmented_packets:
            self.fragmented_packets[original_data_id] = {}

        self.fragmented_packets[original_data_id][offset] = fragment
        self.network_event_scheduler.log_packet_info(fragment, "fragment_stored", self.node_id)

    def print_fragments_info(self):
        for data_id, fragments in self.fragmented_packets.items():
            print(f"Original Data ID: {data_id}")
            for offset, fragment in fragments.items():
                fragment_size = len(fragment.payload)
                print(f"  Offset: {offset}, Size: {fragment_size}")

    def _reassemble_and_process_packet(self, last_fragment):
        original_data_id = last_fragment.header["fragment_flags"]["original_data_id"]
        if original_data_id not in self.fragmented_packets:
            self.network_event_scheduler.log_packet_info(last_fragment, "reassemble_failed_no_fragments", self.node_id)
            return

        fragments = self.fragmented_packets.pop(original_data_id)
        sorted_offsets = sorted(fragments.keys())

        # 再組み立てされたデータを結合して再構築
        reassembled_data = b''.join(fragments[offset].payload for offset in sorted_offsets)

        # 欠けているフラグメントをチェック
        total_data_length = sum(len(fragment.payload) for fragment in fragments.values())
        last_offset = max(sorted_offsets)
        last_fragment_size = len(fragments[last_offset].payload)
        expected_total_length = last_offset + last_fragment_size
        if total_data_length != expected_total_length:
            # 欠けているフラグメントがある場合、それをログに記録
            self.network_event_scheduler.log_packet_info(last_fragment, "reassemble_failed_incomplete_data", self.node_id)
            return

        self.network_event_scheduler.log_packet_info(last_fragment, "reassembled", self.node_id)

    def send_packet(self, destination_mac, destination_ip, data, header_size):
        payload_size = self.mtu - header_size
        total_size = len(data)
        offset = 0

        original_data_id = str(uuid.uuid4())

        while offset < total_size:
            more_fragments = offset + payload_size < total_size

            fragment_data = data[offset:offset + payload_size]
            fragment_offset = offset

            fragment_flags = {
                "more_fragments": more_fragments,
                "original_data_id": original_data_id  # データの一意の識別子を追加
            }

            node_ip_address = self.ip_address.split('/')[0]
            packet = Packet(self.mac_address, destination_mac, node_ip_address, destination_ip, 64, fragment_flags, fragment_offset, header_size, len(fragment_data), self.network_event_scheduler)
            packet.payload = fragment_data

            self._send_packet(packet)

            offset += payload_size

    def _send_packet(self, packet):
        """
        パケットをデフォルトルートのリンクを通じて送信する。
        packet: 送信するパケット
        """
        if self.default_route:
            self.default_route.enqueue_packet(packet, self)
        else:
            for link in self.links:
                link.enqueue_packet(packet, self)

    def create_packet(self, destination_mac, destination_ip, header_size, payload_size):
        node_ip_address = self.ip_address.split('/')[0]
        packet = Packet(source_mac=self.mac_address, destination_mac=destination_mac, source_ip=node_ip_address, destination_ip=destination_ip, ttl=64, header_size=header_size, payload_size=payload_size, network_event_scheduler=self.network_event_scheduler)
        self.network_event_scheduler.log_packet_info(packet, "created", self.node_id)  # パケット生成をログに記録
        self.send_packet(packet)

    def set_traffic(self, destination_mac, destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0):
        end_time = start_time + duration

        def generate_packet():
            if self.network_event_scheduler.current_time < end_time:
                # send_packetメソッドを使用してパケットを送信
                data = b'X' * payload_size  # ダミーデータを生成
                self.send_packet(destination_mac, destination_ip, data, header_size)

                # 次のパケットをスケジュールするためのインターバルを計算
                packet_size = header_size + payload_size
                interval = (packet_size * 8) / bitrate * burstiness
                self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + interval, generate_packet)

        # 最初のパケットをスケジュール
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

class Router:
    def __init__(self, node_id, ip_addresses, network_event_scheduler, hello_interval=10, lsa_interval=10, default_route = None):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.links = []
        self.available_ips = {ip: False for ip in ip_addresses} # CIDR表記のIPアドレスを辞書に変換し、使用状況をFalse（未使用）に初期化
        self.interfaces = {}  # インターフェース（リンクとIPアドレスのマッピング）
        self.routing_table = {}  # ルーティングテーブル
        self.default_route = default_route  # デフォルトルート
        self.neighbors = {}  # 隣接ルータの状態を格納
        self.hello_interval = hello_interval
        self.lsa_sequence_number = 0  # LSAシーケンス番号の初期化
        self.lsa_interval = lsa_interval  # LSA送信のインターバル
        self.lsa_database = {}  # LSA情報を格納
        self.is_topology_initialized = False
        self.topology_database = {}  # トポロジデータベースの初期化
        label = f'Router {node_id}'
        self.network_event_scheduler.add_node(node_id, label, ip_addresses=ip_addresses)
        self.schedule_hello_packet()
        self.schedule_lsa()

    def print_interfaces(self):
        print(f"インターフェース情報（ルータ {self.node_id}）:")
        for link, ip_address in self.interfaces.items():
            print(f"  リンク: {link}, IPアドレス: {ip_address}")

    def add_link(self, link, ip_address=None):
        if link not in self.interfaces:
            self.interfaces[link] = ip_address

    def mark_ip_as_used(self, ip_address):
        if ip_address in self.available_ips:
            self.available_ips[ip_address] = True  # 辞書の値をTrue（使用済み）に更新
        else:
            raise ValueError(f"IPアドレス {ip_address} はこのルータに存在しません。")

    def get_available_ip_addresses(self):
        return [ip for ip in self.available_ips if ip not in self.interfaces.values()]

    def add_route(self, destination_cidr, next_hop, link):
        self.routing_table[destination_cidr] = (next_hop, link)

    def get_route(self, destination_ip):
        if destination_ip == "224.0.0.5":
            return "multicast", None

        for network_cidr, route_info in self.routing_table.items():
            if '/' in network_cidr:
                network_address, mask_length = network_cidr.split('/')
                subnet_mask = self.cidr_to_subnet_mask(mask_length)
                if self.matches_subnet(destination_ip, network_address, subnet_mask):
                    next_hop, link = route_info
                    return next_hop, link
            else:
                # CIDR 形式でないエントリに対するエラーハンドリング
                print(f"Warning: Invalid CIDR format in routing table: {network_cidr}")

        return None, None

    def matches_subnet(self, ip_address, network_address, subnet_mask):
        ip_addr_only = ip_address.split('/')[0] if '/' in ip_address else ip_address
        ip_addr_int = self.ip_to_int(ip_addr_only)
        network_int = self.ip_to_int(network_address)
        mask_int = self.ip_to_int(subnet_mask)

        network_subnet = network_int & mask_int
        return ip_addr_int & mask_int == network_subnet

    def schedule_hello_packet(self):
        # 最初の Hello パケット送信をスケジュール
        initial_delay = random.uniform(0, 0.1)
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + initial_delay,
            self.send_hello_packet
        )

    def schedule_lsa(self):
        # LSA送信のスケジューリング
        initial_delay = random.uniform(0.3, 0.5)
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + initial_delay,
            self.send_lsa
        )

    def send_hello_packet(self):
        for link, interface_cidr in self.interfaces.items():
            network_address, mask_length = interface_cidr.split('/')
            hello_packet = HelloPacket(
                source_mac="00:00:00:00:00:00",  # ダミーMACアドレス
                source_ip=network_address,
                network_mask=self.cidr_to_subnet_mask(mask_length),
                router_id=self.node_id,
                hello_interval=self.hello_interval,  # 適切なHelloインターバルを設定
                neighbors=list(self.neighbors.keys()),  # 隣接ルータのリスト
                network_event_scheduler=self.network_event_scheduler
            )
            link.enqueue_packet(hello_packet, self)

        # 定期的に Hello パケットを送信するためのイベントをスケジュール
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + self.hello_interval,
            self.send_hello_packet
        )

    def send_lsa(self):
        # シーケンス番号のインクリメント
        seq_number = self.increment_lsa_sequence_number()

        # リンク状態情報の取得
        link_state_info = self.get_link_state_info()
        
        # 各インターフェースに対応する隣接ルータへLSAパケットを送信
        for link, ip_address in self.interfaces.items():
            source_ip = ip_address
            lsa_packet = LSAPacket(
                source_mac="00:00:00:00:00:00",  # ダミーMACアドレス
                source_ip=source_ip,  # インターフェースのIPアドレス
                router_id=self.node_id,
                sequence_number=seq_number,  # インクリメントしたシーケンス番号
                link_state_info=link_state_info,  # リンク状態情報
                network_event_scheduler=self.network_event_scheduler
            )
            link.enqueue_packet(lsa_packet, self)

        # 次回のLSA送信をスケジュール
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + self.lsa_interval,
            self.send_lsa
        )

    def flood_lsa(self, original_lsa_packet):
        # リンク状態情報の取得
        link_state_info = self.get_link_state_info()
        
        # 元のLSAパケットの送信元ルータIDを取得
        original_sender_id = original_lsa_packet.payload["router_id"]
        
        # 各インターフェースをループしてLSAパケットを送信
        for link, ip_address in self.interfaces.items():
            # 送信元ルータを除外
            if link.node_x.node_id != original_sender_id and link.node_y.node_id != original_sender_id:
                lsa_packet = original_lsa_packet
                link.enqueue_packet(lsa_packet, self)

    def increment_lsa_sequence_number(self):
        self.lsa_sequence_number += 1
        return self.lsa_sequence_number

    def get_link_state_info(self):
        link_state_info = {}
        for link, ip_address in self.interfaces.items():
            link_state_info[link] = {
                "ip_address": ip_address,
                "cost": self.calculate_link_cost(link),
                "state": self.get_link_state(link)
            }
        return link_state_info

    def calculate_link_cost(self, link):
        # リンクコストを計算する簡単なロジック
        return 1 / link.bandwidth

    def get_link_state(self, link):
        # リンクの状態を取得するロジック（例: アクティブかどうか）
        return "active" if link.is_active else "inactive"

    def forward_packet(self, packet):
        destination_ip = packet.header["destination_ip"]
        next_hop, link = self.get_route(destination_ip)

        if destination_ip == "224.0.0.5":
            for link in self.interfaces.keys():
                self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
                link.enqueue_packet(packet, self)
        elif link:  # unicast
            self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
            link.enqueue_packet(packet, self)
        elif self.default_route:  # default route
            self.network_event_scheduler.log_packet_info(packet, "forwarded via default route", self.node_id)
            self.default_route.enqueue_packet(packet, self)
        else:
            self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def cidr_to_network_address(self, cidr):
        network, mask_length = cidr.split('/')
        subnet_mask = self.cidr_mask_to_int(mask_length)
        return network, subnet_mask

    def receive_packet(self, packet, received_link):
        # 特定のパケットタイプ（HelloやLSA）を先に処理
        if isinstance(packet, HelloPacket):
            self.receive_hello_packet(packet, received_link)
            return  # Helloパケットの場合、処理を終了
        elif isinstance(packet, LSAPacket):
            self.receive_lsa(packet)
            return  # LSAパケットの場合、処理を終了

        # 一般のパケットの場合、TTLを減らす
        packet.header["ttl"] -= 1

        # TTLが0以下になったら、パケットを破棄
        if packet.header["ttl"] <= 0:
            self.network_event_scheduler.log_packet_info(packet, "dropped due to TTL expired", self.node_id)
            return
        else:
            destination_ip = packet.header["destination_ip"]
            if '/' in destination_ip:
                destination_ip, _ = destination_ip.split('/')
            for link, interface_cidr in self.interfaces.items():
                network_address, mask_length = interface_cidr.split('/')
                subnet_mask = self.cidr_to_subnet_mask(mask_length)
                if self.matches_subnet(destination_ip, network_address, subnet_mask):
                    if self.is_final_destination(packet, network_address):
                        pass
                    else:
                        self.forward_packet(packet)
                    return
            print(packet)
            self.forward_packet(packet)

    def is_final_destination(self, packet, network_address):
        destination_ip = packet.header["destination_ip"]
        if '/' in destination_ip:
            destination_ip, _ = destination_ip.split('/')
        return destination_ip == network_address

    def process_packet(self, packet, received_link):
        print(f"Packet {packet.id} processed at router {self.node_id}")

    def receive_hello_packet(self, packet, received_link):
        router_id = packet.payload["router_id"]
        new_neighbor = False

        # 隣接ルータの情報を更新
        if router_id not in self.neighbors:
            new_neighbor = True
            self.neighbors[router_id] = {
                "last_hello_time": self.network_event_scheduler.current_time,
                "link": received_link,
                "neighbor_info": packet.payload
            }
        else:
            last_hello_time = self.neighbors[router_id]["last_hello_time"]
            if self.network_event_scheduler.current_time > last_hello_time:
                new_neighbor = True
                self.neighbors[router_id]["last_hello_time"] = self.network_event_scheduler.current_time
                self.neighbors[router_id]["link"] = received_link
                self.neighbors[router_id]["neighbor_info"] = packet.payload

        # 隣接情報が更新された場合、情報を表示
        if new_neighbor:
            self.print_neighbor_info()

    def print_neighbor_info(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"隣接ルータの情報（ルータ {self.node_id}）:")
            if not self.neighbors:
                print("  隣接ルータはありません。")
                return
            for router_id, info in self.neighbors.items():
                last_hello_time = info["last_hello_time"]
                link = info["link"]
                neighbor_info = info["neighbor_info"]
                print(f"  ルータID: {router_id}")
                print(f"    最後のHello受信時刻: {last_hello_time}")
                print(f"    隣接ルータへのリンク: {link}")
                print(f"    追加情報: {neighbor_info}")

    def receive_lsa(self, lsa_packet):
        lsa_info = lsa_packet.payload["link_state_info"]

        if not self.is_topology_initialized:
            self.initialize_topology_database()
            self.is_topology_initialized = True

        if "sequence_number" in lsa_packet.payload:
            seq_number = lsa_packet.payload["sequence_number"]
            current_lsa_info = self.topology_database.get(lsa_packet.payload["router_id"], {})

            if seq_number > current_lsa_info.get("sequence_number", -1):
                # トポロジデータベースを更新
                self.topology_database[lsa_packet.payload["router_id"]] = {
                    "sequence_number": seq_number,
                    "link_state_info": lsa_info
                }

                # ルーティングテーブルの再計算
                self.update_routing_table_with_dijkstra()

                # LSAを隣接ルータに再送信
                self.flood_lsa(lsa_packet)

            else:
                # 既知のLSAは無視する
                pass

    def initialize_topology_database(self):
        # 自身のルータのリンク状態情報を初期化
        link_state_info = {}
        for link, ip_address in self.interfaces.items():
            link_state_info[link] = {
                "ip_address": ip_address,  # インターフェースのIPアドレス
                "cost": self.calculate_link_cost(link),
                "state": "active"  # 初期状態はアクティブとする
            }

        # トポロジデータベースに自身のルータの情報を登録
        self.topology_database = {
            self.node_id: {'link_state_info': link_state_info}
        }

    def print_topology_database(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"トポロジデータベース（ルータ {self.node_id}）:")
            for router_id, router_info in self.topology_database.items():
                print(f"  ルータID: {router_id}")
                link_state_info = router_info.get("link_state_info", {})
                for link, info in link_state_info.items():
                    if isinstance(info, dict):
                        print(f"    リンク: {link}")
                        print(f"      IPアドレス: {info.get('ip_address')}")
                        print(f"      コスト: {info.get('cost')}")
                        print(f"      状態: {info.get('state')}")
                    else:
                        print(f"    不正なデータ型: {info}")

    def calculate_shortest_paths(self, start_router_id):
        # 最短経路コストの辞書を初期化
        shortest_paths = {router_id: float('inf') for router_id in self.topology_database}
        shortest_paths[start_router_id] = 0
        previous_nodes = {router_id: None for router_id in self.topology_database}

        # プライオリティキューを使用して最小コストのルータを探索
        queue = [(0, start_router_id)]
        while queue:
            current_cost, current_router_id = heapq.heappop(queue)

            # 現在のルータから到達可能なルータに対してコストを更新
            if current_router_id in self.topology_database:
                for link, link_info in self.topology_database[current_router_id]['link_state_info'].items():
                    neighbor_router_id = self.get_neighbor_router_id(link, current_router_id)
                    if neighbor_router_id and neighbor_router_id in self.topology_database:
                        new_cost = current_cost + link_info['cost']
                        if new_cost < shortest_paths[neighbor_router_id]:
                            shortest_paths[neighbor_router_id] = new_cost
                            previous_nodes[neighbor_router_id] = current_router_id
                            heapq.heappush(queue, (new_cost, neighbor_router_id))

        return shortest_paths, previous_nodes

    def update_routing_table_with_dijkstra(self):
        shortest_paths, previous_nodes = self.calculate_shortest_paths(self.node_id)
        print(self.node_id)
        print("Shortest paths:", shortest_paths)  # デバッグ情報の出力
        print("Previous nodes:", previous_nodes)  # デバッグ情報の出力

        # ルーティングテーブルを更新
        for destination, cost in shortest_paths.items():
            if destination != self.node_id:
                destination_cidr = self.get_destination_cidr(destination)
                next_hop = previous_nodes[destination]
                link_to_next_hop = None

                if next_hop == self.node_id:
                    next_hop = None
                    destination_router = self.topology_database.get(destination)
                    if destination_router:
                        ip_address_list = destination_router['link_state_info'].values()
                        # 自身のインターフェースを検索し、ip_addressと同じネットワークに属するリンクを探す
                        for ip_info in ip_address_list:
                            for intf_link, intf_cidr in self.interfaces.items():
                                if self.is_same_network(intf_cidr, ip_info['ip_address']):
                                    link_to_next_hop = intf_link
                                    break
                            if link_to_next_hop:
                                break
                else:
                    link_to_next_hop = self.get_link_to_neighbor(next_hop)

                if destination_cidr and link_to_next_hop:
                    self.add_route(destination_cidr, next_hop, link_to_next_hop)

                print(f"Updating route to {destination} at {destination_cidr} via {next_hop} on link {link_to_next_hop}")  # ルート更新のデバッグ情報

        # ルータ自身のインターフェースに接続されているネットワークに対するルートを追加
        for link, interface_cidr in self.interfaces.items():
            # 既存のルートがない場合、またはルートがNoneの場合のみ追加
            if interface_cidr not in self.routing_table or self.routing_table[interface_cidr][0] is None:
                self.add_route(interface_cidr, None, link)  # 直接接続されているため、next_hopはNone

        # ルーティングテーブルの内容を出力
        print("Updated Routing Table:")
        for destination_cidr, (next_hop, link) in self.routing_table.items():
            print(f"Destination: {destination_cidr}, Next hop: {next_hop}, Link: {link}")

    def get_destination_cidr(self, router_id):
        if router_id in self.topology_database:
            link_info = self.topology_database[router_id]['link_state_info']
            for link, info in link_info.items():
                return info["ip_address"]
        return None

    def is_same_network(self, cidr1, cidr2):
        # CIDR表記のIPアドレスが同じネットワークに属するか判断
        net1 = ipaddress.ip_network(cidr1, strict=False)
        net2 = ipaddress.ip_network(cidr2, strict=False)
        return net1.overlaps(net2)

    def get_neighbor_router_id(self, link, current_router_id):
        if link.node_x.node_id == current_router_id:
            return link.node_y.node_id
        elif link.node_y.node_id == current_router_id:
            return link.node_x.node_id
        else:
            return None  # 現在のルータとリンクしていない場合

    def get_link_to_neighbor(self, neighbor_router_id):
        # next_hopがNoneの場合、直接接続されたリンクを返す
        if neighbor_router_id is None:
            for link in self.links:
                if link.node_x.node_id == self.node_id or link.node_y.node_id == self.node_id:
                    return link
            return None

        # next_hopが他のルータの場合の処理
        if neighbor_router_id in self.neighbors:
            return self.neighbors[neighbor_router_id]['link']
        
        for link in self.links:
            if link.node_x.node_id == neighbor_router_id or link.node_y.node_id == neighbor_router_id:
                return link
        
        return None  # 指定された隣接ルータに接続するリンクが見つからない場合

    def print_routing_table(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"ルーティングテーブル（ルータ {self.node_id}）:")
            for destination, route_info in self.routing_table.items():
                next_hop, link = route_info
                print(f"  宛先IPアドレス: {destination}, Next hop: {next_hop}, リンク: {link}")

    def ip_to_int(self, ip_address):
        octets = ip_address.split('.')
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(octets)))

    def subnet_mask_to_int(self, subnet_mask):
        return (0xffffffff >> (32 - int(subnet_mask))) << (32 - int(subnet_mask))

    def cidr_mask_to_int(self, mask_length):
        mask_length = int(mask_length)
        mask = (1 << 32) - (1 << (32 - mask_length))
        return mask

    def cidr_to_subnet_mask(self, mask_length):
        mask_length = int(mask_length)
        mask = (0xffffffff >> (32 - mask_length)) << (32 - mask_length)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

class Link:
    def __init__(self, node_x, node_y, bandwidth, delay, loss_rate, network_event_scheduler):
        self.node_x = node_x
        self.node_y = node_y
        self.bandwidth = bandwidth
        self.delay = delay
        self.loss_rate = loss_rate
        self.is_active = True
        self.network_event_scheduler = network_event_scheduler

        self.packet_queue_xy = []
        self.packet_queue_yx = []
        self.current_queue_time_xy = 0
        self.current_queue_time_yx = 0

        # IPアドレスの選択とリンクの設定
        ip_x, ip_y = self.setup_link_ips(node_x, node_y)

        # リンクとIPアドレスをノードに追加
        node_x.add_link(self, ip_x)
        node_y.add_link(self, ip_y)
        
        label = f'{bandwidth/1000000} Mbps, {delay} s'
        self.network_event_scheduler.add_link(node_x.node_id, node_y.node_id, label, self.bandwidth, self.delay)

    def set_active(self, active):
        # リンクの状態を設定する
        self.is_active = active

    def setup_link_ips(self, node_x, node_y):
        # ノードから利用可能なIPアドレスリスト（CIDR表記）を取得
        ip_list_x = self.get_available_ip_list(node_x)
        ip_list_y = self.get_available_ip_list(node_y)

        # 互換性のある IP アドレスを選択
        selected_ip_x, selected_ip_y = self.select_compatible_ip(ip_list_x, ip_list_y)
        if selected_ip_x is None or selected_ip_y is None:
            raise ValueError("互換性のある IP アドレスのペアが見つかりませんでした。")

        # 使用済みIPアドレスにフラグを設定
        node_x.mark_ip_as_used(selected_ip_x)
        node_y.mark_ip_as_used(selected_ip_y)

        return selected_ip_x, selected_ip_y

    def get_available_ip_list(self, node):
        # 各ノードタイプに応じて利用可能なIPアドレスリストを返す
        if isinstance(node, Router):
            return node.get_available_ip_addresses()
        else:
            return [node.ip_address]  # NodeやSwitchの場合

    def select_compatible_ip(self, ip_list_x, ip_list_y):
        # CIDR表記で提供されるIPアドレスリストから互換性のあるIPアドレスを選択
        for ip_cidr_x in ip_list_x:
            for ip_cidr_y in ip_list_y:
                if self.is_compatible(ip_cidr_x, ip_cidr_y):
                    return ip_cidr_x, ip_cidr_y
        return None, None  # 互換性のあるアドレスが見つからない場合

    def is_compatible(self, ip_cidr_x, ip_cidr_y):
        """
        二つのIPアドレス（CIDR表記）が同じネットワークに属しているかどうかを判断する。
        :param ip_cidr_x: ノードXのIPアドレス（CIDR表記）
        :param ip_cidr_y: ノードYのIPアドレス（CIDR表記）
        :return: 同じネットワークに属している場合はTrue、そうでない場合はFalse
        """
        ip_address_x, subnet_mask_x = ip_cidr_x.split('/')
        ip_address_y, subnet_mask_y = ip_cidr_y.split('/')

        # CIDR表記のサブネットマスクを整数に変換
        mask_int_x = self.subnet_mask_to_int(subnet_mask_x)
        mask_int_y = self.subnet_mask_to_int(subnet_mask_y)

        # ネットワークアドレスの計算
        network_x = self.ip_to_int(ip_address_x) & mask_int_x
        network_y = self.ip_to_int(ip_address_y) & mask_int_y

        # ネットワークアドレスが一致する場合、同じネットワークに属していると判断
        return network_x == network_y

    def get_network_address(self, ip_address, subnet_mask):
        """
        IPアドレスとサブネットマスクからネットワークアドレスを計算する。

        :param ip_address: 計算するIPアドレス
        :param subnet_mask: 使用するサブネットマスク
        :return: ネットワークアドレス
        """
        # IPアドレスとサブネットマスクをビット演算できるように整数に変換
        ip_addr_int = self.ip_to_int(ip_address)
        mask_int = self.ip_to_int(subnet_mask)

        # ネットワークアドレスの計算
        return ip_addr_int & mask_int

    def ip_to_int(self, ip_address):
        """
        IPアドレスを整数に変換する。

        :param ip_address: 変換するIPアドレス
        :return: 対応する整数
        """
        octets = ip_address.split('.')
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(octets)))

    def subnet_mask_to_int(self, subnet_mask):
        """
        サブネットマスク（CIDR表記）を整数に変換する。
        :param subnet_mask: サブネットマスク（例: "24"）
        :return: 対応する整数
        """
        return (0xffffffff >> (32 - int(subnet_mask))) << (32 - int(subnet_mask))

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
        return f"リンク({self.node_x.node_id} ↔ {self.node_y.node_id}, 帯域幅: {self.bandwidth}, 遅延: {self.delay}, パケットロス率: {self.loss_rate})"

class Packet:
    def __init__(self, source_mac, destination_mac, source_ip, destination_ip, ttl, fragment_flags, fragment_offset, header_size, payload_size, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.id = str(uuid.uuid4())
        self.header = {
            "source_mac": source_mac,
            "destination_mac": destination_mac,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "ttl": ttl,
            "fragment_flags": fragment_flags,
            "fragment_offset": fragment_offset
        }
        self.payload = b'X' * payload_size
        self.size = header_size + payload_size
        self.creation_time = self.network_event_scheduler.current_time
        self.arrival_time = None

    def set_arrived(self, arrival_time):
        self.arrival_time = arrival_time

    def __lt__(self, other):
        return False  # heapqでの比較のため

    def __str__(self):
        return f'パケット(送信元MAC: {self.header["source_mac"]}, 宛先MAC: {self.header["destination_mac"]}, 送信元IP: {self.header["source_ip"]}, 宛先IP: {self.header["destination_ip"]}, TTL: {self.header["ttl"]}, フラグメントフラグ: {self.header["fragment_flags"]}, フラグメントオフセット: {self.header["fragment_offset"]}, ペイロード: {self.payload})'

class BPDU(Packet):
    def __init__(self, source_mac, destination_mac, root_id, bridge_id, path_cost, network_event_scheduler):
        super().__init__(
            source_mac, destination_mac,
            source_ip='0.0.0.0/24',  # IPv4用ダミーIPアドレス
            destination_ip='0.0.0.0/24',  # IPv4用ダミーIPアドレス
            ttl=64, fragment_flags={}, fragment_offset=0,
            header_size=20, payload_size=50, network_event_scheduler=network_event_scheduler
        )
        self.payload = {
            "root_id": root_id,
            "bridge_id": bridge_id,
            "path_cost": path_cost
        }

    def __str__(self):
        return f'BPDU(送信元: {self.header["source_mac"]}, 宛先: {self.header["destination_mac"]}, ルートID: {self.payload["root_id"]}, ブリッジID: {self.payload["bridge_id"]}, パスコスト: {self.payload["path_cost"]})'

class HelloPacket(Packet):
    def __init__(self, source_mac, source_ip, network_mask, router_id, hello_interval, neighbors, network_event_scheduler):
        super().__init__(
            source_mac=source_mac,
            destination_mac="FF:FF:FF:FF:FF:FF",  # OSPF Helloパケットは通常ブロードキャスト
            source_ip=source_ip,
            destination_ip="224.0.0.5",  # OSPF Helloパケットの標準的な宛先IPアドレス
            ttl=1,  # OSPF HelloパケットのTTLは通常1
            fragment_flags={}, fragment_offset=0,
            header_size=24,  # OSPF Helloパケットのヘッダサイズ
            payload_size=20,  # 適切なペイロードサイズを設定
            network_event_scheduler=network_event_scheduler
        )
        self.payload = {
            "network_mask": network_mask,
            "router_id": router_id,
            "hello_interval": hello_interval,
            "neighbors": neighbors  # 隣接ルータのリスト
        }

    def __str__(self):
        return f'HelloPacket(送信元MAC: {self.header["source_mac"]}, 宛先MAC: {self.header["destination_mac"]}, 送信元IP: {self.header["source_ip"]}, ネットワークマスク: {self.payload["network_mask"]}, ルータID: {self.payload["router_id"]}, Helloインターバル: {self.payload["hello_interval"]}, 隣接ルータ: {self.payload["neighbors"]})'

class LSAPacket(Packet):
    def __init__(self, source_mac, source_ip, router_id, sequence_number, link_state_info, network_event_scheduler):
        super().__init__(
            source_mac=source_mac,
            destination_mac="FF:FF:FF:FF:FF:FF",  # LSAは通常ブロードキャスト
            source_ip=source_ip,
            destination_ip="224.0.0.5",  # OSPFのマルチキャストアドレス
            ttl=1,  # OSPFパケットのTTLは通常1
            fragment_flags={}, fragment_offset=0,
            header_size=24,  # 適切なヘッダサイズを設定
            payload_size=100,  # トポロジ情報に基づいて調整
            network_event_scheduler=network_event_scheduler
        )
        self.payload = {
            "router_id": router_id,
            "sequence_number": sequence_number,  # シーケンス番号を追加
            "link_state_info": link_state_info
        }
    def __str__(self):
        return f'LSAPacket(送信元MAC: {self.header["source_mac"]}, 送信元IP: {self.header["source_ip"]}, トポロジ情報: {self.payload["link_state_info"]})'


