import uuid
import re
import random
from random import randint
from ipaddress import ip_interface, ip_network
from sec14a.Switch import Switch
from sec14a.Router import Router
from sec14a.Packet import Packet, UDPPacket, TCPPacket, ARPPacket, DNSPacket, DHCPPacket
from sec14a.Application import ApplicationManager

class Node:
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None, dns_server=None, mtu=10000, default_route=None):
        self.node_id = node_id
        self.ip_address = ip_address
        self.network_event_scheduler = network_event_scheduler
        self.local_seed = self.network_event_scheduler.get_seed()
        if self.local_seed is not None:
            random.seed(self.local_seed)

        if mac_address is None:
            self.mac_address = self.generate_mac_address()
        else:
            if not self.is_valid_mac_address(mac_address):
                raise ValueError("無効なMACアドレス形式です。")
            self.mac_address = mac_address

        self.links = []
        self.applications = {}
        self.used_ports = set()
        self.port_mapping = {}
        self.tcp_connections = {}
        self.cwnd = 1
        self.ssthresh = 32
        self.MAX_CWND = 128
        self.tcp_state = {}
        self.max_attempts = 10
        self.windows = {}
        self.timeout_interval = 2
        self.scheduled_timeouts = {}
        self.pending_tcp_data = {}
        self.arp_table = {}
        self.waiting_for_arp_reply = {}  # {ip_address: [packet, packet, ...]}
        self.pending_packets = {}  # {ip_address: [packet, packet, ...]}
        self.dns_server_ip = dns_server
        self.url_to_ip_mapping = {}
        self.mtu = mtu
        self.fragmented_packets = {}
        self.default_route = default_route

        label = f'Node {node_id}\n{mac_address}'
        self.network_event_scheduler.add_node(node_id, label, ip_addresses=[ip_address])

        # ApplicationManagerをセット
        self.application_layer = ApplicationManager(self)

        # IPがネットワークアドレスであればDHCP開始をスケジュール
        if self.is_network_address(self.ip_address):
            # DHCPクライアントはapplication_layer.dhcp_clientにある前提
            if self.application_layer and self.application_layer.dhcp_client:
                self.application_layer.dhcp_client.schedule_dhcp_discover()

    def is_valid_mac_address(self, mac_address):
        mac_format = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_format.match(mac_address))

    def is_valid_cidr_notation(self, ip_address):
        try:
            ip_network(ip_address, strict=False)
            return True
        except ValueError:
            return False

    def is_network_address(self, address):
        try:
            interface = ip_interface(address)
            network = ip_network(address, strict=False)
            return interface.ip == network.network_address and interface.network.prefixlen == network.prefixlen
        except ValueError:
            return False

    def add_link(self, link, ip_address=None):
        if link not in self.links:
            self.links.append(link)

    def generate_mac_address(self):
        return ':'.join(['{:02x}'.format((uuid.uuid4().int >> (i*8)) & 0xff) for i in range(6)])

    def register_application(self, port, protocol, application_instance):
        self.applications[(port, protocol)] = application_instance

        # このポートは使用中であることを記録
        self.used_ports.add(port)

        if hasattr(application_instance, "__class__"):
            class_name = application_instance.__class__.__name__
            if class_name == "FTPServer":
                if self.application_layer and hasattr(self.application_layer, 'register_ftp_server'):
                    self.application_layer.register_ftp_server(application_instance)
            elif class_name == "FTPClient":
                if self.application_layer and hasattr(self.application_layer, 'register_ftp_client'):
                    self.application_layer.register_ftp_client(application_instance)

    def select_available_port(self, protocol="TCP"):
        for port in range(1024, 49152):
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port
        raise Exception("No available ports")

    def select_random_port(self):
        return random.randint(1024, 49152)

    def add_to_arp_table(self, ip_address, mac_address):
        self.arp_table[ip_address] = mac_address

    def get_mac_address_from_ip(self, ip_address):
        return self.arp_table.get(ip_address, None)

    def print_arp_table(self):
        print(f"ARPテーブル（ノード {self.node_id}）:")
        for ip_address, mac_address in self.arp_table.items():
            print(f"IPアドレス: {ip_address} -> MACアドレス: {mac_address}")

    def mark_ip_as_used(self, ip_address):
        pass

    def add_dns_record(self, domain_name, ip_address):
        self.url_to_ip_mapping[domain_name] = ip_address
        print(f"{self.node_id} DNS record added: {domain_name} -> {ip_address}")

    def process_ARP_packet(self, packet):
        self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
        packet.set_arrived(self.network_event_scheduler.current_time)

        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF":
            if packet.payload.get("operation") == "request" and packet.payload["destination_ip"] == self.ip_address:
                self._send_arp_reply(packet)
                return

        if packet.header["destination_mac"] == self.mac_address:
            if packet.payload.get("operation") == "reply" and packet.payload["destination_ip"] == self.ip_address:
                self.network_event_scheduler.log_packet_info(packet, "ARP reply received", self.node_id)
                source_ip = packet.payload["source_ip"]
                source_mac = packet.payload["source_mac"]
                self.add_to_arp_table(source_ip, source_mac)
                self.on_arp_reply_received(source_ip, source_mac)
                return

    def process_UDP_packet(self, packet):
        if packet.header["destination_mac"] == self.mac_address:
            if packet.header["destination_ip"] == self.ip_address:
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                if self.application_layer and hasattr(self.application_layer, 'on_packet_received'):
                    self.application_layer.on_packet_received(packet)
                else:
                    self.process_data_packet(packet)
            else:
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def process_TCP_packet(self, packet):
        """
        TCPパケットを処理する。
        """
        print(f"[DEBUG] Processing TCP packet from {packet.source_ip}:{packet.source_port} to {packet.destination_ip}:{packet.destination_port}")
        print(f"[DEBUG] Flags: {packet.flags}, Seq: {packet.sequence_number}, Ack: {packet.acknowledgment_number}")

        # コネクションキーを生成（送信元IPとポート）
        connection_key = (packet.destination_ip, packet.destination_port)
        print(f"[DEBUG] Connection key: {connection_key}")

        # SYNパケットの処理
        if 'SYN' in packet.flags.split() and 'ACK' not in packet.flags.split():
            print(f"[DEBUG] Received SYN packet, sending SYN-ACK")
            self.send_TCP_SYN_ACK(packet)
            return

        # SYN-ACKパケットの処理
        if 'SYN' in packet.flags.split() and 'ACK' in packet.flags.split():
            print(f"[DEBUG] Received SYN-ACK packet, establishing connection")
            self.establish_TCP_connection(packet)
            return

        # コネクション情報の取得
        if connection_key not in self.tcp_connections:
            print(f"[DEBUG] No connection found for {connection_key}")
            return

        current_state = self.tcp_connections[connection_key]['state']
        print(f"[DEBUG] Current connection state: {current_state}")

        # ACKパケットの処理
        if 'ACK' in packet.flags.split():
            print(f"[DEBUG] Processing ACK packet")
            self.handle_acknowledgement(connection_key, packet)

        # データパケットの処理
        if packet.payload and len(packet.payload) > 0:
            print(f"[DEBUG] Processing data packet with length {len(packet.payload)}")
            if connection_key in self.application_manager:
                self.application_manager[connection_key].process_packet(packet)
            else:
                print(f"[DEBUG] No application registered for {connection_key}")

        # FINパケットの処理
        if 'FIN' in packet.flags.split():
            print(f"[DEBUG] Received FIN packet")
            self.terminate_TCP_connection(connection_key)

    def initialize_connection_info(self, connection_key, destination_ip, destination_port):
        """
        TCP接続情報を初期化する。
        """
        print(f"[DEBUG] Initializing connection info for {connection_key}")
        self.tcp_connections[connection_key] = {
            'state': 'CLOSED',
            'sequence_number': 0,
            'acknowledgment_number': 0,
            'destination_ip': destination_ip,
            'destination_port': destination_port,
            'unacked_packets': {},
            'received_packets': {},
            'cwnd': 1,
            'ssthresh': 65535,
            'duplicate_ack_count': 0,
            'last_received_ack': 0
        }
        print(f"[DEBUG] Connection info initialized: {self.tcp_connections[connection_key]}")

    def transition_to_state(self, connection_key, new_state):
        """状態遷移を管理する"""
        if connection_key not in self.tcp_connections:
            return

        current_state = self.tcp_connections[connection_key]['congestion_state']
        if current_state == new_state:
            return  # 同じ状態に遷移しようとした場合は何もしない

        # 現在のcwndとssthreshを取得
        cwnd = self.tcp_connections[connection_key]['cwnd']
        ssthresh = self.tcp_connections[connection_key]['ssthresh']

        if new_state == 'slow_start':
            # スロースタート状態への遷移（タイムアウト時）
            self.tcp_connections[connection_key]['ssthresh'] = max(cwnd // 2, 2)
            self.tcp_connections[connection_key]['cwnd'] = 1
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. ssthresh set to {self.tcp_connections[connection_key]['ssthresh']}, cwnd reset to 1.")

        elif new_state == 'congestion_avoidance':
            # 輻輳回避状態への遷移
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. Continuing to increase cwnd linearly.")

        elif new_state == 'fast_recovery':
            # Fast Recovery状態への遷移（3重複ACK時）
            self.tcp_connections[connection_key]['ssthresh'] = max(cwnd // 2, 2)
            self.tcp_connections[connection_key]['cwnd'] = self.tcp_connections[connection_key]['ssthresh'] + 3
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. cwnd set to {self.tcp_connections[connection_key]['cwnd']}.")

        self.log_congestion_window(connection_key, self.tcp_connections[connection_key]['cwnd'], new_state)

    def handle_acknowledgement(self, connection_key, acknowledgment_number):
        if connection_key not in self.windows:
            return

        print(f"[DEBUG] Handling ACK {acknowledgment_number} for connection {connection_key}")
        print(f"[DEBUG] Current window state: {list(self.windows[connection_key].keys())}")

        acked_sequences = []
        for seq_num in self.windows[connection_key]:
            if seq_num < acknowledgment_number:
                acked_sequences.append(seq_num)
                self.cancel_timeout(connection_key, seq_num)

        for seq_num in acked_sequences:
            del self.windows[connection_key][seq_num]
            print(f"[DEBUG] Removed acknowledged packet with sequence number {seq_num}")

        if not self.windows[connection_key]:
            print(f"[DEBUG] Window is empty for connection {connection_key}")
            return

        next_expected_seq = min(self.windows[connection_key].keys())
        print(f"[DEBUG] Next expected sequence number: {next_expected_seq}")

        # PLACEHOLDER: congestion control related code (not modified as per requirements)

    def schedule_send_next_chunk(self, connection_key):
        # イベントスケジューラで僅かに遅れてsend_next_chunk_eventを呼ぶ
        delay = 0.000001  # 必要に応じて調整
        event_time = self.network_event_scheduler.current_time + delay
        self.network_event_scheduler.schedule_event(event_time, self.send_next_chunk_event, connection_key)

    def send_next_chunk_event(self, connection_key):
        # ここで実際の次のチャンク送信処理を行う
        transfer_info = self.tcp_connections[connection_key].get('transfer_info', None)
        if transfer_info:
            file_size = transfer_info.get('file_size', 0)
            bytes_transferred = transfer_info.get('bytes_transferred', 0)
            if bytes_transferred < file_size:
                # まだ送るべきデータあり
                app = self.application_layer
                chunk = app.get_data_chunk(connection_key, transfer_info['payload_size'])
                if chunk:
                    dst_ip, dst_port = connection_key
                    self.send_app_data(dst_ip, chunk, protocol="TCP", destination_port=dst_port)

    def schedule_timeout(self, connection_key, sequence_number):
        event_time = self.network_event_scheduler.current_time + self.timeout_interval
        event_id = self.network_event_scheduler.schedule_event(event_time, self.handle_timeout, connection_key, sequence_number)
        self.tcp_connections[connection_key]['timeout_event_ids'][sequence_number] = event_id

    def handle_timeout(self, connection_key, sequence_number):
        """
        タイムアウトしたパケットに対する処理を行います。
        """
        if connection_key in self.windows and sequence_number in self.windows[connection_key]:
            attempt = self.windows[connection_key][sequence_number]["attempt"]
            packet_info = self.windows[connection_key][sequence_number]["packet_info"]

            # タイムアウト時のssthreshとcwndの更新
            current_cwnd = self.tcp_connections[connection_key]['cwnd']
            self.tcp_connections[connection_key]['ssthresh'] = max(current_cwnd // 2, 2)
            self.tcp_connections[connection_key]['cwnd'] = 1

            # 再送試行回数をチェック
            if attempt < self.max_attempts - 1:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Timeout for sequence number {sequence_number}. Retransmitting packet.")
                # パケット情報から再送するパケットを再構築
                self.retransmit_packet(connection_key, sequence_number)
                # 再送後に再度timeout設定
                self.schedule_timeout(connection_key, sequence_number)
            else:
                # 最大試行回数に達した場合、パケットをドロップ
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Maximum attempts reached for sequence number: {sequence_number}. Dropping packet.")
                del self.windows[connection_key][sequence_number]  # タイムアウトしたパケットをウィンドウから削除

            # スロースタートに遷移
            self.transition_to_state(connection_key, 'slow_start')

            # タイムアウト処理の完了をログに記録
            if self.network_event_scheduler.tcp_verbose:
                print(f"Timeout handled for connection {connection_key}. State transitioned to slow_start.")

            # タイムアウト後にもsend_next_chunkをスケジュールして再送を促す
            self.schedule_send_next_chunk(connection_key)

    def cancel_timeout(self, connection_key, sequence_number):
        if connection_key in self.tcp_connections and 'timeout_event_ids' in self.tcp_connections[connection_key]:
            if sequence_number in self.tcp_connections[connection_key]['timeout_event_ids']:
                event_id = self.tcp_connections[connection_key]['timeout_event_ids'].pop(sequence_number)
                self.network_event_scheduler.cancel_event(event_id)

    def find_retransmit_sequence_number(self, connection_key):
        # この接続のウィンドウ内で最も小さい未ACKのシーケンス番号を探す
        if connection_key in self.windows:
            unacknowledged_sequence_numbers = self.windows[connection_key].keys()
            if unacknowledged_sequence_numbers:
                # シーケンス番号が未ACKのものだけを抽出し、最小のものを返す
                min_unack_seq_num = min(unacknowledged_sequence_numbers)
                return min_unack_seq_num
        return None  # 再送すべきパケットがない場合

    def retransmit_packet(self, connection_key, sequence_number):
        if connection_key in self.windows and sequence_number in self.windows[connection_key]:
            # パケット情報を windows 辞書から取得
            packet_info = self.windows[connection_key][sequence_number]["packet_info"]
            destination_ip = packet_info['destination_ip']
            destination_mac = packet_info['destination_mac']
            data = packet_info['data']
            dscp = packet_info['dscp']
            kwargs = packet_info['kwargs']

            # パケットを再送信
            if self.network_event_scheduler.tcp_verbose:
                print(f"Retransmitting packet with sequence number {sequence_number} to {destination_ip}:{kwargs.get('destination_port')}")

            self._send_transport_packet("TCP", destination_ip, destination_mac, data, dscp, **kwargs)
            self.windows[connection_key][sequence_number]["attempt"] += 1

            # 再送パケットに対して改めてタイムアウトを設定
            self.schedule_timeout(connection_key, sequence_number)

            if self.windows[connection_key][sequence_number]["attempt"] >= self.max_attempts:
                # 最大試行回数到達時の処理
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Maximum retransmission attempts reached for packet with sequence number {sequence_number}. Resetting connection state.")

                # タイムアウト時のssthreshとcwndの更新
                current_cwnd = self.tcp_connections[connection_key]['cwnd']
                self.tcp_connections[connection_key]['ssthresh'] = max(current_cwnd // 2, 2)
                self.tcp_connections[connection_key]['cwnd'] = 1

                # イベントとウィンドウエントリのクリーンアップ
                self.cancel_timeout(connection_key, sequence_number)
                self.cancel_retransmission_event(connection_key, sequence_number)
                del self.windows[connection_key][sequence_number]

                # スロースタートへの遷移
                self.transition_to_state(connection_key, 'slow_start')
            else:
                # 再送イベントを再スケジュール前にキャンセルしてから再スケジュール
                self.cancel_retransmission_event(connection_key, sequence_number)
                self.schedule_retransmission(connection_key)
        else:
            if self.network_event_scheduler.tcp_verbose:
                print(f"No packet with sequence number {sequence_number} found in history for retransmission.")

    def cancel_retransmission_event(self, connection_key, sequence_number):
        # 再送イベントをシーケンス番号ごとにキャンセルできるようにする
        if connection_key in self.tcp_connections and 'retransmission_event_ids' in self.tcp_connections[connection_key]:
            retrans_ids = self.tcp_connections[connection_key]['retransmission_event_ids']
            if sequence_number in retrans_ids:
                event_id = retrans_ids.pop(sequence_number)
                self.network_event_scheduler.cancel_event(event_id)

    def remove_acked_packets_from_window(self, connection_key, ack_number):
        """
        ACKされたパケットをウィンドウから削除する
        """
        if connection_key not in self.tcp_connections:
            return

        window = self.tcp_connections[connection_key].get('window', [])
        if not window:
            return

        print(f"[DEBUG] Removing acked packets up to {ack_number}")
        print(f"[DEBUG] Window before: {window}")

        # Remove acknowledged packets from window
        self.tcp_connections[connection_key]['window'] = [
            seq for seq in window if seq >= ack_number
        ]

        print(f"[DEBUG] Window after: {self.tcp_connections[connection_key]['window']}")

        # Update next expected sequence number if window is empty
        if not self.tcp_connections[connection_key]['window']:
            self.tcp_connections[connection_key]['next_expected_seq'] = ack_number
            print(f"[DEBUG] Updated next expected sequence to {ack_number}")

    def fast_retransmit(self, connection_key):
        self.transition_to_state(connection_key, 'fast_recovery')
        seq_num = self.find_retransmit_sequence_number(connection_key)
        if seq_num is not None:
            # 再送イベント再設定前に既存イベントキャンセル
            self.cancel_retransmission_event(connection_key, seq_num)
            self.schedule_retransmission(connection_key)
        else:
            # 再送すべきパケットなしの場合の処理
            self.tcp_connections[connection_key]['cwnd'] = self.tcp_connections[connection_key]['ssthresh']
            self.transition_to_state(connection_key, 'congestion_avoidance')

    def schedule_retransmission(self, connection_key):
        sequence_number = self.find_retransmit_sequence_number(connection_key)
        if sequence_number is not None:
            event_time = self.network_event_scheduler.current_time + self.timeout_interval / 2
            event_id = self.network_event_scheduler.schedule_event(event_time, self.retransmit_packet, connection_key, sequence_number)
            self.tcp_connections[connection_key]['retransmission_event_ids'][sequence_number] = event_id
        else:
            if self.network_event_scheduler.tcp_verbose:
                print(f"No packets to retransmit for connection {connection_key}")

    def log_congestion_window(self, connection_key, cwnd, state):
        log_entry = {
            'time': self.network_event_scheduler.current_time,
            'connection': connection_key,
            'cwnd': cwnd,
            'state': state
        }
        self.network_event_scheduler.log_cwnd_event(log_entry)
        if self.network_event_scheduler.tcp_verbose:
            print(f"Logged cwnd event: {log_entry}")

    def adjust_congestion_window(self, connection_key):
        if connection_key not in self.tcp_connections:
            return

        state = self.tcp_connections[connection_key]['congestion_state']
        cwnd = self.tcp_connections[connection_key]['cwnd']
        ssthresh = self.tcp_connections[connection_key]['ssthresh']

        if state == 'slow_start':
            new_cwnd = min(cwnd + 1, self.MAX_CWND)
            self.tcp_connections[connection_key]['cwnd'] = new_cwnd
            self.log_congestion_window(connection_key, new_cwnd, 'slow_start')

            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated cwnd to {new_cwnd} for connection {connection_key} in slow start.")

            if new_cwnd >= ssthresh:
                self.transition_to_state(connection_key, 'congestion_avoidance')

        elif state == 'congestion_avoidance':
            increment = max(1, int(1 / cwnd))
            new_cwnd = min(cwnd + increment, self.MAX_CWND)
            self.tcp_connections[connection_key]['cwnd'] = new_cwnd
            self.log_congestion_window(connection_key, new_cwnd, 'congestion_avoidance')

            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated cwnd to {new_cwnd} for connection {connection_key} in congestion avoidance.")

        elif state == 'fast_recovery':
            new_cwnd = min(cwnd + 1, self.MAX_CWND)
            self.tcp_connections[connection_key]['cwnd'] = new_cwnd
            self.log_congestion_window(connection_key, new_cwnd, 'fast_recovery')

            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated cwnd to {new_cwnd} for connection {connection_key} in fast recovery.")

    def check_duplication_threshold(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if connection_key in self.tcp_connections:
            if self.tcp_connections[connection_key]["duplicate_ack_count"] >= 3:
                if self.network_event_scheduler.tcp_verbose:
                    last_ack_number = self.tcp_connections[connection_key].get("last_ack_number")
                    print(f"Duplicate ACK threshold reached for connection {connection_key} with ACK number {last_ack_number}.")

                # 3重複ACK検出時にfast_retransmitを呼び出し、fast_recoveryに遷移
                self.fast_retransmit(connection_key)
                return True
            else:
                return False
        return False

    def update_ACK_number(self, connection_key, received_sequence_number, payload_length):
        if connection_key not in self.tcp_connections:
            if self.network_event_scheduler.tcp_verbose:
                print(f"Connection key {connection_key} not found for updating ACK number.")
            return

        print(f"[DEBUG] update_ACK_number connection_key={connection_key}, received_seq={received_sequence_number}, payload_len={payload_length}")

        current_ack_number = self.tcp_connections[connection_key]["acknowledgment_number"]
        received_end = received_sequence_number + payload_length

        # Initialize next_expected_seq if not present
        if 'next_expected_seq' not in self.tcp_connections[connection_key]:
            self.tcp_connections[connection_key]['next_expected_seq'] = current_ack_number
            print(f"[DEBUG] Initialized next_expected_seq to {current_ack_number}")

        next_expected = self.tcp_connections[connection_key]['next_expected_seq']

        # TCPの基本動作に従った実装：
        # 1. 期待するシーケンス番号と一致する場合はACKを更新
        # 2. 期待するシーケンス番号より前のデータは既に受信済み
        # 3. 期待するシーケンス番号より後ろのデータは受信バッファに保存（今回は実装省略）
        if received_sequence_number == next_expected:
            self.tcp_connections[connection_key]["acknowledgment_number"] = received_end
            self.tcp_connections[connection_key]['next_expected_seq'] = received_end
            print(f"[DEBUG] Updated ACK to {received_end} (in-order packet)")
        else:
            print(f"[DEBUG] Maintaining ACK {current_ack_number} (out-of-order packet, expected {next_expected})")

    def send_TCP_SYN_ACK(self, connection_key, source_port, sequence_number, dscp):
        acknowledgment_number = sequence_number + 1

        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(
                connection_key=connection_key,
                state='SYN_RECEIVED',
                sequence_number=1,
                acknowledgment_number=acknowledgment_number,
                data=None
            )
        else:
            self.tcp_connections[connection_key]['state'] = 'SYN_RECEIVED'
            self.tcp_connections[connection_key]['acknowledgment_number'] = acknowledgment_number

        control_packet_kwargs = {
            "flags": "SYN,ACK",
            "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
            "acknowledgment_number": self.tcp_connections[connection_key]["acknowledgment_number"],
            "source_port": source_port,
            "destination_port": connection_key[1]
        }

        destination_ip = connection_key[0]
        dscp = dscp
        self._send_control_tcp_packet(destination_ip, b"", dscp, **control_packet_kwargs)

        self.tcp_connections[connection_key]["sequence_number"] += 1

    def establish_TCP_connection(self, connection_key, sequence_number):
        if connection_key in self.tcp_connections:
            if self.tcp_connections[connection_key]['state'] == 'ESTABLISHED':
                return

            # Update connection state
            self.update_tcp_connection_state(connection_key, "ESTABLISHED")

            # Set initial sequence number for this side of connection
            if "sequence_number" not in self.tcp_connections[connection_key]:
                self.tcp_connections[connection_key]["sequence_number"] = 1

            # Set acknowledgment number based on received sequence number
            self.tcp_connections[connection_key]["acknowledgment_number"] = sequence_number + 1

            print(f"[DEBUG] Connection {connection_key} established")
            print(f"[DEBUG] Our sequence number: {self.tcp_connections[connection_key]['sequence_number']}")
            print(f"[DEBUG] Their sequence number: {sequence_number}")
            print(f"[DEBUG] Our ACK number: {self.tcp_connections[connection_key]['acknowledgment_number']}")
            return

        # Initialize new connection
        print(f"[DEBUG] Establishing new connection for {connection_key}")
        print(f"[DEBUG] Received initial sequence number: {sequence_number}")

        source_port = self.get_source_port(connection_key, "TCP")
        self.initialize_connection_info(
            connection_key,
            state='ESTABLISHED',
            sequence_number=1,  # Our initial sequence number
            acknowledgment_number=sequence_number + 1,  # Their sequence number + 1
            source_port=source_port,
            data=b''
        )

        # Initialize transfer info
        if 'transfer_info' not in self.tcp_connections[connection_key]:
            self.tcp_connections[connection_key]['transfer_info'] = {
                'end_time': self.network_event_scheduler.current_time + 3600,
                'payload_size': 1460,
                'bytes_transferred': 0,
                'progress': [],
                'file_size': 0
            }

        # Notify application layer
        if self.application_layer and hasattr(self.application_layer, 'on_connection_established'):
            self.application_layer.on_connection_established(connection_key)

    def send_TCP_ACK(self, connection_key, source_port, dscp):
        if connection_key in self.tcp_connections:
            control_packet_kwargs = {
                "flags": "ACK",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": self.tcp_connections[connection_key]["acknowledgment_number"],
                "source_port": source_port,
                "destination_port": connection_key[1]
            }
            destination_ip = connection_key[0]
            dscp = dscp

            self._send_control_tcp_packet(destination_ip, b"", dscp, **control_packet_kwargs)
        else:
            if self.network_event_scheduler.tcp_verbose:
                print("Error: Connection key not found in tcp_connections.")

    def _send_control_tcp_packet(self, destination_ip, data, dscp, **kwargs):
        """
        TCP制御パケット(SYN, SYN-ACK, ACKなど)送信用の共通処理。
        ARP解決を含め、send_app_data相当の処理を内包することも可能。
        """
        destination_mac = self.get_mac_address_from_ip(destination_ip)
        if destination_mac is None:
            # ARP未解決なら待機
            self.send_arp_request(destination_ip)
            if destination_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[destination_ip] = []
            self.waiting_for_arp_reply[destination_ip].append((data, "TCP", dscp, kwargs))
            return

        self._send_transport_packet("TCP", destination_ip, destination_mac, data, dscp, **kwargs)

    def terminate_TCP_connection(self, connection_key):
        # TCP接続を終了する処理
        if self.network_event_scheduler.tcp_verbose:
            print(f"Terminating TCP connection with {connection_key}") 
        if connection_key in self.tcp_connections:
            del self.tcp_connections[connection_key]
            print(f"TCP connection terminated with {connection_key}")
        else:
            print("Error: Connection key not found.")

    def print_tcp_connections(self):
        """
        このノードのすべてのTCPコネクションの状態を表示します。
        """
        if not self.tcp_connections:
            print("現在、アクティブなTCPコネクションはありません。")
            return

        print("アクティブなTCPコネクションの状態:")
        for connection, state in self.tcp_connections.items():
            destination_ip, destination_port = connection
            print(f"宛先IP: {destination_ip}, 宛先ポート: {destination_port}, 状態: {state['state']}")

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)
        elif isinstance(packet, ARPPacket):
            self.process_ARP_packet(packet)
        elif isinstance(packet, DHCPPacket):
            # DHCPパケットはNodeでは処理せず、アプリケーション層へ通知
            if self.application_layer and hasattr(self.application_layer, 'on_dhcp_packet_received'):
                self.application_layer.on_dhcp_packet_received(packet)
        elif isinstance(packet, DNSPacket):
            # DNSパケットはアプリケーション層へ通知
            if self.application_layer and hasattr(self.application_layer, 'on_dns_packet_received'):
                self.application_layer.on_dns_packet_received(packet)
        elif isinstance(packet, UDPPacket):
            self.process_UDP_packet(packet)
        elif isinstance(packet, TCPPacket):
            self.process_TCP_packet(packet)
        else:
            self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def process_data_packet(self, packet):
        # フラグメンテーション処理等は省略
        self.direct_process_packet(packet)

    def direct_process_packet(self, packet):
        pass

    def on_arp_reply_received(self, source_ip, source_mac):
        if source_ip in self.waiting_for_arp_reply:
            for packet in self.waiting_for_arp_reply[source_ip]:
                if isinstance(packet, TCPPacket):
                    packet.mac_header["destination_mac"] = source_mac
                    self._send_transport_packet(packet)
            del self.waiting_for_arp_reply[source_ip]

    def send_arp_request(self, ip_address):
        arp_request_packet = ARPPacket(
            source_mac=self.mac_address,
            destination_mac="ff:ff:ff:ff:ff:ff",  # ブロードキャストアドレス
            source_ip=self.ip_address,
            destination_ip=ip_address,
            operation="request",
            network_event_scheduler=self.network_event_scheduler
        )
        self._send_packet(arp_request_packet)

    def _send_arp_reply(self, request_packet):
        arp_reply_packet = ARPPacket(
            source_mac=self.mac_address,
            destination_mac=request_packet.header["source_mac"],
            source_ip=self.ip_address,
            destination_ip=request_packet.header["source_ip"],
            operation="reply",
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(arp_reply_packet, "ARP reply", self.node_id)
        self._send_packet(arp_reply_packet)

    def is_tcp_connection_established(self, destination_ip, destination_port):
        key = (destination_ip, destination_port)
        return self.tcp_connections.get(key, {}).get("state") == "ESTABLISHED"

    def update_tcp_connection_state(self, connection_key, new_state):
        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(connection_key=connection_key, state=new_state)
        else:
            self.tcp_connections[connection_key]["state"] = new_state
        if self.network_event_scheduler.tcp_verbose:
            print(f"TCP connection state updated to {new_state} for {connection_key}")

    def get_source_port(self, connection_key, protocol, app_type=None, fixed_port=None):
        """
        connection_key: (dst_ip, dst_port)
        protocol: "TCP" or "UDP"
        app_type: "FTP", "FTPSERVER", etc. (application managerで取得した種別)
        fixed_port: None以外ならこのポートを必ず利用（サーバ固定ポートなど）
        """
        # もしfixed_portが指定されていれば、それを使う
        if fixed_port is not None:
            # fixed_portをused_portsへ登録しておく（初回のみ）
            if fixed_port not in self.used_ports:
                self.used_ports.add(fixed_port)
                self.port_mapping[connection_key] = fixed_port
            return fixed_port

        # fixed_portがない場合、app_typeがFTPServerなら21などと決め打ち
        if app_type == "FTPSERVER":
            # FTPサーバは21固定
            if 21 not in self.used_ports:
                self.used_ports.add(21)
            self.port_mapping[connection_key] = 21
            return 21

        # 上記以外の場合、port_mappingに存在するか確認
        if connection_key in self.port_mapping:
            return self.port_mapping[connection_key]

        # port_mappingにない場合、初回割り当て
        source_port = self.select_available_port()
        self.port_mapping[connection_key] = source_port
        return source_port

    def initiate_tcp_handshake(self, destination_ip, destination_port, source_port=None):
        """
        TCPハンドシェイクを開始する。
        """
        print(f"[DEBUG] Initiating TCP handshake to {destination_ip}:{destination_port} from port {source_port}")

        if source_port is None:
            source_port = self.select_available_port("TCP")

        # コネクションキーを生成（自分のIPとポート）
        connection_key = (self.ip_address, source_port)
        print(f"[DEBUG] Connection key: {connection_key}")

        # コネクション情報を初期化
        if connection_key not in self.tcp_connections:
            print(f"[DEBUG] Initializing new connection for {connection_key}")
            self.initialize_connection_info(connection_key, destination_ip, destination_port)
            self.tcp_connections[connection_key]['state'] = 'SYN_SENT'

            # 初期シーケンス番号を設定
            initial_sequence_number = 0  # 実際のTCPでは乱数を使用
            self.tcp_connections[connection_key]['sequence_number'] = initial_sequence_number
            print(f"[DEBUG] Initial sequence number: {initial_sequence_number}")

            # SYNパケットを送信
            print(f"[DEBUG] Sending SYN packet")
            self.send_control_tcp_packet(
                destination_ip=destination_ip,
                destination_port=destination_port,
                flags="SYN",
                source_port=source_port,
                sequence_number=initial_sequence_number
            )
            return True
        else:
            print(f"[ERROR] Connection {connection_key} already exists")
            return False

    def send_app_data(self, destination_ip, destination_port, data, protocol="TCP", **kwargs):
        """
        アプリケーション層からのデータ送信要求を処理する
        Parameters:
        - destination_ip: 送信先IPアドレス
        - destination_port: 送信先ポート番号
        - data: 送信データ
        - protocol: プロトコル（"TCP" or "UDP"）
        - **kwargs: その他のパラメータ
        """
        if protocol == "TCP":
            print(f"[DEBUG] Sending TCP data to {destination_ip}:{destination_port}")
            print(f"[DEBUG] Data length: {len(data)}")

            connection_key = (destination_ip, destination_port)

            # コネクションが確立されていない場合は送信しない
            if not self.is_tcp_connection_established(connection_key):
                print(f"[DEBUG] Connection not established for {connection_key}")
                return False

            # データを送信
            self._send_tcp_data(
                connection_key,
                destination_ip,
                data,
                **kwargs
            )

            print(f"[DEBUG] TCP data sent successfully to {connection_key}")
            return True

        elif protocol == "UDP":
            # UDPの場合は直接送信
            source_port = kwargs.get('source_port', self.select_available_port())
            destination_mac = self.get_mac_address_from_ip(destination_ip)

            if destination_mac is None:
                print(f"[DEBUG] No MAC address found for {destination_ip}, sending ARP request")
                self.send_arp_request(destination_ip)
                return False

            self._send_transport_packet(
                "UDP",
                destination_ip,
                destination_mac,
                data,
                0,
                source_port=source_port,
                destination_port=destination_port
            )
            print(f"[DEBUG] UDP data sent successfully to {destination_ip}:{destination_port}")
            return True

        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def _send_tcp_data(self, connection_key, destination_ip, data, **kwargs):
        """
        TCP特有のデータ送信処理をまとめたヘルパー関数。
        Parameters:
        - connection_key: コネクションを識別するキー (destination_ip, destination_port)
        - destination_ip: 送信先IPアドレス
        - data: 送信データ
        - **kwargs: その他のパラメータ
        """
        # コネクション情報の取得
        connection_info = self.tcp_connections.get(connection_key)
        if not connection_info:
            print(f"[DEBUG] No connection info found for {connection_key}. Cannot send TCP data.")
            return False

        # 転送情報の取得
        traffic_info = connection_info.get('transfer_info')
        if not traffic_info:
            print(f"[DEBUG] No traffic info found for {connection_key}")
            return False

        # MSSに基づいてデータを分割
        mss = connection_info.get('mss', 1460)
        chunks = [data[i:i + mss] for i in range(0, len(data), mss)]

        for chunk in chunks:
            # TCPパケットの送信に必要な引数を準備
            tcp_args = {
                'source_port': connection_info['source_port'],
                'destination_port': connection_key[1],
                'sequence_number': connection_info['sequence_number'],
                'acknowledgment_number': connection_info['acknowledgment_number'],
                'window_size': connection_info['window_size'],
                'flags': {'PSH': True, 'ACK': True}
            }

            # 送信先MACアドレスの取得
            destination_mac = self.get_mac_address_from_ip(destination_ip)
            if destination_mac is None:
                print(f"[DEBUG] No MAC address found for {destination_ip}, sending ARP request")
                self.send_arp_request(destination_ip)
                if destination_ip not in self.waiting_for_arp_reply:
                    self.waiting_for_arp_reply[destination_ip] = []
                self.waiting_for_arp_reply[destination_ip].append((chunk, "TCP", 0, tcp_args))
                return False

            # TCPパケット送信
            self._send_transport_packet(
                "TCP",
                destination_ip,
                destination_mac,
                chunk,
                0,
                **tcp_args
            )

            # シーケンス番号を更新
            connection_info['sequence_number'] += len(chunk)

        return True

    def send_control_tcp_packet(self, destination_ip, destination_port, flags, source_port=None, data=b'', sequence_number=None, acknowledgment_number=None):
        """
        TCPコントロールパケットを送信する。
        """
        if self.network_event_scheduler.tcp_verbose:
            print(f"Sending TCP packet to {destination_ip}:{destination_port} Flags: {flags} Seq:{sequence_number if sequence_number is not None else 'N/A'} Ack:{acknowledgment_number if acknowledgment_number is not None else 'N/A'}")

        # コネクションキーを生成（自分のIPとポート）
        if source_port is None:
            source_port = self.select_available_port("TCP")
        connection_key = (self.ip_address, source_port)

        # コネクション情報を取得
        connection_info = self.tcp_connections.get(connection_key, {})

        # シーケンス番号とACK番号を設定
        if sequence_number is None:
            sequence_number = connection_info.get('sequence_number', 0)
        if acknowledgment_number is None:
            acknowledgment_number = connection_info.get('acknowledgment_number', 0)

        # 送信先MACアドレスの取得
        destination_mac = self.get_mac_address_from_ip(destination_ip)
        if destination_mac is None:
            # TCPパケットを作成して保存
            packet = TCPPacket(
                source_mac=self.mac_address,
                destination_mac="ff:ff:ff:ff:ff:ff",  # 一時的なブロードキャストアドレス
                source_ip=self.ip_address,
                destination_ip=destination_ip,
                ttl=64,
                fragment_flags={},
                fragment_offset=0,
                header_size=20,
                payload_size=len(data),
                network_event_scheduler=self.network_event_scheduler,
                source_port=source_port,
                destination_port=destination_port,
                sequence_number=sequence_number,
                acknowledgment_number=acknowledgment_number,
                flags=flags
            )
            packet.payload = data

            # パケットを待機リストに追加
            if destination_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[destination_ip] = []
            self.waiting_for_arp_reply[destination_ip].append(packet)

            print(f"[DEBUG] No MAC address found for {destination_ip}, sending ARP request")
            self.send_arp_request(destination_ip)
            return False

        # TCPパケットを作成
        packet = TCPPacket(
            source_mac=self.mac_address,
            destination_mac=destination_mac,
            source_ip=self.ip_address,
            destination_ip=destination_ip,
            ttl=64,
            fragment_flags={},
            fragment_offset=0,
            header_size=20,
            payload_size=len(data),
            network_event_scheduler=self.network_event_scheduler,
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            flags=flags
        )
        packet.payload = data

        # パケットを送信
        self._send_transport_packet(packet)

        # 未確認パケットを記録（SYNまたはPSHフラグがある場合）
        if 'SYN' in flags.split() or 'PSH' in flags.split():
            if connection_key in self.tcp_connections:
                self.tcp_connections[connection_key]['unacked_packets'][sequence_number] = {
                    'packet': packet,
                    'time': self.network_event_scheduler.current_time,
                    'retransmission_count': 0
                }
                # タイムアウトイベントをスケジュール
                self.schedule_timeout(connection_key, sequence_number)

        return True

    def _send_transport_packet(self, packet):
        """
        トランスポート層のパケットを送信する。
        """
        if isinstance(packet, TCPPacket):
            print(f"[DEBUG] Sending TCP packet: Src={packet.source_ip}:{packet.source_port} Dst={packet.destination_ip}:{packet.destination_port} Flags={packet.flags} Seq={packet.sequence_number} Ack={packet.acknowledgment_number}")
            self._send_ip_packet_data(packet)
        else:
            raise ValueError("Invalid packet type")

    def _send_ip_packet_data(self, packet):
        """
        IPパケットを送信する。
        """
        if isinstance(packet, TCPPacket):
            # パケットをそのまま送信
            self._send_packet(packet)
        else:
            raise ValueError("Invalid packet type")

    def _send_packet(self, packet):
        if self.default_route:
            self.default_route.enqueue_packet(packet, self)
        else:
            for link in self.links:
                link.enqueue_packet(packet, self)

    def set_ip_address(self, new_ip):
        self.ip_address = new_ip

    def set_dns_server_ip(self, dns_ip):
        self.dns_server_ip = dns_ip

    def resolve_destination_ip(self, destination_url):
        return self.url_to_ip_mapping.get(destination_url, None)

    def print_url_to_ip_mapping(self):
        print("URL to IP Mapping:")
        if not self.url_to_ip_mapping:
            print("  No entries found.")
            return
        for url, ip_address in self.url_to_ip_mapping.items():
            print(f"  {url}: {ip_address}")

    def __str__(self):
        connected_nodes = [link.node_x.node_id if self != link.node_x else link.node_y.node_id for link in self.links]
        connected_nodes_str = ', '.join(map(str, connected_nodes))
        return f"ノード(ID: {self.node_id}, MACアドレス: {self.mac_address}, 接続: {connected_nodes_str})"
