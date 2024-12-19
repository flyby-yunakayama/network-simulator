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
        self.waiting_for_arp_reply = {}
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

    def select_available_port(self):
        for port in range(1024, 49152):
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port
        raise Exception("No available ports")

    def select_random_port(self):
        return random.randint(1024, 49151)

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
        if self.network_event_scheduler.tcp_verbose:
            print(f"Processing TCP packet from {packet.header['source_ip']}:{packet.header['source_port']} to {packet.header['destination_ip']}:{packet.header['destination_port']}")

        if packet.header["destination_mac"] == self.mac_address:
            if packet.header["destination_ip"] == self.ip_address:
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)
                flags = packet.header.get('flags', '')
                if self.network_event_scheduler.tcp_verbose:
                    print(f"TCP flags: {flags}")

                connection_key = (packet.header["source_ip"], packet.header["source_port"])
                source_port = packet.header["destination_port"]
                sequence_number = packet.header["sequence_number"]
                ack_number = packet.header["acknowledgment_number"]
                dscp = packet.header["dscp"]
                payload_length = len(packet.payload)

                if "SYN" in flags:
                    if "ACK" in flags:
                        self.establish_TCP_connection(connection_key, sequence_number)
                        self.send_TCP_ACK(connection_key, source_port, dscp)
                    else:
                        self.send_TCP_SYN_ACK(connection_key, source_port, sequence_number, dscp)
                    return

                if "ACK" in flags:
                    if connection_key in self.tcp_connections and self.tcp_connections[connection_key]['state'] == 'SYN_RECEIVED':
                        self.establish_TCP_connection(connection_key, sequence_number)
                    self.handle_acknowledgement(connection_key, ack_number)

                if "PSH" in flags:
                    self.update_ACK_number(connection_key, sequence_number, payload_length)
                    self.send_TCP_ACK(connection_key, source_port, dscp)
                    self.process_data_packet(packet)

                if "FIN" in flags:
                    self.terminate_TCP_connection(connection_key)

                if self.application_layer and hasattr(self.application_layer, 'on_packet_received'):
                    self.application_layer.on_packet_received(packet)
                else:
                    self.network_event_scheduler.log_packet_info(packet, "no application found", self.node_id)
            else:
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def initialize_connection_info(self, connection_key=None, state='CLOSED', sequence_number=0, acknowledgment_number=0, data=b''):
        self.tcp_connections[connection_key] = {
            'state': state,
            'sequence_number': sequence_number,
            'sequence_number_base': sequence_number,
            'acknowledgment_number': acknowledgment_number,
            'data': data,
            'last_ack_number': None,
            'duplicate_ack_count': 0,
            'cwnd': self.cwnd,
            'ssthresh': self.ssthresh,
            'congestion_state': 'slow_start',
            'transfer_info': None,
            'timeout_event_ids': {},            # シーケンス番号ごとのtimeoutイベントID管理
            'retransmission_event_ids': {}      # シーケンス番号ごとの再送イベントID管理
        }

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

    def handle_acknowledgement(self, connection_key, ack_number):
        if connection_key not in self.tcp_connections:
            return  # コネクションが存在しない場合は何もしない

        if connection_key in self.tcp_connections:
            print(f"[DEBUG] handle_acknowledgement for {connection_key}, ack_number={ack_number}")
            print(f"[DEBUG] cwnd={self.tcp_connections[connection_key]['cwnd']}, ssthresh={self.tcp_connections[connection_key]['ssthresh']}")

        # ウィンドウ内未ACKパケット一覧表示
        if connection_key in self.windows:
            unacked_seqs = sorted(self.windows[connection_key].keys())
            print(f"[DEBUG] Unacked packets for {connection_key}: {unacked_seqs}")

        if connection_key not in self.windows:
            self.windows[connection_key] = {}  # 必要に応じて初期化

        # ACK番号に一致するパケットをウィンドウから削除
        self.remove_acked_packets_from_window(connection_key, ack_number)

        # 転送情報を取得
        transfer_info = self.tcp_connections[connection_key].get('transfer_info', None)

        # ここからは転送進捗更新など
        if transfer_info and transfer_info['file_size'] > 0:
            sequence_number_base = self.tcp_connections[connection_key].get("sequence_number_base", 0)
            bytes_acked = ack_number - sequence_number_base
            if bytes_acked > transfer_info['bytes_transferred']:
                transfer_info['bytes_transferred'] = bytes_acked
                transfer_info['progress'].append((self.network_event_scheduler.current_time, bytes_acked))
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Transfer Progress: {bytes_acked}/{transfer_info['file_size']} bytes transferred.")

        # 現在のACK番号と前回のACK番号を取得
        last_ack = self.tcp_connections[connection_key].get("last_ack_number", 0)

        # ACK番号の判定
        is_duplicate_ack = (ack_number == last_ack)

        # 最新のACK番号を設定
        self.tcp_connections[connection_key]["last_ack_number"] = ack_number

        # fast_recovery中のpartial ACK処理追加
        state = self.tcp_connections[connection_key]['congestion_state']

        if state == 'fast_recovery':
            seq_to_retransmit = self.find_retransmit_sequence_number(connection_key)
            if seq_to_retransmit is not None:
                # partial ACK判定
                if ack_number > last_ack and ack_number < self.windows[connection_key][seq_to_retransmit]["expected_ack_number"]:
                    # partial ACK時はcwndを1減少させ、最小値を保証
                    self.tcp_connections[connection_key]['cwnd'] = max(
                        self.tcp_connections[connection_key]['cwnd'] - 1,
                        self.tcp_connections[connection_key]['ssthresh']
                    )
                    # パケット再送
                    self.retransmit_packet(connection_key, seq_to_retransmit)
                    self.schedule_send_next_chunk(connection_key)
                    return
                else:
                    # partial ACKでない or 全ACK済みならfast_recovery終了
                    self.tcp_connections[connection_key]['cwnd'] = self.tcp_connections[connection_key]['ssthresh']
                    self.transition_to_state(connection_key, 'congestion_avoidance')
                    self.schedule_send_next_chunk(connection_key)
                    return

        # 通常ACK処理（fast_recoveryでない場合）
        if is_duplicate_ack:
            # 重複ACKとしてカウント
            self.tcp_connections[connection_key]["duplicate_ack_count"] += 1
            if self.tcp_connections[connection_key]["duplicate_ack_count"] >= 3:
                self.fast_retransmit(connection_key)
                self.schedule_send_next_chunk(connection_key)
        else:
            # 新しいACKとして処理
            self.tcp_connections[connection_key]["duplicate_ack_count"] = 0
            self.adjust_congestion_window(connection_key)
            self.schedule_send_next_chunk(connection_key)

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
        for seq, packet_info in list(self.windows[connection_key].items()):
            if packet_info["expected_ack_number"] <= ack_number:
                self.cancel_timeout(connection_key, seq)
                self.cancel_retransmission_event(connection_key, seq)  # 再送イベントのキャンセルを追加
                del self.windows[connection_key][seq]

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
            return  # コネクション情報が存在しない場合は処理をスキップ

        print(f"[DEBUG] update_ACK_number connection_key={connection_key}, received_seq={received_sequence_number}, payload_len={payload_length}")
        old_ack = self.tcp_connections[connection_key]["acknowledgment_number"]
        print(f"[DEBUG] Before update: ack_number={old_ack}")

        # 現在のACK番号を取得
        current_ack_number = self.tcp_connections[connection_key]["acknowledgment_number"]

        # 受信したシーケンス番号をセットに追加
        received_sequence_numbers = self.tcp_connections[connection_key].setdefault('received_sequence_numbers', set())
        for seq in range(received_sequence_number, received_sequence_number + payload_length):
            received_sequence_numbers.add(seq)

        # 連続していない番号をリストに記憶
        out_of_order_packets = self.tcp_connections[connection_key].setdefault('out_of_order_packets', [])

        # 期待する次のシーケンス番号を見つける
        next_expected_seq = current_ack_number
        while next_expected_seq in received_sequence_numbers:
            next_expected_seq += 1

        # 受信したシーケンス番号が連続している場合のみACK番号を更新
        if next_expected_seq != current_ack_number:
            self.tcp_connections[connection_key]["acknowledgment_number"] = next_expected_seq

            # リストから連続するシーケンス番号を削除
            while out_of_order_packets and out_of_order_packets[0] == next_expected_seq:
                next_expected_seq += 1
                out_of_order_packets.pop(0)

            self.tcp_connections[connection_key]['out_of_order_packets'] = out_of_order_packets
            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated ACK number to {next_expected_seq} for connection {connection_key}.")
        else:
            # 受け取っていないパケットが存在する場合、現在のACK番号をそのまま使用
            if received_sequence_number + payload_length not in out_of_order_packets:
                out_of_order_packets.append(received_sequence_number + payload_length)
                out_of_order_packets.sort()

        new_ack = self.tcp_connections[connection_key]["acknowledgment_number"]
        print(f"[DEBUG] After update: ack_number={new_ack}")

    def send_TCP_SYN_ACK(self, connection_key, source_port, sequence_number, dscp):
        acknowledgment_number = sequence_number + 1

        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(
                connection_key=connection_key,
                state='SYN_RECEIVED',
                sequence_number=sequence_number,
                acknowledgment_number=acknowledgment_number,
                data=None
            )

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
            else:
                self.update_tcp_connection_state(connection_key, "ESTABLISHED")
                self.tcp_connections[connection_key]["acknowledgment_number"] = sequence_number + 1
        else:
            initial_seq = randint(1,10000)
            self.initialize_connection_info(
                connection_key,
                state='ESTABLISHED',
                sequence_number=initial_seq,  # 本来は事前段階で記憶した初期値を使用
                acknowledgment_number=sequence_number + 1,
                data=b''
            )

        if 'transfer_info' not in self.tcp_connections[connection_key] or self.tcp_connections[connection_key]['transfer_info'] is None:
            # 長めの有効時間を設定（1時間後まで許可）
            end_time = self.network_event_scheduler.current_time + 3600
            # デフォルトのpayload_size、たとえば1460バイト程度
            payload_size = 1460
            self.tcp_connections[connection_key]['transfer_info'] = {
                'end_time': end_time,
                'payload_size': payload_size,
                # ファイル転送であればapp側で設定するが、ここではデフォルトで0bytes転送済みとする
                'bytes_transferred': 0,
                'progress': [],
                'file_size': 0
            }

        # アプリケーション層へコネクション確立を通知
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

    def on_arp_reply_received(self, destination_ip, destination_mac):
        if destination_ip in self.waiting_for_arp_reply:
            for data, protocol, dscp, kwargs in self.waiting_for_arp_reply[destination_ip]:
                self._send_transport_packet(protocol, destination_ip, destination_mac, data, dscp, **kwargs)
            del self.waiting_for_arp_reply[destination_ip]

    def send_arp_request(self, ip_address):
        arp_request_packet = ARPPacket(
            source_mac=self.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip=self.ip_address,
            destination_ip=ip_address,
            operation="request",
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(arp_request_packet, "ARP request", self.node_id)
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

    def initiate_tcp_handshake(self, destination_ip, destination_port, dscp=0):
        if not self.is_tcp_connection_established(destination_ip, destination_port):
            if self.network_event_scheduler.tcp_verbose:
                print(f"Initiating TCP handshake: Sending SYN to {destination_ip}:{destination_port}")

            connection_key = (destination_ip, destination_port)
            if connection_key not in self.tcp_connections:
                self.initialize_connection_info(
                    connection_key=connection_key,
                    state='SYN_SENT',
                    sequence_number=randint(1, 10000),
                    acknowledgment_number=0,
                    data=b''
                )

            # app_typeをapplication_layerから取得する（なければNone）
            app_type = self.application_layer.connection_app_map.get(connection_key, None)
            source_port = self.get_source_port(connection_key, "TCP", app_type=app_type)

            control_packet_kwargs = {
                "flags": "SYN",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": 0,
                "source_port": source_port,
                "destination_port": destination_port
            }

            # _send_control_tcp_packetを呼んでSYNパケットを送信（ARP未解決時は待機）
            sent = self._send_control_tcp_packet(destination_ip, b"", dscp, **control_packet_kwargs)
            # パケットが実際に送信（_send_transport_packet呼び出し）された場合のみシーケンス番号をインクリメント
            if sent:
                self.tcp_connections[connection_key]["sequence_number"] += 1

    def send_app_data(self, dst_ip, data, protocol="TCP", **kwargs):
        if protocol == "TCP":
            destination_port = kwargs.get('destination_port')
            if not destination_port:
                raise ValueError("TCP connection requires a destination_port")

            connection_key = (dst_ip, destination_port)
            conn_info = self.tcp_connections.get(connection_key)
            if not conn_info:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"No connection info found for {connection_key}. Cannot send data.")
                return

            traffic_info = conn_info.get('transfer_info')
            if not traffic_info:
                # traffic_infoがセットされていない場合も対応
                if self.network_event_scheduler.tcp_verbose:
                    print(f"No traffic info found for {connection_key}, setting up new connection or queueing data.")
                return

            print("###################################")
            print(connection_key, traffic_info)
            print("###################################")

            app_type = self.application_layer.connection_app_map.get(connection_key, None)
            end_time = traffic_info['end_time']
            if self.network_event_scheduler.current_time < end_time:
                new_kwargs = dict(kwargs)
                source_port = self.get_source_port(connection_key, "TCP", app_type=app_type)
                new_kwargs['source_port'] = source_port
                new_kwargs['destination_port'] = destination_port
                self._send_tcp_data(connection_key, dst_ip, data, **new_kwargs)
            else:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"End time reached for {connection_key}. No more data sent.")
            
        elif protocol == "UDP":
            destination_port = kwargs.get('destination_port')
            if not destination_port:
                # destination_portが指定されていないなら、設計的にはおかしいので例外
                # 必要ならデフォルトポートや特定ポートに割り当て
                raise ValueError("UDP communication requires a fixed destination_port")

            connection_key = (dst_ip, destination_port)
            app_type = self.application_layer.connection_app_map.get(connection_key, None)

            assigned_port = kwargs.get('source_port')
            source_port = self.get_source_port(connection_key, "UDP", app_type=app_type, fixed_port=assigned_port)

            destination_mac = self.get_mac_address_from_ip(dst_ip)
            if destination_mac is None:
                # ARP解決など
                self.send_arp_request(dst_ip)
                # ARP解決後に再送するロジックを入れるか、waiting_for_arp_replyに追加するか
                if dst_ip not in self.waiting_for_arp_reply:
                    self.waiting_for_arp_reply[dst_ip] = []
                self.waiting_for_arp_reply[dst_ip].append((data, protocol, 0, {'source_port': source_port, 'destination_port': destination_port}))
                return

            # UDPパケット送信
            self._send_transport_packet("UDP", dst_ip, destination_mac, data, 0, source_port=source_port, destination_port=destination_port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def _send_tcp_data(self, connection_key, dst_ip, data, **kwargs):
        """
        TCP特有のデータ送信処理をまとめたヘルパー関数。
        Nodeのconnection_keyに対応するコネクション情報、appからのdata取得やsplitを行う。
        """
        # Nodeのtcp_connectionsからコネクション情報を取得
        connection_info = self.tcp_connections.get(connection_key)
        if not connection_info:
            if self.network_event_scheduler.tcp_verbose:
                print(f"[DEBUG] No connection info found for {connection_key}. Cannot send TCP data.")
            return

        # transfer_infoを取得
        traffic_info = connection_info.get('transfer_info')
        if not traffic_info:
            if self.network_event_scheduler.tcp_verbose:
                print(f"[DEBUG] No transfer_info found for {connection_key}. Cannot send TCP data.")
            return

        payload_size = traffic_info['payload_size']
        data_chunks = [data[i:i+payload_size] for i in range(0, len(data), payload_size)]

        # 一度割り当てたソースポートを再利用
        if connection_key not in self.port_mapping:
            # 通常はハンドシェイク時に決まっているはず
            self.port_mapping[connection_key] = self.select_available_port()
        source_port = self.port_mapping[connection_key]
        destination_port = kwargs.get('destination_port')
        if not destination_port:
            # connection_keyから取得
            dst_ip_key, dst_port_key = connection_key
            destination_port = dst_port_key

        for chunk in data_chunks:
            tcp_args = {
                "source_port": source_port,
                "destination_port": destination_port,
                "sequence_number": self.tcp_connections[connection_key]['sequence_number'],
                "acknowledgment_number": self.tcp_connections[connection_key]['acknowledgment_number'],
                "flags": "PSH"
            }

            destination_mac = self.get_mac_address_from_ip(dst_ip)
            if not destination_mac:
                # ARPリクエストなど
                self.send_arp_request(dst_ip)
                # 待ち行列へ
                if dst_ip not in self.waiting_for_arp_reply:
                    self.waiting_for_arp_reply[dst_ip] = []
                self.waiting_for_arp_reply[dst_ip].append((chunk, "TCP", 0, tcp_args))
                return

            self._send_transport_packet("TCP", dst_ip, destination_mac, chunk, 0, **tcp_args)

            # ウィンドウ管理やシーケンス番号更新、再送タイマー設定など
            seq_num = self.tcp_connections[connection_key]['sequence_number']
            expected_ack = seq_num + len(chunk)

            if connection_key not in self.windows:
                self.windows[connection_key] = {}
            self.windows[connection_key][seq_num] = {
                "packet_info": {
                    'destination_ip': dst_ip,
                    'destination_mac': destination_mac,
                    'data': chunk,
                    'dscp': 0,
                    'kwargs': tcp_args
                },
                "expected_ack_number": expected_ack,
                "attempt": 0
            }
            self.schedule_timeout(connection_key, seq_num)
            self.tcp_connections[connection_key]['sequence_number'] = expected_ack

            # ファイル転送中で、まだtransfer_doneがFalseかつ実データがある場合のみupdate_data_after_sendを呼ぶ
            if traffic_info and traffic_info.get('file_size', 0) > 0 and not traffic_info.get('transfer_done', False) and len(chunk) > 0:
                app = self.application_layer
                app.update_data_after_send(connection_key, len(chunk))

    def send_control_tcp_packet(self, dst_ip, data, dscp=0, source_port=None, destination_port=None, flags="ACK"):
        """
        制御メッセージ(FTPの220,331,230,150,226など)を送信するための関数。
        file_sizeやtransfer_doneなどファイル転送特有のロジックは排除するが、
        コネクションやポート割り当ての処理はsend_app_dataと同様に行う必要がある。
        """

        # パラメータチェック
        if not destination_port:
            raise ValueError("send_control_tcp_packet requires a destination_port")

        # connection_keyを生成
        connection_key = (dst_ip, destination_port)

        # app_type（FTPサーバやクライアントなど）を取得
        app_type = self.application_layer.connection_app_map.get(connection_key, None)

        # TCPの場合、ソースポートが未指定なら割り当てる
        if source_port is None:
            source_port = self.get_source_port(connection_key, "TCP", app_type=app_type)

        # port_mappingがない場合はここで設定
        if connection_key not in self.port_mapping:
            self.port_mapping[connection_key] = source_port

        # tcp_connectionsがない場合は初期化する
        if connection_key not in self.tcp_connections:
            # まだコネクション情報がない場合は適当に初期化する。
            # ここではシーケンス番号やACK番号を0で初期化する。
            self.initialize_connection_info(connection_key=connection_key, state='ESTABLISHED', sequence_number=0, acknowledgment_number=0, data=b'')

        # tcp_connectionsからシーケンス番号等を取得
        seq_num = self.tcp_connections[connection_key]['sequence_number']
        ack_num = self.tcp_connections[connection_key]['acknowledgment_number']

        # データ送信後にシーケンス番号を進める
        # control packetは単発のメッセージなので、送信後にseq_numを増やすだけでOK
        # アプリ側でACKがくるまでは特に大きく管理しなくてもよい
        self.tcp_connections[connection_key]['sequence_number'] = seq_num + len(data)

        # 宛先MACアドレスをARPで取得または待機
        destination_mac = self.get_mac_address_from_ip(dst_ip)
        if destination_mac is None:
            self.send_arp_request(dst_ip)
            if dst_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[dst_ip] = []
            self.waiting_for_arp_reply[dst_ip].append((data, "TCP", dscp, {
                "source_port": source_port,
                "destination_port": destination_port,
                "flags": flags
            }))
            return

        # ファイル転送ロジック(update_data_after_send)は呼ばず、
        # 直接_transport_packetでパケット送信
        self._send_transport_packet("TCP", dst_ip, destination_mac, data, dscp,
                                    source_port=source_port,
                                    destination_port=destination_port,
                                    sequence_number=seq_num,
                                    acknowledgment_number=ack_num,
                                    flags=flags)

    def _send_transport_packet(self, protocol, destination_ip, destination_mac, data, dscp, **kwargs):
        if protocol == "UDP":
            transport_header_size = 8
        elif protocol == "TCP":
            transport_header_size = 20
        else:
            raise ValueError(f"Unknown transport protocol: {protocol}")

        ip_header_size = 20
        header_size = ip_header_size + transport_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, dscp, header_size, protocol=protocol, **kwargs)

        if protocol == "TCP" and self.network_event_scheduler.tcp_verbose:
            print(f"Sending TCP packet to {destination_ip}:{kwargs.get('destination_port')} Flags: {kwargs.get('flags')} Seq:{kwargs.get('sequence_number')} Ack:{kwargs.get('acknowledgment_number')}")

    def _send_ip_packet_data(self, destination_ip, destination_mac, data, dscp, header_size, protocol, **kwargs):
        original_data_id = str(uuid.uuid4())
        total_size = len(data) if data else 0
        offset = 0

        while offset < total_size or (offset == 0 and total_size == 0):
            max_payload_size = self.mtu - header_size
            payload_size = min(max_payload_size, total_size - offset) if data else 0
            fragment_data = data[offset:offset + payload_size] if data else b""
            fragment_offset = offset
            more_fragments = False if total_size == 0 else offset + payload_size < total_size
            fragment_flags = {"more_fragments": more_fragments}
            if more_fragments or payload_size > 0:
                fragment_flags["original_data_id"] = original_data_id

            if protocol == "UDP":
                packet = UDPPacket(
                    source_mac=self.mac_address,
                    destination_mac=destination_mac,
                    source_ip=self.ip_address,
                    destination_ip=destination_ip,
                    ttl=64,
                    dscp=dscp,
                    network_event_scheduler=self.network_event_scheduler,
                    fragment_flags=fragment_flags,
                    fragment_offset=fragment_offset,
                    header_size=header_size,
                    payload_size=payload_size,
                    source_port=kwargs.get('source_port'),
                    destination_port=kwargs.get('destination_port')
                )
            elif protocol == "TCP":
                packet = TCPPacket(
                    source_mac=self.mac_address,
                    destination_mac=destination_mac,
                    source_ip=self.ip_address,
                    destination_ip=destination_ip,
                    ttl=64,
                    dscp=dscp,
                    network_event_scheduler=self.network_event_scheduler,
                    fragment_flags=fragment_flags,
                    fragment_offset=fragment_offset,
                    header_size=header_size,
                    payload_size=payload_size,
                    source_port=kwargs.get('source_port'),
                    destination_port=kwargs.get('destination_port'),
                    sequence_number=kwargs.get('sequence_number', 0),
                    acknowledgment_number=kwargs.get('acknowledgment_number', 0),
                    flags=kwargs.get('flags', '')
                )

            packet.payload = fragment_data
            self._send_packet(packet)

            if not data:
                break
            offset += payload_size

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
