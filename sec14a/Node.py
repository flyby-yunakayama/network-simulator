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
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None, dns_server=None, mtu=1500, default_route=None):
        self.node_id = node_id
        self.ip_address = ip_address  # IPアドレス
        self.network_event_scheduler = network_event_scheduler
        self.local_seed = self.network_event_scheduler.get_seed()
        if self.local_seed is not None:
            random.seed(self.local_seed)
        if mac_address is None:
            self.mac_address = self.generate_mac_address()  # ランダムなMACアドレスを生成
        else:
            if not self.is_valid_mac_address(mac_address):
                raise ValueError("無効なMACアドレス形式です。")
            self.mac_address = mac_address  # MACアドレス
        self.links = []
        self.applications = {} # ポート・プロトコルごとのアプリケーションインスタンス
        self.used_ports = set()  # 使用中のポート番号を保持するセット
        self.port_mapping = {}  # source_portをキーとし、destination_portを値とする辞書
        self.tcp_connections = {}  # 接続状態を追跡する辞書
        self.cwnd = 1  # 輻輳ウィンドウの初期値
        self.ssthresh = 16  # スロースタート閾値の初期値
        self.MAX_CWND = 64
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
        # ランダムなMACアドレスを生成
        return ':'.join(['{:02x}'.format((uuid.uuid4().int >> (i*8)) & 0xff) for i in range(6)])

    def register_application(self, port, protocol, application_instance):
        self.applications[(port, protocol)] = application_instance
        # application_instanceがFTPServerの場合にApplicationManagerへも登録
        if hasattr(application_instance, "__class__") and application_instance.__class__.__name__ == "FTPServer":
            # FTPServerと判定できたらApplicationManagerのregister_ftp_server呼び出し
            if self.application_layer and hasattr(self.application_layer, 'register_ftp_server'):
                self.application_layer.register_ftp_server(application_instance)

    def select_available_port(self):
        for port in range(1024, 49152):
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port
        raise Exception("No available ports")

    def select_random_port(self):
        return random.randint(1024, 49151)

    def assign_destination_port(self, source_port):
        destination_port = self.select_random_port()
        self.port_mapping[source_port] = destination_port
        return destination_port

    def get_destination_port(self, source_port):
        if source_port not in self.port_mapping:
            return self.assign_destination_port(source_port)
        return self.port_mapping[source_port]

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
        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF":  # ブロードキャスト
            self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
            packet.set_arrived(self.network_event_scheduler.current_time)
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

    def add_dns_record(self, domain_name, ip_address):
        self.url_to_ip_mapping[domain_name] = ip_address

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

                # Check TCP flags
                flags = packet.header.get('flags', '')
                if self.network_event_scheduler.tcp_verbose:
                    print(f"TCP flags: {flags}")

                # SYNパケットの処理
                if "SYN" in flags:
                    if "ACK" in flags:  # SYN-ACK受信（クライアント側想定）
                        self.establish_TCP_connection(packet)
                        self.send_TCP_ACK(packet)
                    else:
                        # サーバ側がSYN受信（LISTEN状態想定）でSYN,ACK返答→SYN_RECEIVEDへ遷移
                        self.send_TCP_SYN_ACK(packet)
                    return

                if "ACK" in flags:
                    # ACK受信時にSYN_RECEIVED→ESTABLISHEDへの遷移を確認
                    connection_key = (packet.header["source_ip"], packet.header["source_port"])
                    # コネクションがSYN_RECEIVEDだった場合、ここでestablish_TCP_connectionを呼ぶ
                    if connection_key in self.tcp_connections and self.tcp_connections[connection_key]['state'] == 'SYN_RECEIVED':
                        # ACK受信したのでESTABLISHEDへ移行
                        self.establish_TCP_connection(packet)
                    
                    self.handle_acknowledgement(packet)

                if "PSH" in flags:
                    self.update_ACK_number(packet)
                    self.send_TCP_ACK(packet)
                    self.process_data_packet(packet)

                if "FIN" in flags:
                    self.terminate_TCP_connection(packet)

                # アプリ層へ通知
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
            'transfer_info': None
        }

    def transition_to_state(self, connection_key, new_state):
        """指定された状態へ遷移し、関連する操作を行います。"""
        if connection_key not in self.tcp_connections:
            return

        current_state = self.tcp_connections[connection_key]['congestion_state']
        if current_state == new_state:
            return  # 同じ状態に遷移しようとした場合は何もしない

        # 現在のcwndとssthreshを取得
        cwnd = self.tcp_connections[connection_key]['cwnd']
        ssthresh = self.tcp_connections[connection_key]['ssthresh']

        if new_state == 'slow_start':
            # スロースタート状態への遷移
            self.tcp_connections[connection_key]['cwnd'] = 1
            self.tcp_connections[connection_key]['ssthresh'] = max(cwnd // 2, 2)
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. ssthresh set to {ssthresh}, cwnd reset to 1.")

        elif new_state == 'congestion_avoidance':
            # 輻輳回避状態への遷移
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. Continuing to increase cwnd linearly.")

        elif new_state == 'fast_recovery':
            # Fast Recovery状態への遷移
            self.tcp_connections[connection_key]['ssthresh'] = max(cwnd // 2, 2)
            self.tcp_connections[connection_key]['cwnd'] = ssthresh + 3  # ssthresh + 3つの重複ACKを考慮
            self.tcp_connections[connection_key]['congestion_state'] = new_state
            if self.network_event_scheduler.tcp_verbose:
                print(f"Transitioning to {new_state} for connection {connection_key}. cwnd set to {self.tcp_connections[connection_key]['cwnd']}.")

        self.log_congestion_window(connection_key, self.tcp_connections[connection_key]['cwnd'], new_state)

    def handle_acknowledgement(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        ack_number = packet.header["acknowledgment_number"]

        if connection_key not in self.tcp_connections:
            return  # コネクションが存在しない場合は何もしない
        
        if connection_key not in self.windows:
            self.windows[connection_key] = {}  # 必要に応じて初期化

        # ACK番号に一致するパケットをウィンドウから削除
        self.remove_acked_packets_from_window(connection_key, ack_number)

        # 転送情報を取得
        transfer_info = self.tcp_connections[connection_key].get('transfer_info', None)

        if transfer_info:
            # シーケンス番号のベースを取得
            sequence_number_base = self.tcp_connections[connection_key].get("sequence_number_base", 0)
            bytes_acked = ack_number - sequence_number_base
            if bytes_acked > transfer_info['bytes_transferred']:
                transfer_info['bytes_transferred'] = bytes_acked
                # 進行状況を記録
                transfer_info['progress'].append((self.network_event_scheduler.current_time, bytes_acked))
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Transfer Progress: {bytes_acked}/{transfer_info['file_size']} bytes transferred.")

        # 重複ACKの処理
        if self.tcp_connections[connection_key]["last_ack_number"] == ack_number:
            self.tcp_connections[connection_key]["duplicate_ack_count"] += 1
            if self.tcp_connections[connection_key]["duplicate_ack_count"] >= 3:
                self.fast_retransmit(connection_key)  # Fast retransmit
            else:
                # cwndの調整（重複ACKではなく、送信データがNoneでない場合のみ）
                if self.tcp_connections[connection_key]['data'] is not None:
                    self.adjust_congestion_window(connection_key)
                    self.send_tcp_data_packet(packet)
        else:
            self.tcp_connections[connection_key]["duplicate_ack_count"] = 0
            self.tcp_connections[connection_key]["last_ack_number"] = ack_number
            # cwndの調整（重複ACKではなく、送信データがNoneでない場合のみ）
            if self.tcp_connections[connection_key]['data'] is not None:
                self.adjust_congestion_window(connection_key)
                self.send_tcp_data_packet(packet)

    def remove_acked_packets_from_window(self, connection_key, ack_number):
        for seq, packet_info in list(self.windows[connection_key].items()):
            if packet_info["expected_ack_number"] <= ack_number:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Removing packet with sequence number {seq} from window for connection {connection_key} due to receiving ACK {ack_number}. Expected ACK was {packet_info['expected_ack_number']}.")
                # タイムアウトイベントのキャンセル
                self.cancel_timeout(connection_key, seq)
                del self.windows[connection_key][seq]

    def fast_retransmit(self, connection_key):
        self.transition_to_state(connection_key, 'fast_recovery')
        self.schedule_retransmission(connection_key)

    def schedule_retransmission(self, connection_key):
        sequence_number = self.find_retransmit_sequence_number(connection_key)
        if sequence_number is not None:
            event_time = self.network_event_scheduler.current_time + self.timeout_interval / 2
            self.network_event_scheduler.schedule_event(event_time, self.retransmit_packet, connection_key, sequence_number)
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
            # スロースタート: cwndを指数関数的に増加させる
            new_cwnd = min(cwnd + 1, self.MAX_CWND)
            self.tcp_connections[connection_key]['cwnd'] = new_cwnd
            self.log_congestion_window(connection_key, new_cwnd, 'slow_start')

            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated cwnd to {new_cwnd} for connection {connection_key} in slow start.")

            if new_cwnd >= ssthresh:
                # ssthreshに達したら輻輳回避へ移行
                self.transition_to_state(connection_key, 'congestion_avoidance')

        elif state == 'congestion_avoidance':
            # 輻輳回避: cwndを線形に増加
            new_cwnd = min(cwnd + (1 / cwnd), self.MAX_CWND)
            self.tcp_connections[connection_key]['cwnd'] = new_cwnd
            self.log_congestion_window(connection_key, new_cwnd, 'congestion_avoidance')

            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated cwnd to {new_cwnd} for connection {connection_key} in congestion avoidance.")

        elif state == 'fast_recovery':
            # Fast Recovery: cwndを1増加させる
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

                # スロースタート状態への遷移
                self.transition_to_state(connection_key, 'slow_start')

                return True
            else:
                return False
        return False

    def update_ACK_number(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if connection_key not in self.tcp_connections:
            return  # コネクション情報が存在しない場合は処理をスキップ

        received_sequence_number = packet.header["sequence_number"]
        payload_length = len(packet.payload)

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

    def send_TCP_SYN_ACK(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        
        sequence_number = randint(1, 10000)
        # 受信したSYNパケットのシーケンス番号に1を加えたものがACK番号
        acknowledgment_number = packet.header["sequence_number"] + 1

        # 新しい接続情報を初期化
        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(connection_key=connection_key, state='SYN_RECEIVED', sequence_number=sequence_number, acknowledgment_number=acknowledgment_number, data=None)

        # パラメータ設定
        control_packet_kwargs = {
            "flags": "SYN,ACK",
            "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
            "acknowledgment_number": self.tcp_connections[connection_key]["acknowledgment_number"],
            "source_port": packet.header["destination_port"],
            "destination_port": packet.header["source_port"]
        }
        self._send_tcp_packet(
            destination_ip=packet.header["source_ip"],
            destination_mac=packet.header["source_mac"],
            data=b"",
            dscp=packet.header["dscp"],
            **control_packet_kwargs
        )

        self.tcp_connections[connection_key]["sequence_number"] += 1

    def establish_TCP_connection(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if connection_key in self.tcp_connections:
            if self.tcp_connections[connection_key]['state'] == 'ESTABLISHED':
                return
            else:
                self.update_tcp_connection_state(connection_key, "ESTABLISHED")
                self.tcp_connections[connection_key]["acknowledgment_number"] = packet.header["sequence_number"] + 1
        else:
            # コネクション情報初期化など
            self.initialize_connection_info(connection_key, state='ESTABLISHED')
            self.tcp_connections[connection_key]["acknowledgment_number"] = packet.header["sequence_number"] + 1

        # アプリケーション層へコネクション確立を通知
        if self.application_layer and hasattr(self.application_layer, 'on_connection_established'):
            self.application_layer.on_connection_established(connection_key)

    def send_TCP_ACK(self, packet):
        # コネクションキーを生成
        connection_key = (packet.header["source_ip"], packet.header["source_port"])

        if connection_key in self.tcp_connections:
            # パラメータ設定
            control_packet_kwargs = {
                "flags": "ACK",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": self.tcp_connections[connection_key]["acknowledgment_number"],
                "source_port": packet.header["destination_port"],
                "destination_port": packet.header["source_port"]
            }
            self._send_tcp_packet(
                destination_ip=packet.header["source_ip"],
                destination_mac=packet.header["source_mac"],
                data=b"",
                dscp=packet.header["dscp"],
                **control_packet_kwargs
            )
        else:
            if self.network_event_scheduler.tcp_verbose:
                print("Error: Connection key not found in tcp_connections.")

    def terminate_TCP_connection(self, packet):
        # TCP接続を終了する処理
        if self.network_event_scheduler.tcp_verbose:
            print(f"Terminating TCP connection with {packet.header['source_ip']}:{packet.header['source_port']}") 
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
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
            for packet_info in self.waiting_for_arp_reply[destination_ip]:
                data, protocol, dscp, kwargs = packet_info
                self.send_packet(destination_ip, data, protocol=protocol, dscp=dscp, **kwargs)
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

    def send_packet(self, destination_ip, data, protocol, dscp, **kwargs):
        destination_mac = self.get_mac_address_from_ip(destination_ip)

        if destination_mac is None:
            self.send_arp_request(destination_ip)
            if destination_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[destination_ip] = []
            self.waiting_for_arp_reply[destination_ip].append((data, protocol, dscp, kwargs))
        else:
            if protocol == "UDP":
                self._send_udp_packet(destination_ip, destination_mac, data, dscp, **kwargs)
            elif protocol == "TCP":
                if not self.is_tcp_connection_established(destination_ip, kwargs.get('destination_port')):
                    connection_key = (destination_ip, kwargs.get('destination_port'))
                    self.pending_tcp_data[connection_key] = {"data": data, "kwargs": kwargs}
                    self.initiate_tcp_handshake(destination_ip, destination_mac, dscp, **kwargs)
                else:
                    self._send_tcp_packet(destination_ip, destination_mac, data, dscp, **kwargs)

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

    def initiate_tcp_connection(self, destination_ip, destination_port, dscp=0):
        # TCPコネクション開始用のラッパメソッド
        # MACアドレスはARPを使って取得するため、send_packetでSYNパケットを送る。
        source_port = self.select_random_port()
        self.send_packet(
            destination_ip=destination_ip,
            data=b'',
            protocol="TCP",
            dscp=dscp,
            source_port=source_port,
            destination_port=destination_port,
            flags="SYN"
        )

    def initiate_tcp_handshake(self, destination_ip, destination_mac, dscp, **kwargs):
        if not self.is_tcp_connection_established(destination_ip, kwargs.get('destination_port')):
            if self.network_event_scheduler.tcp_verbose:
                print(f"Initiating TCP handshake: Sending SYN to {destination_ip}:{kwargs.get('destination_port')}")

            connection_key = (destination_ip, kwargs.get('destination_port'))
            if connection_key not in self.tcp_connections:
                self.initialize_connection_info(connection_key=connection_key, state='SYN_SENT', sequence_number=randint(1, 10000), acknowledgment_number=0, data=b'')

            control_packet_kwargs = {
                "flags": "SYN",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": 0,
                "source_port": kwargs.get('source_port'),
                "destination_port": kwargs.get('destination_port'),
                "payload_size": 0
            }
            self._send_tcp_packet(destination_ip, destination_mac, b"", dscp, **control_packet_kwargs)
            self.tcp_connections[connection_key]["sequence_number"] += 1

    def _send_udp_packet(self, destination_ip, destination_mac, data, dscp, **kwargs):
        udp_header_size = 8
        ip_header_size = 20
        header_size = udp_header_size + ip_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, dscp, header_size, protocol="UDP", **kwargs)

    def send_tcp_data_packet(self, packet, attempt=0):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        app = self.application_layer  # ApplicationManagerインスタンス

        traffic_info = app.get_traffic_info(connection_key)
        if not traffic_info:
            if self.network_event_scheduler.tcp_verbose:
                print(f"No traffic info found for {connection_key}")
            return

        end_time = traffic_info['end_time']
        if self.network_event_scheduler.current_time < end_time:
            if connection_key not in self.windows:
                self.windows[connection_key] = {}

            cwnd = self.tcp_connections[connection_key]['cwnd']
            if len(self.windows[connection_key]) < cwnd:
                remaining_data = app.outgoing_data.get(connection_key, b'')
                if not remaining_data:
                    # もう送るデータがない
                    return

                payload_size = traffic_info['payload_size']
                data_to_send = app.get_data_chunk(connection_key, payload_size)

                if not data_to_send:
                    # ペイロードサイズ分取り出せなかった場合も終了
                    return

                data_packet_kwargs = {
                    "source_port": packet.header["destination_port"],
                    "destination_port": packet.header["source_port"],
                    "sequence_number": self.tcp_connections[connection_key]['sequence_number'],
                    "acknowledgment_number": self.tcp_connections[connection_key]['acknowledgment_number'],
                    "flags": "PSH"
                }

                # 実際のTCPパケット送信
                self._send_tcp_packet(
                    destination_ip=packet.header["source_ip"],
                    destination_mac=packet.header["source_mac"],
                    data=data_to_send,
                    dscp=packet.header["dscp"],
                    **data_packet_kwargs
                )

                sequence_number = self.tcp_connections[connection_key]['sequence_number']
                expected_ack_number = sequence_number + len(data_to_send)
                self.windows[connection_key][sequence_number] = {
                    "packet_info": {
                        'destination_ip': packet.header["source_ip"],
                        'destination_mac': packet.header["source_mac"],
                        'data': data_to_send,
                        'dscp': packet.header["dscp"],
                        'kwargs': data_packet_kwargs
                    },
                    "expected_ack_number": expected_ack_number,
                    "attempt": attempt
                }

                self.schedule_timeout(connection_key, sequence_number)
                self.tcp_connections[connection_key]['sequence_number'] += len(data_to_send)

                app.update_data_after_send(connection_key, len(data_to_send))

                if app.outgoing_data.get(connection_key, b''):
                    self.send_tcp_data_packet(packet, attempt)

    def _send_tcp_packet(self, destination_ip, destination_mac, data, dscp, **kwargs):
        tcp_header_size = 20
        ip_header_size = 20
        header_size = tcp_header_size + ip_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, dscp, header_size, protocol="TCP", **kwargs)

        if self.network_event_scheduler.tcp_verbose:
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
