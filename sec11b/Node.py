import uuid
import re
import random
from random import randint
from ipaddress import ip_interface, ip_network
from sec11b.Switch import Switch
from sec11b.Router import Router
from sec11b.Packet import Packet, UDPPacket, TCPPacket, ARPPacket, DNSPacket, DHCPPacket

class Node:
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None, dns_server=None, mtu=1500, default_route=None):
        self.node_id = node_id
        self.ip_address = ip_address  # IPアドレス
        self.network_event_scheduler = network_event_scheduler
        if mac_address is None:
            self.mac_address = self.generate_mac_address()  # ランダムなMACアドレスを生成
        else:
            if not self.is_valid_mac_address(mac_address):
                raise ValueError("無効なMACアドレス形式です。")
            self.mac_address = mac_address  # MACアドレス
        self.links = []
        self.used_ports = set()  # 使用中のポート番号を保持するセット
        self.port_mapping = {}  # source_portをキーとし、destination_portを値とする辞書
        self.tcp_connections = {}  # 接続状態を追跡する辞書
        self.pending_tcp_data = {}  # 未確立のTCP接続に対するデータを一時的に保存する辞書
        self.arp_table = {}  # IPアドレスとMACアドレスのマッピングを保持するARPテーブル
        self.waiting_for_arp_reply = {}  # 宛先IPをキーとした待機中のパケットリスト
        self.dns_server_ip = dns_server  # DNSサーバのIPアドレス
        self.url_to_ip_mapping = {}  # URLとIPアドレスのマッピングを保持するDNSテーブル
        self.waiting_for_dns_reply = {}  # DNSレスポンスを待っているパケットを保存する辞書
        self.mtu = mtu  # Maximum Transmission Unit (MTU)
        self.fragmented_packets = {}  # フラグメントされたパケットの一時格納用
        self.default_route = default_route
        label = f'Node {node_id}\n{mac_address}'

        self.schedule_dhcp_packet()
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

    def is_network_address(self, address):
        try:
            # ip_interfaceを使用して、指定されたアドレスのインターフェースオブジェクトを作成
            interface = ip_interface(address)
            # 指定されたアドレスのネットワークオブジェクトを取得
            network = ip_network(address, strict=False)
            # ネットワークアドレスそのものであるかを判断
            return interface.ip == network.network_address and interface.network.prefixlen == network.prefixlen
        except ValueError:
            # 不正なアドレス形式の場合はFalseを返す
            return False

    def add_link(self, link, ip_address=None):
        if link not in self.links:
            self.links.append(link)

    def generate_mac_address(self):
        # ランダムなMACアドレスを生成
        return ':'.join(['{:02x}'.format(uuid.uuid4().int >> elements & 0xff) for elements in range(0, 12, 2)])

    def select_available_port(self):
        for port in range(1024, 49152):
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port
        raise Exception("No available ports")

    def select_random_port(self):
        """
        ランダムにポート番号を選択します。
        一般的には、1024以上49151以下の範囲で選択します（ウェルノウンポートとダイナミックポートを避けるため）。
        """
        return random.randint(1024, 49151)

    def assign_destination_port(self, source_port):
        """
        source_portに対してランダムなdestination_portを選択し、マッピングに記録します。
        """
        destination_port = self.select_random_port()
        self.port_mapping[source_port] = destination_port
        return destination_port

    def get_destination_port(self, source_port):
        """
        与えられたsource_portに対応するdestination_portを返します。
        存在しない場合は新しく割り当てます。
        """
        if source_port not in self.port_mapping:
            return self.assign_destination_port(source_port)
        return self.port_mapping[source_port]

    def schedule_dhcp_packet(self):
        if self.is_network_address(self.ip_address):
            initial_delay = random.uniform(0.5, 0.6)
            self.network_event_scheduler.schedule_event(
                self.network_event_scheduler.current_time + initial_delay,
                self.send_dhcp_discover
            )

    def send_dhcp_discover(self):
        dhcp_discover_packet = DHCPPacket(
            source_mac=self.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",  # DHCP Discoverはブロードキャストアドレスへ送信される
            source_ip="0.0.0.0/32",  # ソースIPは未割り当て状態で0.0.0.0を使用
            destination_ip="255.255.255.255/32",  # 宛先IPはブロードキャストアドレス
            message_type="DISCOVER",
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(dhcp_discover_packet, "DHCP Discover sent", self.node_id)
        self._send_packet(dhcp_discover_packet)

    def send_dhcp_request(self, requested_ip):
        dhcp_request_packet = DHCPPacket(
            source_mac=self.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",  # DHCP Requestはブロードキャストアドレスへ送信される
            source_ip="0.0.0.0/32",  # ソースIPは未割り当て状態で0.0.0.0を使用
            destination_ip="255.255.255.255/32",  # 宛先IPはブロードキャストアドレス
            message_type="REQUEST",
            network_event_scheduler=self.network_event_scheduler
        )
        # OfferされたIPアドレスをリクエストするための情報をdhcp_dataにセット
        dhcp_request_packet.dhcp_data = {"requested_ip": requested_ip}
        # DHCP Requestパケットを送信
        self.network_event_scheduler.log_packet_info(dhcp_request_packet, "DHCP Request sent", self.node_id)
        self._send_packet(dhcp_request_packet)

    def add_to_arp_table(self, ip_address, mac_address):
        # ARPテーブルにIPアドレスとMACアドレスのマッピングを追加
        self.arp_table[ip_address] = mac_address

    def get_mac_address_from_ip(self, ip_address):
        # 指定されたIPアドレスに対応するMACアドレスをARPテーブルから取得
        return self.arp_table.get(ip_address, None)

    def print_arp_table(self):
        print(f"ARPテーブル（ノード {self.node_id}）:")
        for ip_address, mac_address in self.arp_table.items():
            print(f"IPアドレス: {ip_address} -> MACアドレス: {mac_address}")

    def mark_ip_as_used(self, ip_address):
        # Nodeクラスではこのメソッドは何もしない
        pass

    def add_dns_record(self, domain_name, ip_address):
        # URLとIPアドレスのマッピングをDNSテーブルに追加するメソッド
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
                # ARPリプライを受信した場合の処理
                self.network_event_scheduler.log_packet_info(packet, "ARP reply received", self.node_id)
                source_ip = packet.payload["source_ip"]
                source_mac = packet.payload["source_mac"]
                self.add_to_arp_table(source_ip, source_mac)
                self.on_arp_reply_received(source_ip, source_mac)
                return

    def process_DHCP_packet(self, packet):
        if packet.header["destination_mac"] == self.mac_address:
            self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
            packet.set_arrived(self.network_event_scheduler.current_time)
            if packet.message_type == "OFFER":
                # DHCP Offerパケットの処理
                self.network_event_scheduler.log_packet_info(packet, "DHCP Offer received", self.node_id)
                # OfferされたIPアドレスを取得
                offered_ip = packet.dhcp_data.get("offered_ip")
                if offered_ip:
                    # OfferされたIPアドレスを使用してDHCP Requestを送信
                    self.send_dhcp_request(offered_ip)
                return
            elif packet.message_type == "ACK":
                # DHCP ACKパケットの処理
                self.network_event_scheduler.log_packet_info(packet, "DHCP ACK received", self.node_id)
                # ACKパケットから割り当てられたIPアドレスを取得
                assigned_ip = packet.dhcp_data.get("assigned_ip")
                if assigned_ip:
                    # 割り当てられたIPアドレスをノードのIPアドレスとして設定
                    self.ip_address = assigned_ip
                    print(f"Node {self.node_id} has been assigned the IP address {assigned_ip}.")
                # ACKパケットからDNSサーバのIPアドレスを取得
                dns_server_ip = packet.dhcp_data.get("dns_server_ip")
                if dns_server_ip:
                    self.dns_server_ip = dns_server_ip
                    print(f"Node {self.node_id} has been assigned the DNS server IP address {dns_server_ip}.")
                return

    def process_DNS_packet(self, packet):
        if packet.header["destination_mac"] == self.mac_address:
            self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
            packet.set_arrived(self.network_event_scheduler.current_time)
            # DNSレスポンスの処理
            self.network_event_scheduler.log_packet_info(packet, "DNS packet received", self.node_id)                
            if packet.query_domain and "resolved_ip" in packet.dns_data:
                # DNSレスポンスから解決されたIPアドレスを取得し、DNSテーブルに追加
                self.on_dns_response_received(packet.query_domain, packet.dns_data["resolved_ip"])
                return

    def process_UDP_packet(self, packet):
        if packet.header["destination_mac"] == self.mac_address:
            if packet.header["destination_ip"] == self.ip_address:
                # Log
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                self.process_data_packet(packet)
            else:
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def process_TCP_packet(self, packet):
        if packet.header["destination_mac"] == self.mac_address:
            if packet.header["destination_ip"] == self.ip_address:
                # log
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                # Retrieve the connection key
                connection_key = (packet.header["source_ip"], packet.header["source_port"])
                
                # Ensure connection info exists
                if connection_key not in self.tcp_connections:
                    self.initialize_connection_info(connection_key=connection_key)

                # Check TCP flags for processing
                flags = packet.header.get('flags', '')

                # SYNパケットの処理
                if "SYN" in flags:
                    if "ACK" in flags:  # SYN-ACKパケットを受信した場合
                        self.establish_TCP_connection(packet)  # 接続情報を更新
                        self.send_TCP_ACK(packet)  # ACKを送信
                        self.send_tcp_data_packet(packet)  # パケットを送信
                    else:
                        self.establish_TCP_connection(packet)  # 接続情報を更新
                        self.send_TCP_SYN_ACK(packet)  # SYN-ACKを送信
                    return

                # ACKパケットの処理
                if "ACK" in flags:
                    self.count_duplicated_ACK(packet)  # 重複ACKのカウント
                    if self.check_duplication_threshold(packet):  # 重複ACKの閾値を超えた場合
                        self.retransmit_packet(packet)  # パケットの再送
                    else:
                        self.send_tcp_data_packet(packet)  # パケットの送信

                # PSHパケットの処理
                if "PSH" in flags:
                    self.update_ACK_number(packet)  # ACK番号の更新
                    self.send_TCP_ACK(packet)  # ACKを送信
                    self.process_data_packet(packet)  # データパケットの処理

                # FINパケットの処理
                if "FIN" in flags:
                    self.terminate_TCP_connection(packet)  # TCP接続を終了

            else:
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def initialize_connection_info(self, connection_key=None, state='CLOSED', sequence_number=0, acknowledgment_number=0, data=b''):
        """Initialize TCP connection information for a new connection key."""
        self.tcp_connections[connection_key] = {
            'state': state,
            'sequence_number': sequence_number,
            'acknowledgment_number': acknowledgment_number,
            'data': data,
            'last_ack_number': None,
            'duplicate_ack_count': 0,
            'packet_history': {}  # Packet history for potential retransmission
        }

    def count_duplicated_ACK(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        current_ack_number = packet.header["acknowledgment_number"]

        if connection_key not in self.tcp_connections:
            return  # コネクションが存在しない場合は何もしない

        # 最後に受け取ったACK番号を取得
        last_ack_number = self.tcp_connections[connection_key].get("last_ack_number")

        if current_ack_number == last_ack_number:
            # 重複ACKとみなしてカウントアップ
            self.tcp_connections[connection_key]["duplicate_ack_count"] += 1
        else:
            # 新しいACK番号の場合は、カウントをリセットしてACK番号を更新
            self.tcp_connections[connection_key]["duplicate_ack_count"] = 1
            self.tcp_connections[connection_key]["last_ack_number"] = current_ack_number

    def check_duplication_threshold(self, connection_key):
        if connection_key in self.tcp_connections:
            if self.tcp_connections[connection_key]["duplicate_ack_count"] >= 3:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Duplicate ACK threshold reached for connection {connection_key}")
                return True
            else:
                return False
        return False

    def update_ACK_number(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if connection_key not in self.tcp_connections:
            return  # コネクション情報が存在しない場合は処理をスキップ

        # 受信したパケットの情報を取得
        received_sequence_number = packet.header["sequence_number"]
        payload_length = len(packet.payload)

        # 現在のACK番号を取得
        current_ack_number = self.tcp_connections[connection_key]["acknowledgment_number"]

        print(f"Received sequence number: {received_sequence_number}, Payload length: {payload_length}, Current ACK number: {current_ack_number}")

        new_ack_number = max(received_sequence_number + payload_length, current_ack_number)

        # ACK番号を更新
        if new_ack_number > current_ack_number:
            self.tcp_connections[connection_key]["acknowledgment_number"] = new_ack_number
            if self.network_event_scheduler.tcp_verbose:
                print(f"Updated ACK number to {new_ack_number} for connection {connection_key}.")


    def send_TCP_SYN_ACK(self, packet):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        
        sequence_number = randint(1, 10000)
        # 受信したSYNパケットのシーケンス番号に1を加えたものがACK番号
        acknowledgment_number = packet.header["sequence_number"] + 1

        # 新しい接続情報を初期化
        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(connection_key=connection_key, state='SYN_RECEIVED', sequence_number=sequence_number, acknowledgment_number=acknowledgment_number, data=b'')

        # パラメータ設定
        control_packet_kwargs = {
            "flags": "SYN,ACK",
            "sequence_number": sequence_number,
            "acknowledgment_number": acknowledgment_number,
            "source_port": packet.header["destination_port"],
            "destination_port": packet.header["source_port"]
        }
        self._send_tcp_packet(
            destination_ip=packet.header["source_ip"],
            destination_mac=packet.header["source_mac"],
            data=b"",
            **control_packet_kwargs
        )

        connection_info = self.tcp_connections[connection_key]
        connection_info['sequence_number'] = sequence_number + 1
        connection_info['acknowledgment_number'] = acknowledgment_number + 1
        self.tcp_connections[connection_key] = connection_info

    def send_TCP_ACK(self, packet):
        # コネクションキーを生成
        connection_key = (packet.header["source_ip"], packet.header["source_port"])

        if connection_key in self.tcp_connections:
            received_sequence_number = packet.header["sequence_number"]
            acknowledgment_number = received_sequence_number + 1  # 受信したパケットのシーケンス番号+1をACK番号として設定

            # パラメータ設定
            control_packet_kwargs = {
                "flags": "ACK",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": acknowledgment_number,
                "source_port": packet.header["destination_port"],
                "destination_port": packet.header["source_port"]
            }
            self._send_tcp_packet(
                destination_ip=packet.header["source_ip"],
                destination_mac=packet.header["source_mac"],
                data=b"",
                **control_packet_kwargs
            )

            # 受信したパケットに対するACK番号をローカルのtcp_connectionsに更新
            self.tcp_connections[connection_key]["acknowledgment_number"] = acknowledgment_number

        else:
            if self.network_event_scheduler.tcp_verbose:
                print("Error: Connection key not found in tcp_connections.")

    def establish_TCP_connection(self, packet):
        """
        TCP接続を確立する処理です。接続が確立されたら、保存しておいたデータがあれば送信します。
        """
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if connection_key in self.tcp_connections:
            if self.tcp_connections[connection_key]['state'] == 'ESTABLISHED':
                return
            else:
                self.update_tcp_connection_state(connection_key, "ESTABLISHED")
                if self.network_event_scheduler.tcp_verbose:
                    print(f"Establishing TCP connection with {packet.header['source_ip']}:{packet.header['source_port']}")
                # シーケンス番号を更新
                self.tcp_connections[connection_key]["sequence_number"] += 1

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
        elif isinstance(packet, ARPPacket):  # ARPパケットの処理
            self.process_ARP_packet(packet)
        elif isinstance(packet, DHCPPacket):  # DHCPパケットの処理
            self.process_DHCP_packet(packet)
        elif isinstance(packet, DNSPacket):  # DNSパケットの処理
            self.process_DNS_packet(packet)
        elif isinstance(packet, UDPPacket):  # UDPパケットの処理
            self.process_UDP_packet(packet)
        elif isinstance(packet, TCPPacket):  # TCPパケットの処理
            self.process_TCP_packet(packet)
        else:
            self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def process_data_packet(self, packet):
        # 'more_fragments'キーが存在しない場合はFalseをデフォルト値として使用
        more_fragments = packet.header.get("fragment_flags", {}).get("more_fragments", False)

        # フラグメントされたパケットの処理
        if more_fragments:
            self._store_fragment(packet)
        else:
            # original_data_idのチェックを追加
            original_data_id = packet.header.get("fragment_flags", {}).get("original_data_id")
            if original_data_id and original_data_id in self.fragmented_packets:
                self._reassemble_and_process_packet(packet)
            else:
                # フラグメントされていないパケットの処理
                self.direct_process_packet(packet)

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

    def direct_process_packet(self, packet):
        # フラグメントされていないパケットの直接処理
        pass
        # ここでパケットのペイロードを処理するロジックを実装
        # 例: ペイロードのログ出力、特定のデータの解析、応答の送信など

    def on_arp_reply_received(self, destination_ip, destination_mac):
        # ARPリプライを受信したら、待機中のパケットに対して処理を行う
        if destination_ip in self.waiting_for_arp_reply:
            for packet_info in self.waiting_for_arp_reply[destination_ip]:
                data, protocol, kwargs = packet_info
                # send_packetメソッドを使用して、待機中のパケットを送信
                # kwargsは辞書なので、関数のキーワード引数として展開するために**を使用
                self.send_packet(destination_ip, data, protocol=protocol, **kwargs)
            # 待機リストから該当する宛先IPを削除
            del self.waiting_for_arp_reply[destination_ip]

    def send_arp_request(self, ip_address):
        # ARPリクエストパケットを作成して送信する処理
        # 宛先MACアドレスはブロードキャストアドレス、宛先IPアドレスは問い合わせたいIPアドレス
        arp_request_packet = ARPPacket(
            source_mac=self.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",  # ブロードキャストアドレス
            source_ip=self.ip_address,
            destination_ip=ip_address,
            operation="request",
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(arp_request_packet, "ARP request", self.node_id)
        self._send_packet(arp_request_packet)

    def _send_arp_reply(self, request_packet):
        # ARPリプライパケットを作成
        arp_reply_packet = ARPPacket(
            source_mac=self.mac_address,  # 送信元MACアドレスは自身のMACアドレス
            destination_mac=request_packet.header["source_mac"],  # 宛先MACアドレスはARPリクエストの送信元MACアドレス
            source_ip=self.ip_address,  # 送信元IPアドレスは自身のIPアドレス
            destination_ip=request_packet.header["source_ip"],  # 宛先IPアドレスはARPリクエストの送信元IPアドレス
            operation="reply",  # 操作は'reply'
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(arp_reply_packet, "ARP reply", self.node_id)
        self._send_packet(arp_reply_packet)

    def send_packet(self, destination_ip, data, protocol="UDP", **kwargs):
        """
        汎用的なパケット送信メソッド。プロトコルに基づいて適切なパケットを送信します。
        """
        destination_mac = self.get_mac_address_from_ip(destination_ip)

        if destination_mac is None:
            # ARPリクエストを送信し、パケットを待機リストに追加
            self.send_arp_request(destination_ip)
            if destination_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[destination_ip] = []
            self.waiting_for_arp_reply[destination_ip].append((data, protocol, kwargs))
        else:
            if protocol == "UDP":
                self._send_udp_packet(destination_ip, destination_mac, data, **kwargs)
            elif protocol == "TCP":
                # TCP接続の状態を確認
                if not self.is_tcp_connection_established(destination_ip, kwargs.get('destination_port')):
                    # データを一時的に保存
                    connection_key = (destination_ip, kwargs.get('destination_port'))
                    self.pending_tcp_data[connection_key] = {"data": data, "kwargs": kwargs}
                    # 接続が未確立の場合、ハンドシェイクを開始
                    self.initiate_tcp_handshake(destination_ip, destination_mac, **kwargs)
                else:
                    # 接続が確立されている場合、データパケットを送信
                    self._send_tcp_packet(destination_ip, destination_mac, data, **kwargs)

    def is_tcp_connection_established(self, destination_ip, destination_port):
        # 接続が確立されているかどうかを確認
        key = (destination_ip, destination_port)
        return self.tcp_connections.get(key, {}).get("state") == "ESTABLISHED"

    def update_tcp_connection_state(self, connection_key, new_state):
        """
        指定された宛先に対するTCP接続の状態を更新します。
        """
        if connection_key not in self.tcp_connections:
            self.initialize_connection_info(connection_key=connection_key, state=new_state)
        else:
            self.tcp_connections[connection_key]["state"] = new_state
        if self.network_event_scheduler.tcp_verbose:
            print(f"TCP connection state updated to {new_state} for {connection_key}")

    def initiate_tcp_handshake(self, destination_ip, destination_mac, **kwargs):
        """
        TCPの3ウェイハンドシェイクを開始するためのメソッド。
        SYNパケットを送信してハンドシェイクを開始します。
        """
        # 接続状態を確認し、未確立の場合にのみSYNパケットを送信
        if not self.is_tcp_connection_established(destination_ip, kwargs.get('destination_port')):
            if self.network_event_scheduler.tcp_verbose:
                # TCPハンドシェイク開始の詳細情報を出力
                print(f"Initiating TCP handshake: Sending SYN to {destination_ip}:{kwargs.get('destination_port')} from port {kwargs.get('source_port')}")
                print(f"Flags set to: SYN")
                print(f"Payload size for control packet: 0 bytes")

            connection_key = (destination_ip, kwargs.get('destination_port'))
            if connection_key not in self.tcp_connections:
                self.initialize_connection_info(connection_key=connection_key, state='SYN_SENT', sequence_number=randint(1, 10000), acknowledgment_number=0, data=b'')

            # SYNフラグをセットしてTCPパケットを送信
            control_packet_kwargs = {
                "flags": "SYN",
                "sequence_number": self.tcp_connections[connection_key]["sequence_number"],
                "acknowledgment_number": 0,
                "source_port": kwargs.get('source_port'),
                "destination_port": kwargs.get('destination_port'),
                "payload_size": 0
            }
            self._send_tcp_packet(
                destination_ip=destination_ip,
                destination_mac=destination_mac,
                data=b"",
                **control_packet_kwargs
            )

            if self.network_event_scheduler.tcp_verbose:
                # 接続状態の更新情報を出力
                print(f"Connection state updated to SYN_SENT for {destination_ip}:{kwargs.get('destination_port')}")

    def _send_udp_packet(self, destination_ip, destination_mac, data, **kwargs):
        """
        UDPパケットを送信するための内部メソッド。
        """
        #print(f"Sending UDP packet to {destination_ip}, {len(data)} bytes., kwargs={kwargs}")
        udp_header_size = 8  # UDPヘッダは8バイト
        ip_header_size = 20  # IPヘッダは20バイト
        header_size = udp_header_size + ip_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, header_size, protocol="UDP", **kwargs)

    def send_tcp_data_packet(self, packet):
        """
        ACKを受信したときにデータパケットを送信します。
        """
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        
        if connection_key in self.tcp_connections:
            if 'traffic_info' not in self.tcp_connections[connection_key]:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"No traffic info found for {connection_key}")
                return

            traffic_info = self.tcp_connections[connection_key]['traffic_info']
            if self.network_event_scheduler.current_time < traffic_info['end_time']:
                # 送信するデータを取得
                remaining_data = self.tcp_connections[connection_key]['data']
                payload_size = traffic_info['payload_size']
                next_sequence_number = self.tcp_connections[connection_key]['sequence_number']

                # 送信データがある場合のみシーケンス番号を更新
                data_to_send = remaining_data[:payload_size]
                if data_to_send:
                    next_sequence_number += len(data_to_send)  # データ長に基づいてシーケンス番号を更新

                # パラメータ設定
                data_packet_kwargs = {
                    "source_port": packet.header["destination_port"],
                    "destination_port": packet.header["source_port"],
                    "sequence_number": next_sequence_number,
                    "acknowledgment_number": self.tcp_connections[connection_key]['acknowledgment_number'],
                    "flags": "PSH"
                }

                # パケットを送信
                self._send_tcp_packet(
                    destination_ip=packet.header["source_ip"],
                    destination_mac=packet.header["source_mac"],
                    data=data_to_send,
                    **data_packet_kwargs
                )

                # シーケンス番号と送信済みデータを更新
                self.tcp_connections[connection_key]['data'] = remaining_data[payload_size:]
                self.tcp_connections[connection_key]['sequence_number'] = next_sequence_number  # 更新後のシーケンス番号を保存

    def _send_tcp_packet(self, destination_ip, destination_mac, data, **kwargs):
        """
        TCPパケットを送信するためのメソッド。
        """
        tcp_header_size = 20  # TCPヘッダは20バイト
        ip_header_size = 20  # IPヘッダは20バイト
        header_size = tcp_header_size + ip_header_size

        connection_key = (destination_ip, kwargs.get('destination_port'))
        if connection_key in self.tcp_connections:

            if data:
                self.tcp_connections[connection_key]['sequence_number'] += len(data)

            # 送信するパケットの情報
            packet_info = {
                'destination_ip': destination_ip,
                'destination_mac': destination_mac,
                'data': data,
                'header_size': header_size,
                'kwargs': kwargs
            }
            # 送信したパケット情報を履歴に記録
            sequence_number = self.tcp_connections[connection_key]['sequence_number']
            self.tcp_connections[connection_key]['packet_history'][sequence_number] = packet_info

            # パケットを送信
            self._send_ip_packet_data(destination_ip, destination_mac, data, header_size, protocol="TCP", **kwargs)

            # tcp_verboseがtrueの場合、送信情報を表示
            if self.network_event_scheduler.tcp_verbose:
                print(f"Sending TCP packet from {self.node_id} to {destination_ip}:{kwargs.get('destination_port')} with Flags: {kwargs.get('flags')}, Data Length: {len(data)}, Sequence Number: {kwargs.get('sequence_number')}, Acknowledgment Number: {kwargs.get('acknowledgment_number')}, ")

    def retransmit_packet(self, connection_key, sequence_number):
        if connection_key in self.tcp_connections:
            packet_history = self.tcp_connections[connection_key]['packet_history']
            if sequence_number in packet_history:
                packet_info = packet_history[sequence_number]
                destination_ip = packet_info['destination_ip']
                destination_mac = packet_info['destination_mac']
                data = packet_info['data']
                header_size = packet_info['header_size']
                kwargs = packet_info['kwargs']
                self._send_ip_packet_data(destination_ip, destination_mac, data, header_size, protocol="TCP", **kwargs)
            else:
                if self.network_event_scheduler.tcp_verbose:
                    print(f"No packet with sequence number {sequence_number} found in history for retransmission.")

    def _send_ip_packet_data(self, destination_ip, destination_mac, data, header_size, protocol, **kwargs):
        """
        IPパケットを送信するための内部メソッド。TCP/UDPの区別に応じて適切なパケットを生成します。
        """
        original_data_id = str(uuid.uuid4())
        total_size = len(data) if data else 0
        offset = 0

        while offset < total_size or (offset == 0 and total_size == 0):
            # MTUからヘッダサイズを引いた値が、このフラグメントの最大ペイロードサイズ
            max_payload_size = self.mtu - header_size
            # 実際のペイロードサイズは、残りのデータサイズとmax_payload_sizeの小さい方
            payload_size = min(max_payload_size, total_size - offset) if data else 0
            # フラグメントデータの切り出し
            fragment_data = data[offset:offset + payload_size] if data else b""
            fragment_offset = offset

            # フラグメントフラグの設定
            more_fragments = False if total_size == 0 else offset + payload_size < total_size
            fragment_flags = {
                "more_fragments": more_fragments
            }
            if more_fragments or payload_size > 0:
                fragment_flags["original_data_id"] = original_data_id

            if protocol == "UDP":
                packet = UDPPacket(
                    source_mac=self.mac_address,
                    destination_mac=destination_mac,
                    source_ip=self.ip_address,
                    destination_ip=destination_ip,
                    ttl=64,
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

            # パケットのペイロードにフラグメントデータを設定
            packet.payload = fragment_data
            # パケットの送信
            self._send_packet(packet)

            # データが空の場合はループを抜ける
            if not data:
                break

            # 次のフラグメントのオフセットへ
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

    def start_udp_traffic(self, destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="UDP"):
        def attempt_to_start_traffic():
            destination_ip = self.resolve_destination_ip(destination_url)
            if destination_ip is None:
                # DNSレコードがない場合、DNSクエリを行い、レスポンスの受信後にトラフィックを開始するための処理をスケジュール
                self.send_dns_query_and_set_traffic(destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness, protocol)
            else:
                # DNSレコードが既に存在する場合、直接トラフィック生成を開始
                self.set_udp_traffic(destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness, protocol)
        
        # 最初のパケット生成（またはDNSレコードの検索処理）をstart_timeにスケジュール
        self.network_event_scheduler.schedule_event(start_time, attempt_to_start_traffic)

    def set_udp_traffic(self, destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="UDP"):
        end_time = start_time + duration
        source_port = self.select_random_port()  # 利用可能なランダムなソースポートを選択
        destination_port = self.select_random_port()  # デスティネーションポートもランダムに選択

        def generate_packet():
            if self.network_event_scheduler.current_time < end_time:
                # send_packetメソッドを使用してパケットを送信
                data = b'X' * payload_size  # ダミーデータを生成
                self.send_packet(destination_ip, data, protocol, source_port=source_port, destination_port=destination_port)

                # 次のパケットをスケジュールするためのインターバルを計算
                packet_size = header_size + payload_size
                interval = (packet_size * 8) / bitrate * burstiness
                self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + interval, generate_packet)

        self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time, generate_packet)

    def start_tcp_traffic(self, destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="TCP"):
        def attempt_to_start_traffic():
            destination_ip = self.resolve_destination_ip(destination_url)
            if destination_ip is None:
                # DNSレコードがない場合、DNSクエリを行い、レスポンスの受信後にトラフィックを開始するための処理をスケジュール
                self.send_dns_query_and_set_traffic(destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness, protocol="TCP")
            else:
                # DNSレコードが既に存在する場合、直接トラフィック生成を開始
                self.set_tcp_traffic(destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness)

        self.network_event_scheduler.schedule_event(start_time, attempt_to_start_traffic)

    def set_tcp_traffic(self, destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="TCP"):
        end_time = start_time + duration
        source_port = self.select_random_port()
        destination_port = self.select_random_port()  # 実際のアプリケーションでは、適切な宛先ポートを指定する必要があります
        
        # コネクションキーを生成
        connection_key = (destination_ip, destination_port)
        
        # self.tcp_connectionsにコネクションキーが存在しない場合、新しく追加する
        if connection_key not in self.tcp_connections:
            data = b'X' * (int(bitrate * duration) // 8)
            self.initialize_connection_info(connection_key=connection_key, sequence_number=randint(1, 10000), data=data)
        
        # トラフィック情報をself.tcp_connectionsに保存
        self.tcp_connections[connection_key]['traffic_info'] = {
            'end_time': end_time,
            'payload_size': payload_size,
            'header_size': header_size,
            'bitrate': bitrate,
            'burstiness': burstiness,
            'next_sequence_number': self.tcp_connections[connection_key]['sequence_number']  # 次に送信するシーケンス番号を保存
        }

        # 最初のSYNパケットを送信してTCP接続を開始
        self.send_packet(destination_ip, b"", protocol="TCP", source_port=source_port, destination_port=destination_port, flags="SYN")

    def resolve_destination_ip(self, destination_url):
        # 与えられた宛先URLに対応するIPアドレスをurl_to_ip_mappingから検索します。
        # 見つかった場合はそのIPアドレスを返し、見つからない場合はNoneを返します。
        return self.url_to_ip_mapping.get(destination_url, None)

    def send_dns_query_and_set_traffic(self, destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="UDP"):
        # DNSクエリを送信する前に、トラフィック生成のパラメータと使用するプロトコルを記録します。
        if destination_url not in self.waiting_for_dns_reply:
            self.waiting_for_dns_reply[destination_url] = []
        self.waiting_for_dns_reply[destination_url].append((bitrate, start_time, duration, header_size, payload_size, burstiness, protocol))
        # DNSクエリパケットを生成して送信します。
        self.send_dns_query(destination_url)

    def send_dns_query(self, destination_url):
        # DNSクエリパケットを生成します。
        dns_query_packet = DNSPacket(
            source_mac=self.mac_address,  # このノードのMACアドレス
            destination_mac="FF:FF:FF:FF:FF:FF",  # DNSクエリは通常ブロードキャストされますが、実際にはDNSサーバのMACアドレスが必要です。
            source_ip=self.ip_address,  # このノードのIPアドレス
            destination_ip=self.dns_server_ip,  # DNSサーバのIPアドレス
            query_domain=destination_url,  # 解決したいドメイン名
            query_type="A",  # Aレコードのクエリ（IPv4アドレスを問い合わせる）
            network_event_scheduler=self.network_event_scheduler
        )
        self.network_event_scheduler.log_packet_info(dns_query_packet, "DNS query", self.node_id)
        self._send_packet(dns_query_packet)

    def on_dns_response_received(self, query_domain, resolved_ip):
        # DNSレスポンスを受信した際の処理
        self.add_dns_record(query_domain, resolved_ip)
        if query_domain in self.waiting_for_dns_reply:
            for parameters in self.waiting_for_dns_reply[query_domain]:
                bitrate, start_time, duration, header_size, payload_size, burstiness, protocol = parameters
                # 解決されたIPアドレスを使用してトラフィック生成を開始します。
                if protocol == "UDP":
                    self.set_udp_traffic(resolved_ip, bitrate, start_time, duration, header_size, payload_size, burstiness)
                elif protocol == "TCP":
                    # TCPトラフィック生成メソッドを呼び出す（実装が必要）
                    self.set_tcp_traffic(resolved_ip, bitrate, start_time, duration, header_size, payload_size, burstiness)
            # 処理が完了したら、該当するドメイン名のエントリを削除
            del self.waiting_for_dns_reply[query_domain]

    def print_url_to_ip_mapping(self):
        # DNSテーブルの内容を表示するメソッド
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
