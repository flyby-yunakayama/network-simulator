import uuid
import re
from ipaddress import ip_network
from sec8a.Switch import Switch
from sec8a.Router import Router
from sec8a.Packet import Packet, ARPPacket

class Node:
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None, mtu=1500, default_route=None, arp_timeout=5):
        # IPアドレスが正しいCIDR形式であるか確認
        if not self.is_valid_cidr_notation(ip_address):
            raise ValueError("無効なIPアドレス形式です。")

        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        if mac_address is None:
            self.mac_address = self.generate_mac_address()  # ランダムなMACアドレスを生成
        else:
            if not self.is_valid_mac_address(mac_address):
                raise ValueError("無効なMACアドレス形式です。")
            self.mac_address = mac_address  # MACアドレス
        self.ip_address = ip_address  # IPアドレス
        self.links = []
        self.arp_table = {}  # IPアドレスとMACアドレスのマッピングを保持するARPテーブル
        self.waiting_for_arp_reply = {}  # 宛先IPをキーとした待機中のパケットリスト
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

    def generate_mac_address(self):
        # ランダムなMACアドレスを生成
        return ':'.join(['{:02x}'.format(uuid.uuid4().int >> elements & 0xff) for elements in range(0, 12, 2)])

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

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            # パケットロスをログに記録
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)
            return

        # 宛先MACアドレスがブロードキャストアドレスの場合の処理
        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF":
            if isinstance(packet, ARPPacket):
                # ペイロード内のoperationが'request'で、かつ宛先IPがこのノードのIPアドレスと一致する場合
                if packet.payload.get("operation") == "request" and packet.payload["destination_ip"] == self.ip_address:
                    # 自身のMACアドレスを含むARPリプライを送信
                    self._send_arp_reply(packet)
                    return

        if packet.header["destination_mac"] == self.mac_address:
            if isinstance(packet, ARPPacket):
                if packet.payload.get("operation") == "reply" and packet.payload["destination_ip"] == self.ip_address:
                    # ARPリプライを受信した場合の処理
                    self.network_event_scheduler.log_packet_info(packet, "ARP reply received", self.node_id)
                    source_ip = packet.payload["source_ip"]
                    source_mac = packet.payload["source_mac"]
                    self.add_to_arp_table(source_ip, source_mac)
                    self.on_arp_reply_received(source_ip, source_mac)
                    return

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

    def on_arp_reply_received(self, destination_ip, destination_mac):
        # ARPリプライを受信したら、待機中のパケットに対して処理を行う
        if destination_ip in self.waiting_for_arp_reply:
            for data, header_size in self.waiting_for_arp_reply[destination_ip]:
                self._send_packet_data(destination_ip, destination_mac, data, header_size)
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

    def send_packet(self, destination_ip, data, header_size):
        destination_mac = self.get_mac_address_from_ip(destination_ip)

        if destination_mac is None:
            # ARPリクエストを送信し、パケットを待機リストに追加
            self.send_arp_request(destination_ip)
            if destination_ip not in self.waiting_for_arp_reply:
                self.waiting_for_arp_reply[destination_ip] = []
            self.waiting_for_arp_reply[destination_ip].append((data, header_size))
        else:
            self._send_packet_data(destination_ip, destination_mac, data, header_size)

    def _send_packet_data(self, destination_ip, destination_mac, data, header_size):
        original_data_id = str(uuid.uuid4())
        payload_size = self.mtu - header_size
        total_size = len(data)
        offset = 0

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

    def create_packet(self, destination_ip, header_size, payload_size):
        destination_mac = self.get_mac_address_from_ip(destination_ip)
        node_ip_address = self.ip_address.split('/')[0]
        packet = Packet(source_mac=self.mac_address, destination_mac=destination_mac, source_ip=node_ip_address, destination_ip=destination_ip, ttl=64, header_size=header_size, payload_size=payload_size, network_event_scheduler=self.network_event_scheduler)
        self.network_event_scheduler.log_packet_info(packet, "created", self.node_id)  # パケット生成をログに記録
        self.send_packet(packet)

    def set_traffic(self, destination_ip, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0):
        end_time = start_time + duration

        def generate_packet():
            if self.network_event_scheduler.current_time < end_time:
                # send_packetメソッドを使用してパケットを送信
                data = b'X' * payload_size  # ダミーデータを生成
                self.send_packet(destination_ip, data, header_size)

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
