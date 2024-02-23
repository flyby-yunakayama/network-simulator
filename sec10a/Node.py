import uuid
import re
import random
from ipaddress import ip_interface, ip_network
from sec10a.Switch import Switch
from sec10a.Router import Router
from sec10a.Packet import Packet, UDPPacket, TCPPacket, ARPPacket, DNSPacket, DHCPPacket

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

            if isinstance(packet, DHCPPacket):
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

            if isinstance(packet, DNSPacket):
                # DNSレスポンスの処理
                self.network_event_scheduler.log_packet_info(packet, "DNS packet received", self.node_id)                
                if packet.query_domain and "resolved_ip" in packet.dns_data:
                    # DNSレスポンスから解決されたIPアドレスを取得し、DNSテーブルに追加
                    self.on_dns_response_received(packet.query_domain, packet.dns_data["resolved_ip"])
                    return

            if packet.header["destination_ip"] == self.ip_address:
                # 宛先IPがこのノードの場合
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                # 'more_fragments'キーが存在しない場合はFalseをデフォルト値として使用
                more_fragments = packet.header.get("fragment_flags", {}).get("more_fragments", False)

                # フラグメントされたパケットの処理
                if more_fragments:
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
                self._send_tcp_packet(destination_ip, destination_mac, data, **kwargs)

    def _send_udp_packet(self, destination_ip, destination_mac, data, **kwargs):
        """
        UDPパケットを送信するための内部メソッド。
        """
        print(f"Sending UDP packet to {destination_ip}, {len(data)} bytes., kwargs={kwargs}")
        udp_header_size = 8  # UDPヘッダは8バイト
        ip_header_size = 20  # IPヘッダは20バイト
        header_size = udp_header_size + ip_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, header_size, protocol="UDP", **kwargs)

    def _send_tcp_packet(self, destination_ip, destination_mac, data, **kwargs):
        """
        TCPパケットを送信するためのメソッド。
        """
        tcp_header_size = 20  # TCPヘッダは20バイト
        ip_header_size = 20  # IPヘッダは20バイト
        header_size = tcp_header_size + ip_header_size
        self._send_ip_packet_data(destination_ip, destination_mac, data, header_size, protocol="TCP", **kwargs)

    def _send_ip_packet_data(self, destination_ip, destination_mac, data, header_size, protocol, **kwargs):
        """
        IPパケットを送信するための内部メソッド。TCP/UDPの区別に応じて適切なパケットを生成します。
        """
        original_data_id = str(uuid.uuid4())
        total_size = len(data)
        offset = 0

        while offset < total_size:
            # MTUからヘッダサイズを引いた値が、このフラグメントの最大ペイロードサイズ
            max_payload_size = self.mtu - header_size
            # 実際のペイロードサイズは、残りのデータサイズとmax_payload_sizeの小さい方
            payload_size = min(max_payload_size, total_size - offset)
            # フラグメントデータの切り出し
            fragment_data = data[offset:offset + payload_size]
            fragment_offset = offset

            # フラグメントフラグの設定
            more_fragments = offset + payload_size < total_size
            fragment_flags = {
                "more_fragments": more_fragments,
                "original_data_id": original_data_id
            }
            print(f"Fragmenting data: offset={offset}, payload_size={payload_size}, more_fragments={more_fragments}, total_size={total_size}")

            if protocol == "UDP":
                packet = UDPPacket(
                    source_mac=self.mac_address,
                    destination_mac=destination_mac,
                    source_ip=self.ip_address.split('/')[0],
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
                    source_ip=self.ip_address.split('/')[0],
                    destination_ip=destination_ip,
                    ttl=64,
                    network_event_scheduler=self.network_event_scheduler,
                    fragment_flags=fragment_flags,
                    fragment_offset=fragment_offset,
                    header_size=header_size,
                    payload_size=payload_size,
                    source_port=kwargs.get('source_port'),
                    destination_port=kwargs.get('destination_port'),
                    sequence_number=kwargs.get('sequence_number'),
                    acknowledgment_number=kwargs.get('acknowledgment_number'),
                    flags=kwargs.get('flags')
                )

            # パケットのペイロードにフラグメントデータを設定
            packet.payload = fragment_data
            # パケットの送信
            self._send_packet(packet)

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
                print(f"Generating UDP packet to {destination_ip}, {len(data)} bytes., payload_size={payload_size}")
                self.send_packet(destination_ip, data, protocol, source_port=source_port, destination_port=destination_port)

                # 次のパケットをスケジュールするためのインターバルを計算
                packet_size = header_size + payload_size
                interval = (packet_size * 8) / bitrate * burstiness
                self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + interval, generate_packet)

        self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time, generate_packet)

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
                    self.set_udp_traffic(resolved_ip, bitrate, start_time, duration, payload_size, burstiness)
                elif protocol == "TCP":
                    # TCPトラフィック生成メソッドを呼び出す（実装が必要）
                    self.set_tcp_traffic(resolved_ip, bitrate, start_time, duration, payload_size, burstiness)
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
