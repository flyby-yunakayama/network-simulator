import uuid
from ipaddress import ip_network

from sec9a.Packet import ARPPacket, DNSPacket, DHCPPacket

class Server:
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None):
        self.node_id = node_id
        self.ip_address = ip_address
        self.network_event_scheduler = network_event_scheduler
        self.mac_address = mac_address if mac_address else self.generate_mac_address()
        self.links = []

    def generate_mac_address(self):
        # ランダムなMACアドレスを生成
        return ':'.join(['{:02x}'.format(uuid.uuid4().int >> elements & 0xff) for elements in range(0, 12, 2)])

    def add_link(self, link, ip_address=None):
        if link not in self.links:
            self.links.append(link)

    def mark_ip_as_used(self, ip_address):
        pass

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            # パケットロスをログに記録
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)
            return

        # 宛先MACアドレスがブロードキャストアドレスまたは自身のMACアドレスの場合の処理
        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF" or packet.header["destination_mac"] == self.mac_address:
            if isinstance(packet, ARPPacket):
                # ARPパケット処理
                if packet.payload.get("operation") == "request" and packet.payload["destination_ip"] == self.ip_address:
                    # ARPリクエストの処理
                    self._send_arp_reply(packet)

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

    def _send_packet(self, packet):
        for link in self.links:
            link.enqueue_packet(packet, self)

class DNSServer(Server):
    def __init__(self, node_id, ip_address, network_event_scheduler, mac_address=None):
        super().__init__(node_id, ip_address, network_event_scheduler, mac_address)
        self.dns_records = {}  # ドメイン名をキーにしてIPアドレスを取得するための辞書
        label = f'DNSServer {node_id}'
        self.network_event_scheduler.add_node(node_id, label, ip_addresses=[ip_address])

    def add_dns_record(self, domain_name, ip_address):
        # 新しいDNSレコードを追加するメソッド
        self.dns_records[domain_name] = ip_address

    def receive_packet(self, packet, received_link):
        super().receive_packet(packet, received_link)  # Serverクラスの共通処理を利用

        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF" or packet.header["destination_mac"] == self.mac_address:
            if isinstance(packet, DNSPacket) and packet.header["destination_ip"] == self.ip_address:
                self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)
                packet.set_arrived(self.network_event_scheduler.current_time)

                # DNSパケット処理
                self.network_event_scheduler.log_packet_info(packet, "DNS query received", self.node_id)
                dns_response_packet = self.handle_dns_query(packet)
                self.network_event_scheduler.log_packet_info(dns_response_packet, "DNS response", self.node_id)
                self._send_packet(dns_response_packet)

            else:
                # 宛先IPがこのノードではない場合の処理
                self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def handle_dns_query(self, dns_packet):
        # DNSクエリを処理してレスポンスを返すメソッド
        query_domain = dns_packet.query_domain
        if query_domain in self.dns_records:
            # クエリされたドメインがDNSレコードに存在する場合、対応するIPアドレスを取得
            resolved_ip = self.dns_records[query_domain]
            # DNSレスポンスパケットを生成して返す
            dns_response_packet = DNSPacket(
                source_mac=self.mac_address,
                destination_mac=dns_packet.header["source_mac"],
                source_ip=self.ip_address,
                destination_ip=dns_packet.header["source_ip"],
                query_domain=query_domain,
                query_type="A",  # クエリタイプは"A"（IPv4アドレス）
                network_event_scheduler=self.network_event_scheduler
            )
            # DNSレスポンスに解決されたIPアドレスを含める
            dns_response_packet.dns_data = {"resolved_ip": resolved_ip}
            return dns_response_packet
        else:
            # クエリされたドメインがDNSレコードに存在しない場合はNoneを返す
            return None

class DHCPServer(Server):
    def __init__(self, node_id, ip_address, network_event_scheduler, ip_pool_start, ip_pool_end, mac_address=None):
        super().__init__(node_id, ip_address, network_event_scheduler, mac_address)
        self.ip_pool = self.initialize_ip_pool(ip_pool_start, ip_pool_end)
        self.leased_ips = {}

    def initialize_ip_pool(self, start_cidr):
        network = ip_network(start_cidr, strict=False)
        ip_pool = [f"{ip}/{network.prefixlen}" for ip in network.hosts()]
        return ip_pool

    def receive_packet(self, packet, received_link):
        super().receive_packet(packet, received_link)  # Serverクラスの共通処理を利用

        if packet.header["destination_mac"] == "FF:FF:FF:FF:FF:FF" and packet.header["destination_ip"] == "255.255.255.255/32":
            if isinstance(packet, DHCPPacket):
                if packet.message_type == "DISCOVER":
                    self.handle_dhcp_discover(packet)
                elif packet.message_type == "REQUEST":
                    self.handle_dhcp_request(packet)
                else:
                    pass

    def handle_dhcp_discover(self, discover_packet):
        # DHCP DISCOVERメッセージの処理
        # 利用可能なIPアドレスを割り当て、DHCPOfferPacketを生成して送信
        offered_ip = self.assign_ip_address()
        offer_packet = self.create_dhcp_offer_packet(discover_packet, offered_ip)
        self._send_packet(offer_packet)

    def handle_dhcp_request(self, request_packet):
        # DHCP REQUESTメッセージの処理
        # IPアドレスの割り当てを確定し、DHCPAckPacketを生成して送信
        ack_packet = self.create_dhcp_ack_packet(request_packet)
        self._send_packet(ack_packet)

    def assign_ip_address(self, discover_packet):
        # 利用可能なIPアドレスを割り当てる
        if self.ip_pool:
            assigned_ip = self.ip_pool.pop(0)
            # DHCP Offerメッセージの送信
            offer_packet = self.create_dhcp_offer_packet(discover_packet, assigned_ip)
            self.network_event_scheduler.log_packet_info(offer_packet, "DHCP Offer", self.node_id)
            self._send_packet(offer_packet)

    def create_dhcp_offer_packet(self, discover_packet, offered_ip):
        # DHCPOfferPacketの生成（DHCPPacketクラスを使用）
        return DHCPPacket(
            source_mac=self.mac_address,
            destination_mac=discover_packet.header["source_mac"],
            source_ip=self.ip_address,
            destination_ip=offered_ip,
            message_type="OFFER",
            network_event_scheduler=self.network_event_scheduler
        )

    def create_dhcp_ack_packet(self, request_packet):
        # DHCPAckPacketの生成（DHCPPacketクラスを使用）
        return DHCPPacket(
            source_mac=self.mac_address,
            destination_mac=request_packet.header["source_mac"],
            source_ip=self.ip_address,
            destination_ip=request_packet.dhcp_data["requested_ip"],
            message_type="ACK",
            network_event_scheduler=self.network_event_scheduler
        )
