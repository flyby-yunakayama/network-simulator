class Router:
    def __init__(self, node_id, ip_addresses, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.links = []
        self.available_ips = {ip: False for ip in ip_addresses} # CIDR表記のIPアドレスを辞書に変換し、使用状況をFalse（未使用）に初期化
        self.interfaces = {}  # インターフェース（リンクとIPアドレスのマッピング）
        self.routing_table = {}  # ルーティングテーブル
        label = f'Router {node_id}'
        self.network_event_scheduler.add_node(node_id, label)

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

    def matches_subnet(self, ip_address, network_address, subnet_mask):
        ip_addr_int = self.ip_to_int(ip_address)
        network_int = self.ip_to_int(network_address)
        mask_int = self.ip_to_int(subnet_mask)

        network_subnet = network_int & mask_int

        return ip_addr_int & mask_int == network_subnet

    def forward_packet(self, packet):
        destination_ip = packet.header["destination_ip"]
        next_hop, link = self.get_route(destination_ip)

        if link:
            self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
            link.enqueue_packet(packet, self)
        elif self.default_route:
            self.network_event_scheduler.log_packet_info(packet, "forwarded via default route", self.node_id)
            self.default_route.enqueue_packet(packet, self)
        else:
            self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def get_route(self, destination_ip):
        for network_cidr, (next_hop, link) in self.routing_table.items():
            network_address, mask_length = network_cidr.split('/')
            subnet_mask = self.cidr_to_subnet_mask(mask_length)

            if self.matches_subnet(destination_ip, network_address, subnet_mask):
                return next_hop, link
        return None, None

    def cidr_to_network_address(self, cidr):
        network, mask_length = cidr.split('/')
        subnet_mask = self.cidr_mask_to_int(mask_length)
        return network, subnet_mask

    def receive_packet(self, packet, received_link):
        destination_ip = packet.header["destination_ip"]
        for link, interface_cidr in self.interfaces.items():
            network_address, mask_length = interface_cidr.split('/')
            subnet_mask = self.cidr_to_subnet_mask(mask_length)
            if self.matches_subnet(destination_ip, network_address, subnet_mask):
                if self.is_final_destination(packet, network_address):
                    pass
                else:
                    self.forward_packet(packet)
                return
        self.forward_packet(packet)

    def is_final_destination(self, packet, network_address):
        return packet.header["destination_ip"] == network_address

    def process_packet(self, packet, received_link):
        print(f"Packet {packet.id} processed at router {self.node_id}")

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
