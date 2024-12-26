import uuid

class Packet:
    def __init__(self, source_mac, destination_mac, source_ip, destination_ip, ttl, fragment_flags, fragment_offset, header_size, payload_size, network_event_scheduler, dscp=0):
        self.network_event_scheduler = network_event_scheduler
        self.id = str(uuid.uuid4())
        # MACヘッダとIPヘッダを分割して管理
        self.mac_header = {
            "source_mac": source_mac,
            "destination_mac": destination_mac
        }
        self.ip_header = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "ttl": ttl,
            "fragment_flags": fragment_flags,
            "fragment_offset": fragment_offset,
            "dscp": dscp
        }
        self.size = header_size + payload_size
        self.creation_time = self.network_event_scheduler.current_time
        self.arrival_time = None
    
    @property
    def header(self):
        # MACヘッダとIPヘッダを統合して返す
        return {**self.mac_header, **self.ip_header}

    # MACヘッダを疑似的に除去するメソッド
    def remove_mac_header(self):
        self.mac_header = {}

    # MACヘッダを再付与するメソッド
    def add_mac_header(self, source_mac, destination_mac):
        self.mac_header = {
            "source_mac": source_mac,
            "destination_mac": destination_mac
        }

    def get_priority(self):
        # Map DSCP values to priority levels (0-7, with 7 being the highest priority)
        dscp = self.ip_header["dscp"]
        if dscp >= 56:  # Network Control
            return 7
        elif dscp >= 48:  # Expedited Forwarding
            return 6
        elif dscp >= 40:  # Assured Forwarding 4
            return 5
        elif dscp >= 32:  # Assured Forwarding 3
            return 4
        elif dscp >= 24:  # Assured Forwarding 2
            return 3
        elif dscp >= 16:  # Assured Forwarding 1
            return 2
        elif dscp > 8:  # Class Selector
            return 1
        else:  # Best Effort
            return 0

    def set_arrived(self, arrival_time):
        self.arrival_time = arrival_time

    def __lt__(self, other):
        return False  # heapqでの比較のため

    def __str__(self):
        source_mac = self.mac_header.get("source_mac", "不明")
        destination_mac = self.mac_header.get("destination_mac", "不明")
        return f'パケット(送信元MAC: {source_mac}, 宛先MAC: {destination_mac}, 送信元IP: {self.ip_header["source_ip"]}, 宛先IP: {self.ip_header["destination_ip"]}, TTL: {self.ip_header["ttl"]}, フラグメントフラグ: {self.ip_header["fragment_flags"]}, フラグメントオフセット: {self.ip_header["fragment_offset"]}, ペイロード: {self.payload})'

class TCPPacket(Packet):
    def __init__(self, source_port, destination_port, sequence_number, acknowledgment_number, flags, **kwargs):
        super().__init__(**kwargs)
        self.tcp_header = {
            "source_port": source_port,
            "destination_port": destination_port,
            "sequence_number": sequence_number,
            "acknowledgment_number": acknowledgment_number,
            "flags": flags
        }
        self.payload = data

    @property
    def header(self):
        # MACヘッダ、IPヘッダ、TCPヘッダを統合して返す
        return {**self.mac_header, **self.ip_header, **self.tcp_header}

class UDPPacket(Packet):
    def __init__(self, source_port, destination_port, **kwargs):
        super().__init__(**kwargs)
        self.udp_header = {
            "source_port": source_port,
            "destination_port": destination_port
        }
        self.payload = data

    @property
    def header(self):
        # MACヘッダ、IPヘッダ、UDPヘッダを統合して返す
        return {**self.mac_header, **self.ip_header, **self.udp_header}

class ARPPacket(Packet):
    def __init__(self, source_mac, destination_mac, source_ip, destination_ip, operation, network_event_scheduler):
        super().__init__(
            source_mac=source_mac,
            destination_mac=destination_mac,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ttl=1, fragment_flags={}, fragment_offset=0, # ダミーのTTLとフラグメント情報
            dscp=56,
            header_size=28,  # ARPヘッダの標準的なサイズ
            payload_size=28,  # ARPパケットのペイロードサイズ
            network_event_scheduler=network_event_scheduler
        )
        # ARP特有の情報をペイロードとして設定
        self.payload = {
            "operation": operation,  # ARP操作（"request"または"reply"）
            "source_mac": source_mac,  # 送信元MACアドレス
            "destination_mac": destination_mac,  # 宛先MACアドレス
            "source_ip": source_ip,  # 送信元IPアドレス
            "destination_ip": destination_ip  # 宛先IPアドレス
        }

    def __str__(self):
        # ARPパケットの情報を文字列で返す
        return f'ARPPacket(送信元MAC: {self.mac_header["source_mac"]}, 宛先MAC: {self.mac_header["destination_mac"]}, 操作: {self.payload["operation"]})'

class DNSPacket(Packet):
    def __init__(self, source_mac, destination_mac, source_ip, destination_ip, query_domain, query_type, network_event_scheduler):
        super().__init__(
            source_mac=source_mac,
            destination_mac=destination_mac,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ttl=64,  # DNSパケットのTTLは通常のIPパケットと同様に設定
            dscp=56,
            fragment_flags={}, fragment_offset=0,
            header_size=0,  # DNSヘッダサイズは固定ではないため、具体的なサイズは省略
            payload_size=0,  # 実際のペイロードサイズはクエリによって異なる
            network_event_scheduler=network_event_scheduler
        )
        self.query_domain = query_domain  # 問い合わせるドメイン名
        self.query_type = query_type  # 問い合わせるタイプ（例: A, AAAA, MXなど）
        # DNSクエリまたはレスポンスの詳細情報を格納するためのプレースホルダ
        self.dns_data = {}

    def __str__(self):
        source_mac = self.mac_header.get("source_mac", "不明")
        destination_mac = self.mac_header.get("destination_mac", "不明")
        return f'DNSPacket(送信元MAC: {source_mac}, 宛先MAC: {destination_mac}, 送信元IP: {self.ip_header["source_ip"]}, 宛先IP: {self.ip_header["destination_ip"]}, Query Domain: {self.query_domain}, Query Type: {self.query_type})'

class DHCPPacket(Packet):
    def __init__(self, source_mac, destination_mac, source_ip, destination_ip, message_type, network_event_scheduler):
        super().__init__(
            source_mac=source_mac,
            destination_mac=destination_mac,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ttl=255,  # DHCPパケットは通常ローカルネットワーク内でのみ流れるためTTLは最大値
            dscp=56,
            fragment_flags={}, fragment_offset=0,
            header_size=240,  # DHCPパケットのヘッダサイズは固定で240バイト
            payload_size=0,  # 実際のペイロードサイズはオプションによって異なる
            network_event_scheduler=network_event_scheduler
        )
        self.message_type = message_type  # DHCPメッセージタイプ ('DISCOVER', 'OFFER', 'REQUEST', 'ACK')
        # DHCPメッセージの詳細情報を格納するためのプレースホルダ
        self.dhcp_data = {}

    def __str__(self):
        source_mac = self.mac_header.get("source_mac", "不明")
        destination_mac = self.mac_header.get("destination_mac", "不明")
        return f'DHCPPacket(送信元MAC: {source_mac}, 宛先MAC: {destination_mac}, 送信元IP: {self.ip_header["source_ip"]}, 宛先IP: {self.ip_header["destination_ip"]}, Message Type: {self.message_type})'

class BPDU(Packet):
    def __init__(self, source_mac, destination_mac, root_id, bridge_id, path_cost, network_event_scheduler):
        super().__init__(
            source_mac=source_mac, 
            destination_mac=destination_mac,
            source_ip='0.0.0.0/24',  # IPv4用ダミーIPアドレス
            destination_ip='0.0.0.0/24',  # IPv4用ダミーIPアドレス
            ttl=1,
            fragment_flags={},
            fragment_offset=0, # ダミーのTTLとフラグメント情報
            dscp=56,
            header_size=20,
            payload_size=50,
            network_event_scheduler=network_event_scheduler
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
            dscp=56,
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
            dscp=56,
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
