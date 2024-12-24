import random

from sec15a.Packet import DNSPacket, DHCPPacket, TCPPacket, UDPPacket

class ApplicationManager:
    def __init__(self, node):
        self.node = node

        # DNS, DHCPクライアントを内部で生成
        self.dns_client = DnsClient(node)
        # DHCPクライアントは必要に応じて登録
        self.dhcp_client = None

        # 管理するアプリケーションインスタンス
        self.ftp_client = None
        self.ftp_server = None
        self.http_client = None
        self.http_server = None
        self.udp_app = None

        # connection_keyやプロトコルに応じてアプリを特定するマップ
        self.connection_app_map = {}

    def register_ftp_client(self, ftp_client):
        self.ftp_client = ftp_client

    def register_ftp_server(self, ftp_server):
        self.ftp_server = ftp_server

    def register_http_client(self, http_client):
        self.http_client = http_client

    def register_http_server(self, http_server):
        self.http_server = http_server

    def register_udp_app(self, udp_app):
        self.udp_app = udp_app

    def register_dhcp_client(self):
        """Register a DHCP client for this node and schedule discover if needed."""
        self.dhcp_client = DhcpClient(self.node)
        # Schedule DHCP discover if using dynamic IP
        if self.node.is_network_address(self.node.ip_address):
            self.dhcp_client.schedule_dhcp_discover()

    def map_connection_to_app(self, connection_key, app_type):
        self.connection_app_map[connection_key] = app_type

    def on_dns_packet_received(self, packet):
        self.dns_client.on_dns_packet_received(packet)

    def on_dhcp_packet_received(self, packet):
        self.dhcp_client.on_dhcp_packet_received(packet)

    def on_packet_received(self, packet):
        """
        Nodeから呼ばれるパケット受信イベント。
        TCP/UDPなどのポートやIP情報を見て、どのアプリへ渡すか決定。
        """
        protocol = "TCP" if isinstance(packet, TCPPacket) else ("UDP" if isinstance(packet, UDPPacket) else None)
        if not protocol:
            return  # ARP, DHCP, DNSは別処理済み

        app_type = self.connection_app_map.get((packet.header.get("source_ip"), packet.header.get("source_port")))

        # print("src", packet.header.get("source_ip"), packet.header.get("source_port"), "dst", packet.header.get("destination_ip"), packet.header.get("destination_port"), app_type)

        if app_type == "FTP" and self.ftp_client:
            self.ftp_client.on_packet_received(packet)
        elif app_type == "FTPSERVER" and self.ftp_server:
            self.ftp_server.on_packet_received(packet)
        elif app_type == "HTTP" and self.http_client:
            self.http_client.on_packet_received(packet)
        elif app_type == "HTTPSERVER" and self.http_server:
            self.http_server.on_packet_received(packet)
        elif app_type == None and (self.ftp_server or self.http_server):  # マッピングがない場合はサーバとして扱う
            if packet.header.get("destination_port") == 80 and self.http_server:
                self.connection_app_map[(packet.header.get("source_ip"), packet.header.get("source_port"))] = "HTTPSERVER"
                self.http_server.on_packet_received(packet)
            elif self.ftp_server:
                self.ftp_server.on_packet_received(packet)
        elif app_type == "UDP" and self.udp_app:
            self.udp_app.on_packet_received(packet)
        else:
            # マッピングがない場合はドロップ、あるいはログ
            pass

    def on_connection_established(self, connection_key):
        # connection_keyに基づいてどのアプリか判定
        # 該当のアプリケーションへon_connection_establishedイベントを渡す
        app_type = self.connection_app_map.get((connection_key[0], connection_key[1]))
        print("on_connection_established", connection_key, app_type)
        if app_type == "FTP" and self.ftp_client:
            self.ftp_client.on_connection_established(connection_key)
        elif app_type == "FTPSERVER" and self.ftp_server:
            self.ftp_server.on_connection_established(connection_key)
        elif app_type == "HTTP" and self.http_client:
            self.http_client.on_connection_established(connection_key)
        elif app_type == "HTTPSERVER" and self.http_server:
            self.http_server.on_connection_established(connection_key)
        elif app_type == None:  # マッピングがない場合はサーバとして扱う
            if connection_key[1] == 80 and self.http_server:  # ポート80はHTTPサーバ
                self.connection_app_map[connection_key] = "HTTPSERVER"
                self.http_server.on_connection_established(connection_key)
            elif self.ftp_server:  # それ以外はFTPサーバ
                self.connection_app_map[connection_key] = "FTPSERVER"
                self.ftp_server.on_connection_established(connection_key)
        # UDPAppなども同様にハンドル可能

    def get_traffic_info(self, connection_key):
        conn = self.node.tcp_connections.get(connection_key)
        if conn and 'transfer_info' in conn:
            return conn['transfer_info']
        return None

    def get_data_chunk(self, connection_key, payload_size):
        app_type = self.connection_app_map.get(connection_key)
        if app_type == "FTP" and self.ftp_client:
            return self.ftp_client.get_data_chunk(connection_key, payload_size)
        elif app_type == "FTPSERVER" and self.ftp_server:
            return self.ftp_server.get_data_chunk(connection_key, payload_size)
        return None

    def update_data_after_send(self, connection_key, sent_bytes):
        key = (connection_key[0], connection_key[1])
        app_type = self.connection_app_map.get(key)

        # デバッグ用出力：現在のconnection_keyとapp_type
        print(f"[DEBUG update_data_after_send] connection_key={connection_key}, app_type={app_type}")
        
        # FTPサーバの場合
        if app_type == "FTPSERVER" and self.ftp_server:
            # traffic_info を node.tcp_connections から取得
            transfer_info = self.node.tcp_connections.get(connection_key, {}).get('transfer_info', {})
            # デバッグ用出力：transfer_info の内容
            print(f"[DEBUG update_data_after_send] transfer_info for {connection_key}: {transfer_info}")

            if transfer_info.get('file_size', 0) > 0 and not transfer_info.get('transfer_done', False):
                self.ftp_server.update_data_after_send(connection_key, sent_bytes)
                client_ip, client_port = connection_key
                server_port = 21
                self.ftp_server.check_transfer_complete(connection_key, client_ip, client_port, server_port)
            else:
                # ファイル転送中でない制御メッセージの場合は何もしない
                pass

        # FTPクライアントの場合
        elif app_type == "FTP" and self.ftp_client:
            # traffic_info を node.tcp_connections から取得
            transfer_info = self.node.tcp_connections.get(connection_key, {}).get('transfer_info', {})
            # デバッグ用出力：transfer_info の内容
            print(f"[DEBUG update_data_after_send] transfer_info for {connection_key}: {transfer_info}")

            if transfer_info.get('file_size', 0) > 0:
                self.ftp_client.update_data_after_send(connection_key, sent_bytes)
        else:
            # 非FTPやマッピングなしの場合は特に何もしない
            print("[DEBUG update_data_after_send] No FTP client/server associated with this connection_key.")

    def resolve_destination_url(self, destination_url, callback=None):
        if self.node.is_valid_cidr_notation(destination_url):
            if callback:
                callback(destination_url)
            return destination_url

        if destination_url in self.dns_client.url_to_ip_mapping:
            resolved_ip = self.dns_client.url_to_ip_mapping[destination_url]
            if callback:
                callback(resolved_ip)
            return resolved_ip
        else:
            self.dns_client.resolve_domain(destination_url, callback)
            return None

    def check_dns_resolution(self):
        self.dns_client.check_pending_queries()


class DnsClient:
    def __init__(self, node):
        self.node = node
        self.url_to_ip_mapping = {}
        self.pending_queries = {}

    def resolve_domain(self, domain, callback=None):
        """Send a DNS query for the given domain."""
        # Check if already resolved
        if domain in self.url_to_ip_mapping:
            if callback:
                callback(self.url_to_ip_mapping[domain])
            return
        if not self.node.dns_server_ip:
            print("No DNS server IP set. Cannot resolve domain.")
            return

        print(f"Node {self.node.node_id} sending DNS query for {domain}")
        # Create DNS query packet
        dns_query_packet = DNSPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",  # Broadcast
            source_ip=self.node.ip_address,
            destination_ip=self.node.dns_server_ip,
            query_domain=domain,
            query_type="A",
            network_event_scheduler=self.node.network_event_scheduler
        )
        self.pending_queries[domain] = callback
        # Send DNS query directly using UDP
        self.node._send_packet(dns_query_packet)

    def on_dns_packet_received(self, packet):
        if packet.query_domain and "resolved_ip" in packet.dns_data:
            domain = packet.query_domain
            resolved_ip = packet.dns_data["resolved_ip"]
            self.url_to_ip_mapping[domain] = resolved_ip
            print(f"DNS resolved: {domain} -> {resolved_ip}")
            if domain in self.pending_queries and self.pending_queries[domain]:
                self.pending_queries[domain](resolved_ip)
            if domain in self.pending_queries:
                del self.pending_queries[domain]

    def check_pending_queries(self):
        # 必要ならタイムアウト処理など実装
        pass


class DhcpClient:
    def __init__(self, node):
        self.node = node
        self.state = "INIT"
        self.requested_ip = None
        self.retries = 0
        self.max_retries = 3
        self.retry_timeout = 2.0  # seconds

    def schedule_dhcp_discover(self):
        """
        DHCP DISCOVERをランダムな遅延後に送信する。
        Node側またはシナリオ側でこのメソッドが呼ばれることでDHCP開始。
        """
        initial_delay = random.uniform(0.5, 0.6)
        self.node.network_event_scheduler.schedule_event(
            self.node.network_event_scheduler.current_time + initial_delay,
            self.send_dhcp_discover
        )

    def send_dhcp_discover(self):
        """Send DHCP discover packet and schedule retry if needed."""
        print(f"Node {self.node.node_id} sending DHCP DISCOVER (attempt {self.retries + 1}/{self.max_retries})")
        
        # DHCP Discover
        dhcp_discover_packet = DHCPPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip="0.0.0.0/32",
            destination_ip="255.255.255.255/32",
            message_type="DISCOVER",
            network_event_scheduler=self.node.network_event_scheduler
        )
        
        # Use _send_packet directly for broadcast packets
        self.node._send_packet(dhcp_discover_packet)
        self.node.network_event_scheduler.log_packet_info(dhcp_discover_packet, "DHCP Discover sent", self.node.node_id)
        self.state = "DISCOVER_SENT"
        
        # Schedule retry if we haven't exceeded max retries
        if self.retries < self.max_retries:
            self.node.network_event_scheduler.schedule_event(
                self.node.network_event_scheduler.current_time + self.retry_timeout,
                self.retry_discover
            )
            
    def retry_discover(self):
        """Retry DHCP discover if still in DISCOVER_SENT state."""
        if self.state == "DISCOVER_SENT":
            self.retries += 1
            if self.retries < self.max_retries:
                self.send_dhcp_discover()
            else:
                print(f"Node {self.node.node_id} failed to get DHCP response after {self.max_retries} attempts")

    def on_dhcp_packet_received(self, packet):
        """Handle incoming DHCP packets based on current state."""
        # Log packet arrival
        self.node.network_event_scheduler.log_packet_info(packet, "arrived", self.node.node_id)
        packet.set_arrived(self.node.network_event_scheduler.current_time)

        if packet.message_type == "OFFER" and self.state == "DISCOVER_SENT":
            # Log DHCP Offer
            self.node.network_event_scheduler.log_packet_info(packet, "DHCP Offer received", self.node.node_id)
            offered_ip = packet.dhcp_data.get("offered_ip")
            if offered_ip:
                self.send_dhcp_request(offered_ip)
                self.state = "REQUEST_SENT"

        elif packet.message_type == "ACK" and self.state == "REQUEST_SENT":
            # Log DHCP ACK
            self.node.network_event_scheduler.log_packet_info(packet, "DHCP ACK received", self.node.node_id)
            assigned_ip = packet.dhcp_data.get("assigned_ip")
            dns_server_ip = packet.dhcp_data.get("dns_server_ip")
            if assigned_ip:
                self.node.set_ip_address(assigned_ip)
                print(f"Node {self.node.node_id} has been assigned the IP address {assigned_ip}.")
            if dns_server_ip:
                self.node.set_dns_server_ip(dns_server_ip)
                print(f"Node {self.node.node_id} has been assigned the DNS server IP address {dns_server_ip}.")
            self.state = "BOUND"

    def send_dhcp_request(self, requested_ip):
        """Send DHCP request packet and schedule retry if needed."""
        print(f"Node {self.node.node_id} sending DHCP REQUEST for IP {requested_ip}")
        
        dhcp_request_packet = DHCPPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip="0.0.0.0/32",
            destination_ip="255.255.255.255/32",
            message_type="REQUEST",
            network_event_scheduler=self.node.network_event_scheduler
        )
        dhcp_request_packet.dhcp_data = {"requested_ip": requested_ip}
        
        # Use _send_packet directly for broadcast packets
        self.node._send_packet(dhcp_request_packet)
        self.node.network_event_scheduler.log_packet_info(
            dhcp_request_packet, 
            "DHCP Request sent", 
            self.node.node_id
        )
        self.state = "REQUEST_SENT"
        
        # Schedule retry
        self.node.network_event_scheduler.schedule_event(
            self.node.network_event_scheduler.current_time + self.retry_timeout,
            lambda: self.retry_request(requested_ip)
        )
        
    def retry_request(self, requested_ip):
        """Retry DHCP request if still in REQUEST_SENT state."""
        if self.state == "REQUEST_SENT":
            self.retries += 1
            if self.retries < self.max_retries:
                self.send_dhcp_request(requested_ip)
            else:
                print(f"Node {self.node.node_id} failed to get DHCP ACK after {self.max_retries} attempts")

class UDPApp:
    def __init__(self, node, protocol="UDP"):
        self.node = node
        self.app_manager = node.application_layer
        self.protocol = protocol
        self.bitrate = None
        self.header_size = None
        self.payload_size = None
        self.burstiness = None
        self.dscp = 0
        self.destination_ip = None
        self.destination_port = None
        self.source_port = None
        self.end_time = None

    def start_traffic(self, destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, dscp=0):
        self.bitrate = bitrate
        self.header_size = header_size
        self.payload_size = payload_size
        self.burstiness = burstiness
        self.dscp = dscp
        self.end_time = self.node.network_event_scheduler.current_time + duration

        self.source_port = self.node.select_random_port()
        self.destination_port = self.node.select_random_port()

        def on_resolved(ip):
            self.destination_ip = ip
            current_time = self.node.network_event_scheduler.current_time
            delay = max(0, start_time - current_time)
            self.node.network_event_scheduler.schedule_event(current_time + delay, self.schedule_traffic)
            # UDP通信キーをApplicationManagerに登録
            self.app_manager.map_connection_to_app((ip, self.destination_port), "UDP")

        resolved_ip = self.app_manager.resolve_destination_url(destination_url, callback=on_resolved)
        if resolved_ip is not None:
            # すでに解決済みなら即スケジュール
            self.destination_ip = resolved_ip
            self.node.network_event_scheduler.schedule_event(start_time, self.schedule_traffic)
            self.app_manager.map_connection_to_app((resolved_ip, self.destination_port), "UDP")

    def schedule_traffic(self):
        self.send_packet_event()

    def send_packet_event(self):
        current_time = self.node.network_event_scheduler.current_time
        if current_time > self.end_time:
            return

        data = b'X' * self.payload_size
        self.node.send_app_data(self.destination_ip, data, protocol=self.protocol, dscp=self.dscp,
                                source_port=self.source_port, destination_port=self.destination_port)
        packet_size = self.header_size + self.payload_size
        interval = (packet_size * 8) / self.bitrate * self.burstiness
        next_time = current_time + interval
        self.node.network_event_scheduler.schedule_event(next_time, self.send_packet_event)

    def on_packet_received(self, packet):
        # UDP受信時の処理(今回は送信専用と仮定し、何もしない)
        pass


class FTPClient:
    def __init__(self, node, server_url=None, verbose=False):
        self.node = node
        self.app_manager = node.application_layer
        self.server_url = server_url
        self.verbose = verbose
        self.state = "NOT_CONNECTED"
        self.file_to_retrieve = None
        self.outgoing_data = {}

    def connect(self, server_ip, server_port=21):
        if self.verbose:
            print("[FTPClient] Requesting TCP connect to ", server_ip, server_port)
        self.server_ip = server_ip  # サーバIPを保存
        self.server_port = server_port  # サーバポートを保存
        self.state = "CONNECTING"
        self.node.initiate_tcp_handshake(server_ip, server_port)
        self.app_manager.map_connection_to_app((server_ip, server_port), "FTP")

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[FTPClient] Received: ", data.strip())

        # FTPの基本的な流れ:
        # 1. 接続成立後、サーバから220応答が来る
        # 2. クライアントはUSERコマンド送信
        # 3. サーバが331応答ならPASSコマンド送信
        # 4. サーバが230応答ならログイン成功
        # 5. ファイル取得(RETR)コマンドなどを送る
        if data.startswith("220"):
            self.state = "LOGGED_OUT"
            self.send_ftp_command("USER anonymous\r\n")
        elif data.startswith("331"):
            self.send_ftp_command("PASS anonymous@\r\n")
        elif data.startswith("230"):
            self.state = "LOGGED_IN"
            if self.file_to_retrieve:
                self.send_ftp_command(f"RETR {self.file_to_retrieve}\r\n")
        elif data.startswith("150"):
            # ファイル転送開始時にtraffic_infoをセットするなどの処理をここで行う
            pass
        elif data.startswith("226"):
            # 転送完了
            pass

    def on_connection_established(self, connection_key):
        self.set_traffic_info(connection_key)
        if self.verbose:
            print("[FTPClient] Connection established. Waiting for server greeting (220)...")

    def send_ftp_command(self, command):
        if self.verbose:
            print("[FTPClient] Sending command:", command.strip())
        # server_portを使ってsend_app_dataに渡す
        self.node.send_app_data(
            self.server_ip,
            command.encode('utf-8'),
            protocol="TCP",
            destination_port=self.server_port
        )

    def retrieve_file(self, filename):
        self.file_to_retrieve = filename
        if self.verbose:
            print("[FTPClient] Will retrieve file after login:", filename)

    def set_traffic_info(self, connection_key):
        end_time = self.node.network_event_scheduler.current_time + 3600
        payload_size = 1460
        # Node側に直接書き込む
        self.node.tcp_connections[connection_key]['transfer_info'] = {
            'end_time': end_time,
            'payload_size': payload_size,
            'bytes_transferred': 0,
            'progress': [],
            'file_size': 0,
            'transfer_done': False
        }

    def get_traffic_info(self, connection_key):
        return self.node.tcp_connections[connection_key].get('transfer_info', None)

    def get_data_chunk(self, connection_key, payload_size):
        data = self.outgoing_data.get(connection_key, b'')
        chunk = data[:payload_size]
        return chunk

    def update_data_after_send(self, connection_key, sent_bytes):
        data = self.outgoing_data.get(connection_key, b'')
        self.outgoing_data[connection_key] = data[sent_bytes:]


class FTPServer:
    def __init__(self, node, shared_files, verbose=False):
        self.node = node
        self.app_manager = node.application_layer  
        self.shared_files = shared_files
        self.verbose = verbose
        self.state = "READY"
        self.outgoing_data = {}  # 送るべきファイルデータを保持するための辞書

    def on_connection_established(self, connection_key):
        self.set_traffic_info(connection_key)
        client_ip, client_port = connection_key
        server_port = 21  # 自サーバのFTP制御ポート
        if self.verbose:
            print("[FTPServer] Connection established. Sending 220 greeting.")
        self.send_ftp_response(client_ip, client_port, server_port, "220 Service ready\r\n")
        self.state = "WAIT_USER"

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[FTPServer] Received: ", data.strip())

        client_ip = packet.header["source_ip"]
        client_port = packet.header["source_port"]
        server_port = packet.header["destination_port"]
        connection_key = (client_ip, client_port)

        if self.state == "WAIT_USER":
            if data.startswith("USER"):
                self.send_ftp_response(client_ip, client_port, server_port, "331 User name okay, need password.\r\n")
            elif data.startswith("PASS"):
                self.send_ftp_response(client_ip, client_port, server_port, "230 User logged in, proceed.\r\n")
                self.state = "LOGGED_IN"

        elif self.state == "LOGGED_IN":
            if data.startswith("RETR"):
                parts = data.strip().split(" ", 1)
                if len(parts) < 2:
                    self.send_ftp_response(client_ip, client_port, server_port, "501 Syntax error in parameters or arguments.\r\n")
                    return
                filename = parts[1]
                file_data = self.shared_files.get(filename, None)
                if file_data is None:
                    self.send_ftp_response(client_ip, client_port, server_port, "550 File not found.\r\n")
                    return
                
                file_size = len(file_data)
                transfer_info = {
                    'end_time': self.node.network_event_scheduler.current_time + 3600,
                    'payload_size': 1460,
                    'bytes_transferred': 0,
                    'progress': [],
                    'file_size': file_size,
                    'transfer_done': False
                }

                # Node側のtransfer_infoに直接設定
                self.node.tcp_connections[connection_key]['transfer_info'] = transfer_info
                self.outgoing_data[connection_key] = file_data

                self.send_ftp_response(client_ip, client_port, server_port, "150 File status okay; about to open data connection.\r\n")
                self.send_next_chunk(connection_key, client_ip, client_port, server_port)

    def send_next_chunk(self, connection_key, client_ip, client_port, server_port):
        chunk = self.get_data_chunk(connection_key, self.node.tcp_connections[connection_key]['transfer_info']['payload_size'])
        if chunk:
            self.node.send_app_data(client_ip, chunk, protocol="TCP", source_port=server_port, destination_port=client_port)
        else:
            # 送るべきデータが尽きた。ACK後にtransfer_done確認へ
            pass

    def get_data_chunk(self, connection_key, payload_size):
        """
        outgoing_dataからpayload_size分のデータを取り出す。
        """
        if connection_key not in self.outgoing_data:
            return b""
        data = self.outgoing_data[connection_key]
        if not data:
            return b""
        chunk = data[:payload_size]
        # chunk送出後、outgoing_dataをスライス
        self.outgoing_data[connection_key] = data[payload_size:]
        return chunk

    def update_data_after_send(self, connection_key, bytes_sent):
        ti = self.node.tcp_connections[connection_key]['transfer_info']
        self.check_transfer_complete(connection_key, *connection_key, 21)

    def check_transfer_complete(self, connection_key, client_ip, client_port, server_port):
        ti = self.node.tcp_connections[connection_key]['transfer_info']
        if ti['bytes_transferred'] >= ti['file_size'] and not self.outgoing_data.get(connection_key, b''):
            if not ti['transfer_done']:
                ti['transfer_done'] = True
                self.send_ftp_response(client_ip, client_port, server_port, "226 Closing data connection.\r\n")
                if self.verbose:
                    print(f"[FTPServer] Transfer complete for {connection_key}. Sent 226 response.")

    def send_ftp_response(self, dst_ip, client_port, server_port, response):
        if self.verbose:
            print("[FTPServer] Sending response:", response.strip())
        self.node.send_control_tcp_packet(
            dst_ip=dst_ip,
            data=response.encode('utf-8'),
            dscp=0,
            source_port=server_port,
            destination_port=client_port,
            flags="ACK"
        )

    def set_traffic_info(self, connection_key):
        end_time = self.node.network_event_scheduler.current_time + 3600
        payload_size = 1460
        self.node.tcp_connections[connection_key]['transfer_info'] = {
            'end_time': end_time,
            'payload_size': payload_size,
            'bytes_transferred': 0,
            'progress': [],
            'file_size': 0,
            'transfer_done': False
        }

    def get_traffic_info(self, connection_key):
        return self.node.tcp_connections[connection_key].get('transfer_info', None)


class HTTPClient:
    def __init__(self, node, server_url=None, verbose=False):
        self.node = node
        self.app_manager = node.application_layer
        self.server_url = server_url
        self.verbose = verbose
        self.state = "NOT_CONNECTED"
        self.file_to_retrieve = None
        self.response_data = {}
        
    def connect(self, server_ip, server_port=80):
        if self.verbose:
            print("[HTTPClient] Requesting TCP connect to", server_ip, server_port)
        self.server_ip = server_ip
        self.server_port = server_port
        self.state = "CONNECTING"
        self.node.initiate_tcp_handshake(server_ip, server_port)
        self.app_manager.map_connection_to_app((server_ip, server_port), "HTTP")
        
    def get_file(self, filename):
        self.file_to_retrieve = filename
        if self.state == "CONNECTED":
            self.send_http_request(f"GET /{filename} HTTP/1.0\r\n\r\n")
        elif self.verbose:
            print("[HTTPClient] Will retrieve file after connection:", filename)
            
    def send_http_request(self, request):
        if self.verbose:
            print("[HTTPClient] Sending request:", request.strip())
        self.node.send_app_data(
            self.server_ip,
            request.encode('utf-8'),
            protocol="TCP",
            destination_port=self.server_port
        )
        
    def on_connection_established(self, connection_key):
        self.state = "CONNECTED"
        if self.verbose:
            print("[HTTPClient] Connection established.")
        if self.file_to_retrieve:
            self.get_file(self.file_to_retrieve)
            
    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[HTTPClient] Received:", data.strip())
            
        # Simple HTTP response parsing
        if data.startswith("HTTP/1.0 200 OK"):
            if self.verbose:
                print("[HTTPClient] File retrieved successfully")
        elif data.startswith("HTTP/1.0 404"):
            if self.verbose:
                print("[HTTPClient] File not found")


class HTTPServer:
    def __init__(self, node, shared_files, verbose=False):
        self.node = node
        self.app_manager = node.application_layer
        self.shared_files = shared_files
        self.verbose = verbose
        self.state = "READY"
        
    def on_connection_established(self, connection_key):
        if self.verbose:
            print("[HTTPServer] Connection established.")
        self.state = "READY"
            
    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[HTTPServer] Received:", data.strip())
            
        client_ip = packet.header["source_ip"]
        client_port = packet.header["source_port"]
        server_port = packet.header["destination_port"]
        
        # Parse HTTP request
        if data.startswith("GET"):
            # Extract filename from GET request
            parts = data.split(" ")
            if len(parts) < 2:
                self.send_http_response(client_ip, client_port, server_port, "HTTP/1.0 400 Bad Request\r\n\r\n")
                return
                
            filename = parts[1].lstrip("/").split()[0]  # Remove leading / and any trailing parts
            file_data = self.shared_files.get(filename, None)
            
            
            if file_data is None:
                # File not found - send 404
                self.send_http_response(client_ip, client_port, server_port, "HTTP/1.0 404 Not Found\r\n\r\n")
                return
                
            # File found - send 200 OK with Content-Length
            response = f"HTTP/1.0 200 OK\r\nContent-Length: {len(file_data)}\r\n\r\n"
            response = response.encode('utf-8') + file_data
            
            if self.verbose:
                print(f"[HTTPServer] Sending file {filename} ({len(file_data)} bytes)")
                
            self.node.send_app_data(
                client_ip,
                response,
                protocol="TCP",
                source_port=server_port,
                destination_port=client_port
            )
            
    def send_http_response(self, client_ip, client_port, server_port, response):
        if self.verbose:
            print("[HTTPServer] Sending response:", response.strip())
        self.node.send_app_data(
            client_ip,
            response.encode('utf-8'),
            protocol="TCP",
            source_port=server_port,
            destination_port=client_port
        )


class TLSClient:
    """
    クライアント側のTLSを模擬するクラス。
    - TCP接続が確立された後に start_tls_handshake() を呼び出す想定。
    - 簡易的に shared_key を固定し、暗号化の代わりに ENC(...) で包むだけ。
    """

    def __init__(self, node, verbose=False):
        self.node = node
        self.verbose = verbose
        self.handshake_done = False
        self.shared_key = None  # 実際には鍵交換などを経て生成するが、ここでは模擬用

    def start_tls_handshake(self, connection_key):
        """
        TLSハンドシェイクを模擬する。実際には暗号アルゴリズムや証明書交換などを省略し、
        handshake_done=True にするだけ。
        """
        if self.verbose:
            print(f"[TLSClient] Starting TLS handshake with {connection_key}")

        # 簡易的: 'dummy_key' を共有鍵として設定
        self.shared_key = "dummy_key"
        self.handshake_done = True

        if self.verbose:
            print(f"[TLSClient] TLS Handshake done. Shared key = {self.shared_key}")

    def send_encrypted(self, connection_key, app_data: bytes):
        """
        TLSハンドシェイク後にアプリデータを "暗号化"（体）で送信。
        - 実際には b"ENC(" + ... + b")" で包んでいるだけ。
        """
        if not self.handshake_done:
            if self.verbose:
                print("[TLSClient] Error: TLS handshake not done yet.")
            return

        # 簡易 "暗号化"
        encrypted_data = b"ENC(" + app_data + b")"

        dst_ip, dst_port = connection_key
        # 実際のTCP送信を node.send_app_data(...) に任せる
        self.node.send_app_data(dst_ip, encrypted_data, protocol="TCP", destination_port=dst_port)

    def receive_encrypted(self, packet):
        """
        packet.payload が ENC(...) の形で来ると想定し、暗号解除を模擬する。
        """
        if not self.handshake_done:
            if self.verbose:
                print("[TLSClient] Error: Received data before TLS handshake.")
            return b""

        payload = packet.payload
        # ENC(...) で包まれているなら中身を取り出す
        if payload.startswith(b"ENC(") and payload.endswith(b")"):
            return payload[4:-1]  # ENC(... ) の ... 部分を返す
        return payload


class TLSServer:
    """
    サーバ側のTLSを模擬するクラス。
    - TCP接続（ポート443など）が確立されたら accept_tls_handshake() を呼んでもらう想定。
    - 暗号化も簡易的に ENC(...) を使用。
    """

    def __init__(self, node, verbose=False):
        self.node = node
        self.verbose = verbose
        self.handshake_done = False
        self.shared_key = None

    def accept_tls_handshake(self, connection_key):
        """
        クライアントからのTLS接続要求を受け付ける形でハンドシェイクを模擬。
        実際には "ServerHello, Certificate" 等を送るが省略。
        """
        if self.verbose:
            print(f"[TLSServer] Accepting TLS handshake on {connection_key}")

        self.shared_key = "dummy_key"
        self.handshake_done = True

        if self.verbose:
            print(f"[TLSServer] TLS Handshake done. Shared key = {self.shared_key}")

    def send_encrypted(self, connection_key, app_data: bytes):
        """
        サーバ側から暗号化（体）して送信する。
        """
        if not self.handshake_done:
            if self.verbose:
                print("[TLSServer] Error: TLS handshake not done yet.")
            return

        encrypted_data = b"ENC(" + app_data + b")"
        dst_ip, dst_port = connection_key
        self.node.send_app_data(dst_ip, encrypted_data, protocol="TCP", destination_port=dst_port)

    def receive_encrypted(self, packet):
        """
        ENC(...) 形のペイロードを復号（体）して返す。
        """
        if not self.handshake_done:
            if self.verbose:
                print("[TLSServer] Error: Received data before TLS handshake.")
            return b""

        payload = packet.payload
        if payload.startswith(b"ENC(") and payload.endswith(b")"):
            return payload[4:-1]
        return payload


class HTTPSClient:
    """
    TLSClient + HTTPClient を合体させたクラスの一例。
    - 先にTCPハンドシェイク完了後、TLSハンドシェイク (start_tls_handshake) を行う。
    - HTTPリクエスト/レスポンス時は暗号化(ENC(...))された形で送る/受け取る。
    """

    def __init__(self, node, server_url=None, verbose=False):
        # HTTPClient 相当の情報
        self.node = node
        self.app_manager = node.application_layer
        self.server_url = server_url
        self.verbose = verbose
        self.state = "NOT_CONNECTED"
        self.file_to_retrieve = None

        # TLSClient を内包
        self.tls = TLSClient(node, verbose=verbose)

        # ここではHTTPのような処理を自前で行うが、既存HTTPClientがあるなら継承してもよい
        self.server_ip = None
        self.server_port = None

    def connect(self, server_ip, server_port=443):
        if self.verbose:
            print("[HTTPSClient] Requesting TCP connect to", server_ip, server_port)
        self.server_ip = server_ip
        self.server_port = server_port
        self.state = "CONNECTING"

        # TCPハンドシェイク (Nodeのメソッド)
        self.node.initiate_tcp_handshake(server_ip, server_port)
        self.app_manager.map_connection_to_app((server_ip, server_port), "HTTPS")

    def on_connection_established(self, connection_key):
        # TCPコネクションが確立。次にTLSハンドシェイクを模擬
        if self.verbose:
            print("[HTTPSClient] TCP connection established. Starting TLS handshake...")
        self.tls.start_tls_handshake(connection_key)
        self.state = "CONNECTED"

        # もし事前に "self.file_to_retrieve" が設定されていれば HTTPリクエストを送るなど
        if self.file_to_retrieve:
            self.send_https_request(f"GET /{self.file_to_retrieve} HTTP/1.1\r\nHost: example\r\n\r\n")

    def send_https_request(self, request_str):
        """
        TLSで暗号化したHTTPリクエストを送る。
        """
        if self.state != "CONNECTED":
            if self.verbose:
                print("[HTTPSClient] Not connected yet.")
            return

        connection_key = (self.server_ip, self.server_port)
        if self.verbose:
            print("[HTTPSClient] Sending HTTPS request (encrypted):", request_str.strip())
        self.tls.send_encrypted(connection_key, request_str.encode('utf-8'))

    def get_file(self, filename):
        """
        単純化した "GET /filename" リクエスト
        """
        self.file_to_retrieve = filename
        # 接続済みならすぐ送る
        if self.state == "CONNECTED":
            self.send_https_request(f"GET /{filename} HTTP/1.1\r\nHost: example\r\n\r\n")

    def on_packet_received(self, packet):
        """
        Node -> ApplicationManager -> ここ
        受信したTLS暗号データを復号してHTTPレスポンスを得る。
        """
        decrypted = self.tls.receive_encrypted(packet)
        data = decrypted.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[HTTPSClient] Received (decrypted):", data.strip())

        # ここでHTTPレスポンスをパースするなどお好みで

class HTTPSServer:
    """
    TLSServer + HTTPServer を合体させたクラスの一例。
    - 先にTCPハンドシェイク完了後、accept_tls_handshake() を呼んでTLS確立。
    - HTTPSのリクエスト/レスポンスは暗号化(ENC(...))されてやり取りされる。
    """

    def __init__(self, node, shared_files, verbose=False):
        self.node = node
        self.app_manager = node.application_layer
        self.verbose = verbose
        self.shared_files = shared_files

        # TLSServerを内包
        self.tls = TLSServer(node, verbose=verbose)
        self.state = "READY"

    def on_connection_established(self, connection_key):
        if self.verbose:
            print("[HTTPSServer] TCP connection established. Accepting TLS handshake.")
        # TCP確立後に TLSハンドシェイクを実施
        self.tls.accept_tls_handshake(connection_key)
        self.state = "READY"

    def on_packet_received(self, packet):
        # TLSで復号
        decrypted = self.tls.receive_encrypted(packet)
        data = decrypted.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[HTTPSServer] Received (decrypted):", data.strip())

        # 簡単なHTTPパース例
        if data.startswith("GET"):
            # "GET /xxx HTTP/..." からファイル名を抜き出す
            parts = data.split(" ")
            if len(parts) < 2:
                self.send_http_response(packet, "HTTP/1.1 400 Bad Request\r\n\r\n")
                return

            filename = parts[1].lstrip("/").split()[0]
            file_data = self.shared_files.get(filename, None)

            if file_data is None:
                self.send_http_response(packet, "HTTP/1.1 404 Not Found\r\n\r\n")
                return

            # 200 OK + ファイル本体
            response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(file_data)}\r\n\r\n"
            response_bytes = response.encode('utf-8') + file_data

            if self.verbose:
                print(f"[HTTPSServer] Sending file {filename} ({len(file_data)} bytes) over TLS")

            # TLS暗号化して送信
            connection_key = (packet.header["source_ip"], packet.header["source_port"])
            self.tls.send_encrypted(connection_key, response_bytes)

    def send_http_response(self, packet, response_str):
        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        self.tls.send_encrypted(connection_key, response_str.encode('utf-8'))


