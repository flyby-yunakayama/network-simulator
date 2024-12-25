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
        self.https_client = None
        self.https_server = None
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

    def register_https_client(self, https_client):
        self.https_client = https_client

    def register_https_server(self, https_server):
        self.https_server = https_server

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
        elif app_type == "HTTPSSERVER" and self.https_server:
            self.https_server.on_packet_received(packet)
        elif app_type == None and (self.ftp_server or self.http_server or self.https_server):  # マッピングがない場合はサーバとして扱う
            if packet.header.get("destination_port") == 443 and self.https_server:
                self.connection_app_map[(packet.header.get("source_ip"), packet.header.get("source_port"))] = "HTTPSSERVER"
                self.https_server.on_packet_received(packet)
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
        elif app_type == "HTTPSSERVER" and self.https_server:
            self.https_server.on_connection_established(connection_key)
        elif app_type == None:  # マッピングがない場合はサーバとして扱う
            if connection_key[1] == 443 and self.https_server:  # ポート443はHTTPSサーバ
                self.connection_app_map[connection_key] = "HTTPSSERVER"
                self.https_server.on_connection_established(connection_key)
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
    def __init__(self, node, verbose=False):
        self.node = node  # ネットワークノードを保存
        self.app_manager = node.application_layer  # アプリケーションレイヤーのマネージャを取得
        self.verbose = verbose  # 詳細表示のフラグを保存
        self.state = "NOT_CONNECTED"  # 初期状態を「未接続」に設定
        self.file_to_retrieve = None  # 取得するファイル名を初期化
        self.outgoing_data = {}  # 送信データを保存する辞書を初期化

    def connect(self, server_ip=None, server_url=None, server_port=21):
        """
        FTPサーバへの接続を開始します。server_ipが指定されていない場合はserver_urlを解決します。
        
        Parameters:
        - server_ip: FTPサーバのIPアドレス（オプション）。
        - server_port: FTPサーバのポート番号（デフォルトは21）。
        - server_url: 接続するFTPサーバのURL（オプション）。
        """
        # server_ipが指定されていれば、直接接続を試みる
        if server_ip:
            self._initiate_connection(server_ip, server_port)
        # server_urlが指定されていれば、DNS解決を行ってから接続を試みる
        elif server_url:
            self.server_url = server_url  # サーバURLを保存
            if self.verbose:
                print("[FTPClient] サーバURLからIPを解決しています:", server_url)
            
            def on_resolved(ip):
                if ip:
                    if self.verbose:
                        print("[FTPClient] 解決されたIP:", ip)
                    self._initiate_connection(ip, server_port)
                else:
                    if self.verbose:
                        print("[FTPClient] サーバURLの解決に失敗しました:", server_url)
            
            # ApplicationManagerを通じてサーバURLを解決
            resolved_ip = self.app_manager.resolve_destination_url(server_url, callback=on_resolved)
            if resolved_ip is not None:
                # すでに解決済みの場合は即座に接続を開始
                on_resolved(resolved_ip)
        else:
            if self.verbose:
                print("[FTPClient] 接続情報が不足しています。server_ipまたはserver_urlを指定してください。")

    def _initiate_connection(self, server_ip, server_port):
        """
        指定されたIPとポートに対して接続を開始します。
        
        Parameters:
        - server_ip: FTPサーバのIPアドレス。
        - server_port: FTPサーバのポート番号。
        """
        if self.verbose:
            print("[FTPClient] TCP接続を要求しています:", server_ip, server_port)
        self.server_ip = server_ip  # サーバのIPアドレスを保存
        self.server_port = server_port  # サーバのポート番号を保存
        self.state = "CONNECTING"  # 状態を「接続中」に変更
        self.node.initiate_tcp_handshake(server_ip, server_port)  # TCPハンドシェイクを開始
        self.app_manager.map_connection_to_app((server_ip, server_port), "FTP")  # 接続をFTPアプリケーションにマッピング

    def on_packet_received(self, packet):
        """
        パケットを受信したときに呼び出されるハンドラ。
        
        Parameters:
        - packet: 受信したパケットのオブジェクト。
        """
        data = packet.payload.decode('utf-8', errors='ignore')  # パケットのペイロードをデコード
        if self.verbose:
            print("[FTPClient] 受信データ:", data.strip())

        # FTPの基本的なやり取りの流れに基づいて処理を行う
        if data.startswith("220"):
            # サーバからの220応答（サービス準備完了）
            self.state = "LOGGED_OUT"  # 状態を「ログアウト済み」に変更
            self.send_ftp_command("USER anonymous\r\n")  # ユーザー名を送信
        elif data.startswith("331"):
            # サーバからの331応答（パスワードが必要）
            self.send_ftp_command("PASS anonymous@\r\n")  # パスワードを送信
        elif data.startswith("230"):
            # サーバからの230応答（ログイン成功）
            self.state = "LOGGED_IN"  # 状態を「ログイン済み」に変更
            if self.file_to_retrieve:
                # 取得したいファイルが指定されていればRETRコマンドを送信
                self.send_ftp_command(f"RETR {self.file_to_retrieve}\r\n")
        elif data.startswith("150"):
            # サーバからの150応答（ファイル転送開始）
            # ファイル転送の開始に伴う処理をここで追加可能
            pass
        elif data.startswith("226"):
            # サーバからの226応答（転送完了）
            # ファイル転送完了後の処理をここで追加可能
            pass

    def on_connection_established(self, connection_key):
        self.set_traffic_info(connection_key)
        if self.verbose:
            print("[FTPClient] Connection established. Waiting for server greeting (220)...")

    def send_ftp_command(self, command):
        """
        FTPコマンドをサーバに送信します。
        
        Parameters:
        - command: 送信するFTPコマンドの文字列。
        """
        if self.verbose:
            print("[FTPClient] 送信コマンド:", command.strip())
        # サーバIPとポートを指定してデータを送信
        self.node.send_app_data(
            self.server_ip,  # サーバのIPアドレス
            command.encode('utf-8'),  # コマンドをバイト列にエンコード
            protocol="TCP",  # プロトコルをTCPに指定
            destination_port=self.server_port  # 送信先ポートを指定
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
        """
        HTTPClientクラスのコンストラクタ。
        
        Parameters:
        - node: ネットワークノードのインスタンス。
        - server_url: 接続するHTTPサーバのURL（オプション）。
        - verbose: 詳細なログを表示するかどうかのフラグ。
        """
        self.node = node  # ネットワークノードを保存
        self.app_manager = node.application_layer  # アプリケーションレイヤーのマネージャを取得
        self.server_url = server_url  # サーバURLを保存
        self.verbose = verbose  # 詳細表示のフラグを保存
        self.state = "NOT_CONNECTED"  # 初期状態を「未接続」に設定
        self.file_to_retrieve = None  # 取得するファイル名を初期化
        self.response_data = {}  # 受信したレスポンスデータを保存する辞書を初期化
        
    def connect(self, server_ip=None, server_url=None, server_port=80):
        """
        HTTPサーバへの接続を開始します。server_ipが指定されていない場合はserver_urlを解決します。
        
        Parameters:
        - server_ip: HTTPサーバのIPアドレス（オプション）。
        - server_port: HTTPサーバのポート番号（デフォルトは80）。
        - server_url: 接続するHTTPサーバのURL（オプション）。
        """
        # server_ipが指定されていれば、直接接続を試みる
        if server_ip:
            self._initiate_connection(server_ip, server_port)
        # server_urlが指定されていれば、DNS解決を行ってから接続を試みる
        elif server_url:
            self.server_url = server_url  # サーバURLを保存
            if self.verbose:
                print("[HTTPClient] サーバURLからIPを解決しています:", server_url)
            
            def on_resolved(ip):
                if ip:
                    if self.verbose:
                        print("[HTTPClient] 解決されたIP:", ip)
                    self._initiate_connection(ip, server_port)
                else:
                    if self.verbose:
                        print("[HTTPClient] サーバURLの解決に失敗しました:", server_url)
            
            # ApplicationManagerを通じてサーバURLを解決
            resolved_ip = self.app_manager.resolve_destination_url(server_url, callback=on_resolved)
            if resolved_ip is not None:
                # すでに解決済みの場合は即座に接続を開始
                on_resolved(resolved_ip)
        else:
            if self.verbose:
                print("[HTTPClient] 接続情報が不足しています。server_ipまたはserver_urlを指定してください。")

    def _initiate_connection(self, server_ip, server_port):
        """
        指定されたIPとポートに対して接続を開始します。
        
        Parameters:
        - server_ip: HTTPサーバのIPアドレス。
        - server_port: HTTPサーバのポート番号。
        """
        if self.verbose:
            print("[HTTPClient] TCP接続を要求しています:", server_ip, server_port)
        self.server_ip = server_ip  # サーバのIPアドレスを保存
        self.server_port = server_port  # サーバのポート番号を保存
        self.state = "CONNECTING"  # 状態を「接続中」に変更
        self.node.initiate_tcp_handshake(server_ip, server_port)  # TCPハンドシェイクを開始
        self.app_manager.map_connection_to_app((server_ip, server_port), "HTTP")  # 接続をHTTPアプリケーションにマッピング
        
    def get_file(self, filename):
        """
        指定されたファイルを取得するリクエストを送信します。
        
        Parameters:
        - filename: 取得するファイルの名前。
        """
        self.file_to_retrieve = filename  # 取得するファイル名を保存
        if self.state == "CONNECTED":
            # 既に接続が確立されている場合は即座にGETリクエストを送信
            self.send_http_request(f"GET /{filename} HTTP/1.0\r\n\r\n")
        elif self.verbose:
            # 接続がまだ確立されていない場合は、接続後にファイルを取得することをログに記録
            print("[HTTPClient] 接続後にファイルを取得します:", filename)
            
    def send_http_request(self, request):
        """
        HTTPリクエストをサーバに送信します。
        
        Parameters:
        - request: 送信するHTTPリクエストの文字列。
        """
        if self.verbose:
            print("[HTTPClient] 送信リクエスト:", request.strip())
        # サーバIPとポートを指定してデータを送信
        self.node.send_app_data(
            self.server_ip,  # サーバのIPアドレス
            request.encode('utf-8'),  # リクエストをバイト列にエンコード
            protocol="TCP",  # プロトコルをTCPに指定
            destination_port=self.server_port  # 送信先ポートを指定
        )
        
    def on_connection_established(self, connection_key):
        """
        TCP接続が確立したときに呼び出されるハンドラ。
        
        Parameters:
        - connection_key: 接続を一意に識別するキー（クライアントIPとクライアントポートのタプル）。
        """
        self.state = "CONNECTED"  # 状態を「接続済み」に変更
        if self.verbose:
            print("[HTTPClient] 接続が確立しました。")
        if self.file_to_retrieve:
            # 取得するファイルが指定されていれば、ファイル取得リクエストを送信
            self.get_file(self.file_to_retrieve)
            
    def on_packet_received(self, packet):
        """
        パケットを受信したときに呼び出されるハンドラ。
        
        Parameters:
        - packet: 受信したパケットのオブジェクト。
        """
        data = packet.payload.decode('utf-8', errors='ignore')  # パケットのペイロードをデコード
        if self.verbose:
            print("[HTTPClient] 受信データ:", data.strip())
            
        # シンプルなHTTPレスポンスの解析
        if data.startswith("HTTP/1.0 200 OK"):
            # サーバからの200 OKレスポンスを受信した場合
            if self.verbose:
                print("[HTTPClient] ファイルの取得に成功しました")
            # ここでファイルデータを処理することも可能
        elif data.startswith("HTTP/1.0 404"):
            # サーバからの404 Not Foundレスポンスを受信した場合
            if self.verbose:
                print("[HTTPClient] ファイルが見つかりませんでした")
            # 追加のエラーハンドリングが可能

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
    学習用に単純化したTLSクライアント実装。実際のTLS手順とは異なるが、
    ハンドシェイクのフローを模擬し、暗号化(体)した送受信を行う。
    """

    def __init__(self, node, verbose=False):
        self.node = node
        self.verbose = verbose
        # connection_keyごとに状態を持つ: 
        #   e.g. "IDLE" → "WAIT_SERVER_HELLO" → "WAIT_SERVER_FINISHED" → "ESTABLISHED"
        self.handshake_state = {}
        # ハンドシェイクが完了すると、ここに共通鍵を保存するという想定
        self.shared_keys = {}

    def get_state(self, connection_key):
        return self.handshake_state.get(connection_key, "IDLE")

    def is_established(self, connection_key):
        """ハンドシェイク完了 (ESTABLISHED) かどうか。"""
        return (self.get_state(connection_key) == "ESTABLISHED")

    def start_handshake(self, connection_key):
        """
        TCPコネクションが確立した直後に呼ばれ、TLSのClientHelloを送る。
        """
        if self.verbose:
            print(f"[TLSClient] start_handshake: Sending ClientHello for {connection_key}")

        self.handshake_state[connection_key] = "WAIT_SERVER_HELLO"
        self.shared_keys[connection_key] = None

        # シンプルに文字列 "ClientHello" を送る
        self._send_tls_message(connection_key, b"ClientHello")

    def on_packet_received(self, packet):
        """
        Node -> ApplicationManager -> HTTPSClient -> TLSClient という流れで呼び出される想定。
        ハンドシェイク or 通常データを振り分ける。
        """
        data = packet.payload
        if not data:
            # **追加：空ペイロードはACK等とみなし無視する**
            if self.verbose:
                print("[TLSClient] Received empty payload (likely ACK). Ignoring.")
            return
        
        src_ip = packet.header["source_ip"]
        src_port = packet.header["source_port"]
        connection_key = (src_ip, src_port)

        state = self.get_state(connection_key)
        if state.startswith("WAIT"):
            self._handle_handshake_message(connection_key, data)
        else:
            # すでにESTABLISHEDなら暗号化データかもしれない
            if self.is_established(connection_key):
                # 復号して返したい場合はここで処理
                if self.verbose:
                    print(f"[TLSClient] Received encrypted data in established state: {data[:50]} ...")

    def _handle_handshake_message(self, connection_key, data):
        """
        ハンドシェイク中のメッセージを処理。
        """
        state = self.get_state(connection_key)

        if state == "WAIT_SERVER_HELLO":
            if data.startswith(b"ServerHello"):
                if self.verbose:
                    print(f"[TLSClient] Received ServerHello from {connection_key}")
                # 次はキー交換要求を送る（省略OK）
                self.handshake_state[connection_key] = "WAIT_SERVER_FINISHED"
                self._send_tls_message(connection_key, b"ClientKeyExchange")
            else:
                if self.verbose:
                    print(f"[TLSClient] Unexpected handshake message. Received: {data}")
                # 異常とみなしても良い

        elif state == "WAIT_SERVER_FINISHED":
            if data.startswith(b"ServerFinished"):
                # ハンドシェイク完了
                self.handshake_state[connection_key] = "ESTABLISHED"
                self.shared_keys[connection_key] = b"MySharedKey"  # ダミー
                if self.verbose:
                    print(f"[TLSClient] TLS Handshake finished for {connection_key}")
            else:
                if self.verbose:
                    print(f"[TLSClient] Unexpected handshake message. Received: {data}")

    def _send_tls_message(self, connection_key, msg: bytes):
        """
        TCP送信。実際には node.send_app_data() を呼ぶだけ。
        """
        dst_ip, dst_port = connection_key
        # 送信
        self.node.send_app_data(
            dst_ip,
            msg,
            protocol="TCP",
            destination_port=dst_port
        )

    def encrypt(self, connection_key, plaintext: bytes) -> bytes:
        """共通鍵で暗号化（体）。"""
        if not self.is_established(connection_key):
            # ハンドシェイク前なら生データを返す or エラー
            return plaintext

        # ダミー暗号化: ENC(...) で包むだけ
        return b"ENC(" + plaintext + b")"

    def decrypt(self, connection_key, ciphertext: bytes) -> bytes:
        """共通鍵で復号（体）。"""
        if not self.is_established(connection_key):
            return ciphertext  # エラーまたは無視

        # ダミー復号: ENC(...) を外すだけ
        if ciphertext.startswith(b"ENC(") and ciphertext.endswith(b")"):
            return ciphertext[4:-1]
        return ciphertext


class TLSServer:
    """
    学習用に単純化したTLSサーバ実装。ServerHello, ServerFinishedを返すことで、
    クライアントのハンドシェイクを模擬する。
    """

    def __init__(self, node, verbose=False):
        self.node = node
        self.verbose = verbose
        self.handshake_state = {}
        self.shared_keys = {}

    def get_state(self, connection_key):
        return self.handshake_state.get(connection_key, "IDLE")

    def is_established(self, connection_key):
        return (self.get_state(connection_key) == "ESTABLISHED")

    def accept_handshake(self, connection_key):
        """
        TCP接続確立直後に呼ばれる想定。
        サーバは ClientHello を待つ。
        """
        self.handshake_state[connection_key] = "WAIT_CLIENT_HELLO"
        self.shared_keys[connection_key] = None
        if self.verbose:
            print(f"[TLSServer] Ready to accept TLS handshake from {connection_key}")

    def on_packet_received(self, packet):
        """
        HTTPSサーバ(=HTTPServer継承)から呼ばれ、TLSハンドシェイク中のメッセージかどうかを判別する。
        """
        data = packet.payload
        if not data:
            # **追加：空ペイロードはACK等とみなし無視する**
            if self.verbose:
                print("[TLSServer] Received empty payload (likely ACK). Ignoring.")
            return

        src_ip = packet.header["source_ip"]
        src_port = packet.header["source_port"]
        connection_key = (src_ip, src_port)

        state = self.get_state(connection_key)
        if state.startswith("WAIT"):
            self._handle_handshake_message(connection_key, data)
        else:
            if self.is_established(connection_key):
                # 既に確立済なら暗号化データかもしれない
                if self.verbose:
                    print(f"[TLSServer] Received encrypted data in established state: {data[:50]} ...")

    def _handle_handshake_message(self, connection_key, data):
        state = self.get_state(connection_key)

        if state == "WAIT_CLIENT_HELLO":
            if data.startswith(b"ClientHello"):
                if self.verbose:
                    print(f"[TLSServer] Received ClientHello from {connection_key}")
                self.handshake_state[connection_key] = "WAIT_CLIENT_KEYEXCHANGE"
                self._send_tls_message(connection_key, b"ServerHello")
            else:
                if self.verbose:
                    print(f"[TLSServer] Unexpected handshake message. Received: {data}")

        elif state == "WAIT_CLIENT_KEYEXCHANGE":
            if data.startswith(b"ClientKeyExchange"):
                if self.verbose:
                    print(f"[TLSServer] Received ClientKeyExchange from {connection_key}")
                self.handshake_state[connection_key] = "ESTABLISHED"
                self.shared_keys[connection_key] = b"MySharedKey"
                # ServerFinished を返して完了
                self._send_tls_message(connection_key, b"ServerFinished")
                if self.verbose:
                    print(f"[TLSServer] TLS Handshake finished for {connection_key}")
            else:
                if self.verbose:
                    print(f"[TLSServer] Unexpected handshake message. Received: {data}")

    def _send_tls_message(self, connection_key, msg: bytes):
        """
        TCP送信 (node.send_app_data) を行う。
        """
        dst_ip, dst_port = connection_key
        self.node.send_app_data(
            dst_ip,
            msg,
            protocol="TCP",
            destination_port=dst_port
        )

    def encrypt(self, connection_key, plaintext: bytes) -> bytes:
        if not self.is_established(connection_key):
            return plaintext
        return b"ENC(" + plaintext + b")"

    def decrypt(self, connection_key, ciphertext: bytes) -> bytes:
        if not self.is_established(connection_key):
            return ciphertext
        if ciphertext.startswith(b"ENC(") and ciphertext.endswith(b")"):
            return ciphertext[4:-1]
        return ciphertext


class HTTPSClient(HTTPClient):
    """
    HTTPClientを継承し、TLSClientを内包してHTTPSの流れを実装。
    - connect() でTCP接続した後、TLSハンドシェイクを実施。
    - ハンドシェイク完了後にHTTPリクエストを暗号化して送受信する。
    """

    def __init__(self, node, server_url=None, verbose=False):
        super().__init__(node, server_url=server_url, verbose=verbose)
        self.tls_client = TLSClient(node, verbose=verbose)  # 内部でTLSClientを生成
        self._https_connection_key = None  # TCP接続のキー (ip, port)

    def _initiate_connection(self, server_ip, server_port):
        """
        親クラスのHTTPClient._initiate_connectionをオーバーライド。
        接続を "HTTPS" としてapp_managerに登録するように変更。
        """
        if self.verbose:
            print("[HTTPSClient] TCP接続を要求しています(HTTPS):", server_ip, server_port)
        self.server_ip = server_ip
        self.server_port = server_port
        self.state = "CONNECTING"
        self.node.initiate_tcp_handshake(server_ip, server_port)
        # ここで "HTTPS" としてマッピング
        self.app_manager.map_connection_to_app((server_ip, server_port), "HTTPS")

    def on_connection_established(self, connection_key):
        """
        TCP接続確立時に呼ばれる。
        ここでTLSハンドシェイクを開始し、完了後にHTTPリクエストを送る。
        """
        self.state = "CONNECTED"
        self._https_connection_key = connection_key
        if self.verbose:
            print("[HTTPSClient] TCP接続が確立しました。TLSハンドシェイクを開始します。")

        # TLSハンドシェイク開始
        self.tls_client.start_handshake(connection_key)

        # もしファイル取得要求があれば、ハンドシェイク完了後に送信する。
        # → handle_tls_packet などで handshake が完了したタイミングで send_http_request() を呼ぶ
        # ただしサンプルでは省略し、手動でon_packet_receivedの中などでチェックする

    def on_packet_received(self, packet):
        # TLSClientにまず処理してもらう
        self.tls_client.on_packet_received(packet)

        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        # TLSハンドシェイク完了を検知
        if self.tls_client.is_established(connection_key):
            # もしまだHTTPリクエストを送っていなければ、ここで自動送信する例
            if self.file_to_retrieve and self.state == "CONNECTED":
                # send_https_request で暗号化して送る
                request = f"GET /{self.file_to_retrieve} HTTP/1.0\r\n\r\n"
                self.send_https_request(request)
                # 状態を "REQUEST_SENT" とかにしてもOK

            # 受け取ったpayloadを復号
            decrypted = self.tls_client.decrypt(connection_key, packet.payload)
            if decrypted.startswith(b"HTTP/1.0 200 OK"):
                if self.verbose:
                    print("[HTTPSClient] (TLS) ファイルの取得に成功しました:", decrypted.decode('utf-8', errors='ignore'))
            elif decrypted.startswith(b"HTTP/1.0 404"):
                if self.verbose:
                    print("[HTTPSClient] (TLS) ファイルが見つかりません:", decrypted.decode('utf-8', errors='ignore'))
            # 他のHTTPレスポンス解析も必要なら追加

    def send_https_request(self, request: str):
        """
        ハンドシェイク完了後に送るHTTPリクエストを暗号化してTCP送信。
        """
        if self._https_connection_key is None:
            if self.verbose:
                print("[HTTPSClient] Error: No TCP connection yet.")
            return
        if not self.tls_client.is_established(self._https_connection_key):
            if self.verbose:
                print("[HTTPSClient] Error: TLS handshake not finished yet.")
            return

        # 暗号化
        enc_data = self.tls_client.encrypt(self._https_connection_key, request.encode('utf-8'))
        dst_ip, dst_port = self._https_connection_key
        self.node.send_app_data(dst_ip, enc_data, protocol="TCP", destination_port=dst_port)

    def get_file(self, filename):
        self.file_to_retrieve = filename
        # 親クラス(HTTPClient)の仕組み: connect() → on_connection_established() → ...
        if self.state == "CONNECTED" and self._https_connection_key:
            # すでにTLS完了ならすぐ送信
            if self.tls_client.is_established(self._https_connection_key):
                req = f"GET /{filename} HTTP/1.0\r\n\r\n"
                self.send_https_request(req)
            else:
                if self.verbose:
                    print("[HTTPSClient] TLS未完了のため、get_fileは保留します。")
        else:
            if self.verbose:
                print("[HTTPSClient] TCP接続がまだなので、接続後に自動送信を試みます。")


class HTTPSServer(HTTPServer):
    """
    HTTPServerを継承し、TLSサーバ (TLSServer) を内包してHTTPSの流れを実装。
    - TCP接続確立イベントで accept_handshake() を呼び、
    - ハンドシェイク完了後に暗号化されたHTTPリクエストを処理し、暗号化レスポンスを返す。
    """

    def __init__(self, node, shared_files, verbose=False):
        super().__init__(node, shared_files, verbose=verbose)
        self.tls_server = TLSServer(node, verbose=verbose)

    def on_connection_established(self, connection_key):
        """
        親クラス(HTTPServer)のon_connection_establishedをオーバーライド。
        TCP接続時に TLSハンドシェイクを受け付ける。
        """
        if self.verbose:
            print("[HTTPSServer] TCP接続を受け付けました。TLSハンドシェイクを開始します。")
        # 親の処理(一応実行。状態を "READY" にセットするなど)
        super().on_connection_established(connection_key)

        # TLSサーバ側の accept_handshake 呼び出し
        self.tls_server.accept_handshake(connection_key)

    def on_packet_received(self, packet):
        # まずはTLSサーバ側に渡してハンドシェイク or 復号
        self.tls_server.on_packet_received(packet)

        connection_key = (packet.header["source_ip"], packet.header["source_port"])
        if not self.tls_server.is_established(connection_key):
            # ハンドシェイク未完了なら何もしない
            if self.verbose:
                print("[HTTPSServer] TLS handshake in progress, state:", self.tls_server.get_state(connection_key))
            return

        # ハンドシェイク完了 → HTTPS本体
        decrypted = self.tls_server.decrypt(connection_key, packet.payload)
        if self.verbose and decrypted:
            print(f"[HTTPSServer] (TLS) Decrypted HTTP request: {decrypted[:60]} ...")

        # 従来のHTTPServerと同じように、擬似パケットを作ってsuper()に渡す
        fake_packet = self._create_fake_http_packet(packet, decrypted)
        super().on_packet_received(fake_packet)

    def _create_fake_http_packet(self, original_packet, new_payload):
        """
        復号結果をpayloadとする、新しいパケットオブジェクトを作成して返す。
        """
        from copy import deepcopy
        new_packet = deepcopy(original_packet)
        new_packet.payload = new_payload
        return new_packet

    def send_http_response(self, client_ip, client_port, server_port, response):
        """
        親クラスの send_http_response をオーバーライドし、暗号化して送信する。
        """
        connection_key = (client_ip, client_port)
        if not self.tls_server.is_established(connection_key):
            # 未確立なら素のHTTPで送る or エラー
            super().send_http_response(client_ip, client_port, server_port, response)
            return

        # TLS暗号化
        enc_data = self.tls_server.encrypt(connection_key, response.encode('utf-8'))
        self.node.send_app_data(
            client_ip,
            enc_data,
            protocol="TCP",
            source_port=server_port,
            destination_port=client_port
        )
        if self.verbose:
            print("[HTTPSServer] (TLS) Sending encrypted response:", response.strip())


