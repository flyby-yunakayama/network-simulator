import random

from sec14a.Packet import DNSPacket, DHCPPacket, TCPPacket, UDPPacket

class ApplicationManager:
    def __init__(self, node):
        self.node = node

        # DNS, DHCPクライアントを内部で生成
        self.dns_client = DnsClient(node)
        self.dhcp_client = DhcpClient(node)

        # 管理するアプリケーションインスタンス
        self.ftp_client = None
        self.ftp_server = None
        self.udp_app = None

        # connection_keyやプロトコルに応じてアプリを特定するマップ
        self.connection_app_map = {}

    def register_ftp_client(self, ftp_client):
        self.ftp_client = ftp_client

    def register_ftp_server(self, ftp_server):
        self.ftp_server = ftp_server

    def register_udp_app(self, udp_app):
        self.udp_app = udp_app

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
        elif app_type == None and self.ftp_server:  # マッピングがない場合はFTPSERVERとして扱う
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
        elif app_type == None and self.ftp_server:  # マッピングがない場合はFTPSERVERとして扱う
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
        # すでに解決済みかチェック
        if domain in self.url_to_ip_mapping:
            if callback:
                callback(self.url_to_ip_mapping[domain])
            return
        if not self.node.dns_server_ip:
            print("No DNS server IP set. Cannot resolve domain.")
            return

        # DNSクエリパケット作成
        dns_query_packet = DNSPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip=self.node.ip_address,
            destination_ip=self.node.dns_server_ip,
            query_domain=domain,
            query_type="A",
            network_event_scheduler=self.node.network_event_scheduler
        )
        # UDPでDNSサーバへクエリ送信
        self.node.send_app_data(
            self.node.dns_server_ip,
            dns_query_packet.to_bytes(),
            protocol="UDP",
            source_port=53,
            destination_port=53
        )
        self.pending_queries[domain] = callback

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
        # DHCP Discover
        dhcp_discover_packet = DHCPPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip="0.0.0.0/32",
            destination_ip="255.255.255.255/32",
            message_type="DISCOVER",
            network_event_scheduler=self.node.network_event_scheduler
        )
        self.node.send_app_data(
            "255.255.255.255",
            dhcp_discover_packet.to_bytes(),
            protocol="UDP",
            source_port=68,
            destination_port=67
        )
        self.node.network_event_scheduler.log_packet_info(dhcp_discover_packet, "DHCP Discover sent", self.node_id)
        self.state = "DISCOVER_SENT"

    def on_dhcp_packet_received(self, packet):
        if packet.message_type == "OFFER" and self.state == "DISCOVER_SENT":
            offered_ip = packet.dhcp_data.get("offered_ip")
            if offered_ip:
                self.send_dhcp_request(offered_ip)
                self.state = "REQUEST_SENT"

        elif packet.message_type == "ACK" and self.state == "REQUEST_SENT":
            assigned_ip = packet.dhcp_data.get("assigned_ip")
            dns_server_ip = packet.dhcp_data.get("dns_server_ip")
            if assigned_ip:
                self.node.set_ip_address(assigned_ip)
                print(f"Assigned IP: {assigned_ip}")
            if dns_server_ip:
                self.node.set_dns_server_ip(dns_server_ip)
                print(f"Assigned DNS server: {dns_server_ip}")
            self.state = "BOUND"

    def send_dhcp_request(self, requested_ip):
        dhcp_request_packet = DHCPPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip="0.0.0.0/32",
            destination_ip="255.255.255.255/32",
            message_type="REQUEST",
            network_event_scheduler=self.node.network_event_scheduler
        )
        dhcp_request_packet.dhcp_data = {"requested_ip": requested_ip}

        self.node.send_app_data(
            "255.255.255.255",
            dhcp_request_packet.to_bytes(),
            protocol="UDP",
            source_port=68,
            destination_port=67
        )
        self.node.network_event_scheduler.log_packet_info(
            dhcp_request_packet, 
            "DHCP Request sent", 
            self.node.node_id
        )

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
        chunk = self.get_data_chunk(connection_key, self.traffic_info[connection_key]['payload_size'])
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
        ti['bytes_transferred'] += bytes_sent
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
            flags="PSH"
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
