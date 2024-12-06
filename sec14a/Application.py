from sec14a.Packet import DNSPacket, DHCPPacket

class Application:
    def __init__(self, node):
        self.node = node
        self.node.set_application_layer(self)
        # DNS, DHCPクライアントインスタンスを作成
        self.dns_client = DnsClient(node)
        self.dhcp_client = DhcpClient(node)

    def on_dns_packet_received(self, packet):
        self.dns_client.on_dns_packet_received(packet)

    def on_dhcp_packet_received(self, packet):
        self.dhcp_client.on_dhcp_packet_received(packet)

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
        self.node.send_packet(
            self.node.dns_server_ip,
            dns_query_packet.to_bytes(),
            protocol="UDP",
            dscp=0,
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
        self.start_dhcp()

    def start_dhcp(self):
        # DHCP Discover
        dhcp_discover_packet = DHCPPacket(
            source_mac=self.node.mac_address,
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_ip="0.0.0.0/32",
            destination_ip="255.255.255.255/32",
            message_type="DISCOVER",
            network_event_scheduler=self.node.network_event_scheduler
        )
        self.node.send_packet(
            "255.255.255.255",
            dhcp_discover_packet.to_bytes(),
            protocol="UDP",
            dscp=0,
            source_port=68,
            destination_port=67
        )
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

        self.node.send_packet(
            "255.255.255.255",
            dhcp_request_packet.to_bytes(),
            protocol="UDP",
            dscp=0,
            source_port=68,
            destination_port=67
        )


class UDPApp(Application):
    def __init__(self, node):
        super().__init__(node)
        self.bitrate = None
        self.header_size = None
        self.payload_size = None
        self.burstiness = None
        self.protocol = "UDP"
        self.dscp = 0
        self.destination_ip = None
        self.destination_port = None
        self.source_port = None
        self.end_time = None

    def start_traffic(self, destination_url, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0, protocol="UDP", dscp=0):
        """
        UDPトラフィックを開始します。
        :param destination_url: 宛先URLまたはIP
        :param bitrate: ビットレート（bps）
        :param start_time: トラフィック開始時間
        :param duration: 持続時間（秒）
        :param header_size: ヘッダーサイズ
        :param payload_size: ペイロードサイズ
        :param burstiness: バースト係数
        :param protocol: "UDP"を想定
        :param dscp: DSCP値
        """
        self.bitrate = bitrate
        self.header_size = header_size
        self.payload_size = payload_size
        self.burstiness = burstiness
        self.protocol = protocol
        self.dscp = dscp
        self.end_time = self.node.network_event_scheduler.current_time + duration

        # ポート番号を決定
        self.source_port = self.node.select_random_port()
        self.destination_port = self.node.select_random_port()

        # URLがIP形式かチェックし、IPでなければDNS解決する
        resolved_ip = self.node.resolve_destination_ip(destination_url)
        if resolved_ip is not None:
            # すでに解決済みの場合、すぐにスケジュール開始
            self.destination_ip = resolved_ip
            self.node.network_event_scheduler.schedule_event(start_time, self.schedule_traffic)
        else:
            # DNS解決が必要
            # DNS解決後のコールバックでスケジュール開始
            def on_resolved(ip):
                self.destination_ip = ip
                # DNS解決完了後にstart_timeで送信開始
                current_time = self.node.network_event_scheduler.current_time
                delay = max(0, start_time - current_time)
                self.node.network_event_scheduler.schedule_event(current_time + delay, self.schedule_traffic)

            self.resolve_destination_url(destination_url, callback=on_resolved)

    def schedule_traffic(self):
        """
        トラフィック送信を開始するメソッド。
        最初のパケット送出を現在時刻で行い、その後一定間隔でsend_packet_eventを呼ぶ。
        """
        # すぐに最初のパケット送信
        self.send_packet_event()

    def send_packet_event(self):
        """
        1パケット送信後、次のパケット送信をスケジュール。
        end_timeを超えていたら送信終了。
        """
        current_time = self.node.network_event_scheduler.current_time
        if current_time > self.end_time:
            # 終了
            return

        # データ生成
        data = b'X' * self.payload_size
        # パケット送信
        self.node.send_packet(self.destination_ip, data, self.protocol, self.dscp,
                              source_port=self.source_port, destination_port=self.destination_port)

        # 次のパケット送信までのインターバル計算
        packet_size = self.header_size + self.payload_size  # トータルサイズ（簡易想定）
        interval = (packet_size * 8) / self.bitrate * self.burstiness
        next_time = current_time + interval
        self.node.network_event_scheduler.schedule_event(next_time, self.send_packet_event)

    def on_packet_received(self, packet):
        """
        UDP受信時の処理が必要ならここで実装可能。
        今回は送信アプリケーションなので特に処理しない想定。
        """
        pass

class FTPClient(Application):
    def __init__(self, node, server_url=None, verbose=False):
        super().__init__(node)
        self.server_url = server_url
        self.verbose = verbose
        self.state = "NOT_CONNECTED"
        self.file_to_retrieve = None

    def connect(self, server_ip, server_port=21):
        # NodeレベルでTCP接続を要求し、接続確立後にon_packet_receivedが呼ばれる
        if self.verbose:
            print("[FTPClient] Requesting TCP connect to ", server_ip, server_port)
        # TCPハンドシェイクはNode内で行われるため、ここでは単に Node に "connect" 的な処理を依頼する
        # Nodeが接続完了後に最初のパケット（220）が届くはず
        self.state = "CONNECTING"
        self.node.initiate_tcp_connection(server_ip, server_port)  # 仮のメソッド（実装要）

    def on_packet_received(self, packet):
        # この時点でTCP接続は確立済み（Node側で完了）
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[FTPClient] Received: ", data.strip())
        # 接続確立後、最初のレスポンスは220想定
        if data.startswith("220"):
            self.state = "LOGGED_OUT"
            # USERコマンド送信
            self.send_ftp_command("USER anonymous\r\n")
        elif data.startswith("331"):
            # PASSコマンド送信
            self.send_ftp_command("PASS anonymous@\r\n")
        elif data.startswith("230"):
            # ログイン成功
            self.state = "LOGGED_IN"
            if self.file_to_retrieve:
                self.send_ftp_command(f"RETR {self.file_to_retrieve}\r\n")
        elif data.startswith("150"):
            # ファイル転送開始
            pass
        elif data.startswith("226"):
            # 転送完了
            # FINやACKはNode内部で処理し、ここでは不要
            # 必要ならNodeに"close connection"的なメソッドを呼んで接続終了させる
            pass

    def send_ftp_command(self, command):
        if self.verbose:
            print("[FTPClient] Sending command:", command.strip())
        self.node.send_app_data(self.server_url, command.encode('utf-8'), protocol="TCP")  # 仮のメソッド

    def retrieve_file(self, filename):
        self.file_to_retrieve = filename
        if self.verbose:
            print("[FTPClient] Will retrieve file after login:", filename)

class FTPServer(Application):
    def __init__(self, node, shared_files, verbose=False):
        super().__init__(node)
        self.shared_files = shared_files
        self.verbose = verbose
        self.state = "READY"  # TCP接続はNodeで確立されると想定

    def on_packet_received(self, packet):
        # この時点でTCP接続は確立済み
        data = packet.payload.decode('utf-8', errors='ignore')
        if self.verbose:
            print("[FTPServer] Received: ", data.strip())

        # 最初のパケットを受け取ったら220を返す
        if self.state == "READY":
            self.send_ftp_response(packet.header["source_ip"], packet.header["destination_port"], packet.header["source_port"], "220 Service ready\r\n")
            self.state = "WAIT_USER"
            return

        if data.startswith("USER"):
            self.send_ftp_response(packet.header["source_ip"], packet.header["destination_port"], packet.header["source_port"], "331 User name okay, need password.\r\n")
        elif data.startswith("PASS"):
            self.send_ftp_response(packet.header["source_ip"], packet.header["destination_port"], packet.header["source_port"], "230 User logged in, proceed.\r\n")
        elif data.startswith("RETR"):
            filename = data.strip().split(" ")[1]
            file_data = self.shared_files.get(filename, b"Test file data.")
            self.send_ftp_response(packet.header["source_ip"], packet.header["destination_port"], packet.header["source_port"], "150 File status okay; about to open data connection.\r\n")
            self.node.send_app_data(packet.header["source_ip"], file_data, protocol="TCP")  # 仮メソッド
            self.send_ftp_response(packet.header["source_ip"], packet.header["destination_port"], packet.header["source_port"], "226 Closing data connection.\r\n")

    def send_ftp_response(self, dst_ip, dst_port, src_port, response):
        if self.verbose:
            print("[FTPServer] Sending response:", response.strip())
        self.node.send_app_data(dst_ip, response.encode('utf-8'), protocol="TCP")  # 仮メソッド
