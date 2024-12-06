class Application:
    def __init__(self, node):
        self.node = node
        # DNS解決待ちの辞書: { domain: callback }
        # callbackは解決後に呼ぶ関数(またはNone)
        self.waiting_for_dns = {}

    def resolve_destination_url(self, destination_url, callback=None):
        """
        DNS解決を試みる。既にurl_to_ip_mappingにあれば即座にIPを返す。
        CIDR付きIPアドレスならDNS不要なので直接それを返す。
        そうでなければDNSクエリを送り、応答待ち状態にする。
        """
        # CIDR付きIPかどうかの判定
        if self.node.is_valid_cidr_notation(destination_url):
            # CIDR付きIPが直接指定された場合はDNS不要
            # url_to_ip_mappingやDNSクエリは行わず、そのまま返す。
            if callback:
                callback(destination_url)
            return destination_url

        # CIDR付きでなく、url_to_ip_mappingにも未登録ならDNSクエリ
        if destination_url in self.node.url_to_ip_mapping:
            # すでに解決済み
            resolved_ip = self.node.url_to_ip_mapping[destination_url]
            if callback:
                callback(resolved_ip)
            return resolved_ip
        else:
            # 未解決なのでDNSクエリを送信し、待機状態に
            self.waiting_for_dns[destination_url] = callback
            self.node.send_dns_query(destination_url)
            return None

    def check_dns_resolution(self):
        """
        DNS応答がすでにNodeのurl_to_ip_mappingに反映されていないか定期的にチェックする。
        解決済みのドメインが見つかれば対応するコールバックを呼び出す。

        本メソッドは、アプリケーション層のイベントループ等から定期的に呼び出せる。
        """
        resolved_domains = []
        for domain, cb in self.waiting_for_dns.items():
            if domain in self.node.url_to_ip_mapping:
                # 解決済み
                resolved_ip = self.node.url_to_ip_mapping[domain]
                if cb:
                    cb(resolved_ip)
                resolved_domains.append(domain)

        # 解決済みドメインを待機リストから削除
        for domain in resolved_domains:
            del self.waiting_for_dns[domain]

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
        self.state = "INITIAL"
        self.server_ip = None
        self.control_port = None
        self.file_to_retrieve = None
        self.verbose = verbose

    def connect(self, server_ip, server_port=21):
        if self.verbose:
            print(f"[FTPClient] Connecting to {server_ip}:{server_port}")
        self.server_ip = server_ip
        self.initiate_ftp_control_connection(server_ip, server_port)

    def initiate_ftp_control_connection(self, server_ip, server_port=21):
        if self.verbose:
            print(f"[FTPClient] Initiating control connection to {server_ip}:{server_port}")
        source_port = self.node.select_random_port()
        destination_port = server_port
        self.control_port = destination_port
        self.node.register_application(destination_port, "TCP", self)
        self.state = "CONNECTING"
        self.node.send_packet(server_ip, b"", protocol="TCP", dscp=0,
                              source_port=source_port, destination_port=destination_port, flags="SYN")

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        flags = packet.header.get("flags", "")
        if self.verbose:
            print(f"[FTPClient] Packet received: flags={flags}, data={data.strip()}")

        # TCPハンドシェイク処理
        if "SYN" in flags and "ACK" in flags and self.state == "CONNECTING":
            self.state = "ESTABLISHED"
            if self.verbose:
                print("[FTPClient] Connection established, sending ACK")
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="ACK")
            return

        if "FIN" in flags:
            if self.verbose:
                print("[FTPClient] FIN received, closing connection")
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="ACK")
            self.state = "CLOSED"
            return

        # FTPプロトコルメッセージ処理
        if data.startswith("220"):
            if self.verbose:
                print("[FTPClient] Server ready (220), sending USER")
            self.send_ftp_command("USER anonymous\r\n")
        elif data.startswith("331"):
            if self.verbose:
                print("[FTPClient] 331 received, sending PASS")
            self.send_ftp_command("PASS anonymous@\r\n")
        elif data.startswith("230"):
            if self.verbose:
                print("[FTPClient] 230 received, logged in. Sending RETR if file specified")
            if self.file_to_retrieve:
                self.send_ftp_command(f"RETR {self.file_to_retrieve}\r\n")
        elif data.startswith("150"):
            if self.verbose:
                print("[FTPClient] 150 received, file transfer starting")
            # ファイルデータがサーバから送られるはず
        elif data.startswith("226"):
            if self.verbose:
                print("[FTPClient] 226 received, transfer complete. Sending FIN to close.")
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="FIN")

    def send_ftp_command(self, command):
        source_port = self.node.select_random_port()
        if self.verbose:
            print(f"[FTPClient] Sending command: {command.strip()}")
        self.node.send_packet(self.server_ip, command.encode('utf-8'),
                              protocol="TCP", dscp=0, source_port=source_port,
                              destination_port=self.control_port, flags="PSH")

    def retrieve_file(self, filename):
        self.file_to_retrieve = filename
        if self.verbose:
            print(f"[FTPClient] retrieve_file called with filename={filename}")


class FTPServer(Application):
    def __init__(self, node, shared_files, verbose=False):
        super().__init__(node)
        self.shared_files = shared_files
        self.node.register_application(21, "TCP", self)
        self.state = "LISTEN"
        self.verbose = verbose

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        flags = packet.header.get("flags", "")
        src_ip = packet.header["source_ip"]
        src_port = packet.header["source_port"]
        dst_port = packet.header["destination_port"]

        if self.verbose:
            print(f"[FTPServer] Packet received: flags={flags}, data={data.strip()}")

        # TCPハンドシェイク処理
        if "SYN" in flags and self.state == "LISTEN":
            self.state = "SYN_RECEIVED"
            if self.verbose:
                print("[FTPServer] SYN received, sending SYN,ACK")
            self.node.send_packet(src_ip, b"", protocol="TCP", dscp=0,
                                  source_port=dst_port, destination_port=src_port,
                                  flags="SYN,ACK")
            return

        if "ACK" in flags and self.state == "SYN_RECEIVED":
            self.state = "ESTABLISHED"
            if self.verbose:
                print("[FTPServer] Connection established, sending 220")
            self.send_ftp_response(src_ip, dst_port, src_port, "220 Service ready\r\n")
            return

        if "FIN" in flags and self.state == "ESTABLISHED":
            if self.verbose:
                print("[FTPServer] FIN received, closing connection")
            self.node.send_packet(src_ip, b"", protocol="TCP", dscp=0,
                                  source_port=dst_port, destination_port=src_port,
                                  flags="ACK")
            self.state = "CLOSED"
            return

        # FTPプロトコルメッセージ処理
        if data.startswith("USER"):
            if self.verbose:
                print("[FTPServer] USER received, sending 331")
            self.send_ftp_response(src_ip, dst_port, src_port, "331 User name okay, need password.\r\n")
        elif data.startswith("PASS"):
            if self.verbose:
                print("[FTPServer] PASS received, sending 230")
            self.send_ftp_response(src_ip, dst_port, src_port, "230 User logged in, proceed.\r\n")
        elif data.startswith("RETR"):
            if self.verbose:
                print("[FTPServer] RETR received, sending file data (150 then file then 226)")
            self.send_ftp_response(src_ip, dst_port, src_port, "150 File status okay; about to open data connection.\r\n")
            self.node.register_application(20, "TCP", self)
            filename = data.strip().split(" ")[1]
            file_data = self.shared_files.get(filename, b"Test file data.")
            source_port = self.node.select_random_port()
            self.node.send_packet(src_ip, file_data, protocol="TCP", dscp=0,
                                  source_port=20, destination_port=src_port, flags="PSH")
            self.send_ftp_response(src_ip, dst_port, src_port, "226 Closing data connection.\r\n")

    def send_ftp_response(self, dst_ip, dst_port, src_port, response):
        source_port = self.node.select_random_port()
        if self.verbose:
            print(f"[FTPServer] Sending response: {response.strip()}")
        self.node.send_packet(dst_ip, response.encode('utf-8'), protocol="TCP", dscp=0,
                              source_port=source_port, destination_port=src_port, flags="PSH")
