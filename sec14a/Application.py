class Application:
    def __init__(self, node):
        self.node = node
        # DNS解決待ちの辞書: { domain: callback }
        # callbackは解決後に呼ぶ関数(またはNone)
        self.waiting_for_dns = {}

    def resolve_destination_url(self, destination_url, callback=None):
        """
        DNS解決を試みる。既にurl_to_ip_mappingにあれば即座にIPを返し、
        なければDNSクエリを送り、応答待ち状態にする。

        :param destination_url: 解決したいURL
        :param callback: 解決後に呼ばれるコールバック関数（任意）
        :return: 解決済みの場合はIPアドレス、未解決ならNone
        """
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

class FTPClient(Application):
    def __init__(self, node, server_url=None):
        super().__init__(node)
        self.server_url = server_url
        self.state = "INITIAL"
        self.server_ip = None
        self.control_port = None
        self.file_to_retrieve = "testfile.txt"

    def connect(self, server_ip, server_port=21):
        """
        明示的にサーバIPとポートを指定してFTPコントロール接続を開始するメソッド。
        server_ipが直接指定できる場合はDNS解決を省略。
        """
        self.server_ip = server_ip
        self.initiate_ftp_control_connection(server_ip, server_port)

    def initiate_ftp_control_connection(self, server_ip, server_port=21):
        # FTPは21番ポートがデフォルト
        source_port = self.node.select_random_port()
        destination_port = server_port
        self.control_port = destination_port
        # 21/TCPでこのアプリを登録
        self.node.register_application(destination_port, "TCP", self)
        self.state = "CONNECTING"
        self.node.send_packet(server_ip, b"", protocol="TCP", dscp=0,
                              source_port=source_port, destination_port=destination_port, flags="SYN")

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        flags = packet.header.get("flags", "")

        if "SYN" in flags and "ACK" in flags and self.state == "CONNECTING":
            self.state = "ESTABLISHED"
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="ACK")
            return

        if "FIN" in flags:
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="ACK")
            self.state = "CLOSED"
            print("FTP Client: Connection closed.")
            return

        if data.startswith("220"):
            self.send_ftp_command("USER anonymous\r\n")
        elif data.startswith("331"):
            self.send_ftp_command("PASS anonymous@\r\n")
        elif data.startswith("230"):
            self.send_ftp_command(f"RETR {self.file_to_retrieve}\r\n")
        elif data.startswith("150"):
            # データ転送開始準備OK
            pass
        elif data.startswith("226"):
            # 転送完了、FIN送信
            self.node.send_packet(packet.header["source_ip"], b"", protocol="TCP", dscp=0,
                                  source_port=packet.header["destination_port"], destination_port=packet.header["source_port"],
                                  flags="FIN")

    def send_ftp_command(self, command):
        source_port = self.node.select_random_port()
        self.node.send_packet(self.server_ip, command.encode('utf-8'),
                              protocol="TCP", dscp=0, source_port=source_port,
                              destination_port=self.control_port, flags="PSH")
        print(f"FTP Client: Sent command: {command.strip()}")

class FTPServer(Application):
    def __init__(self, node, shared_files):
        super().__init__(node)
        self.shared_files = shared_files
        self.node.register_application(21, "TCP", self)
        self.state = "LISTEN"

    def on_packet_received(self, packet):
        data = packet.payload.decode('utf-8', errors='ignore')
        flags = packet.header.get("flags", "")
        src_ip = packet.header["source_ip"]
        src_port = packet.header["source_port"]
        dst_port = packet.header["destination_port"]

        if "SYN" in flags and self.state == "LISTEN":
            self.state = "SYN_RECEIVED"
            self.node.send_packet(src_ip, b"", protocol="TCP", dscp=0,
                                  source_port=dst_port, destination_port=src_port,
                                  flags="SYN,ACK")
            return

        if "ACK" in flags and self.state == "SYN_RECEIVED":
            self.state = "ESTABLISHED"
            self.send_ftp_response(src_ip, dst_port, src_port, "220 Service ready\r\n")
            return

        if "FIN" in flags and self.state == "ESTABLISHED":
            self.node.send_packet(src_ip, b"", protocol="TCP", dscp=0,
                                  source_port=dst_port, destination_port=src_port,
                                  flags="ACK")
            self.state = "CLOSED"
            print("FTP Server: Connection closed.")
            return

        if data.startswith("USER"):
            self.send_ftp_response(src_ip, dst_port, src_port, "331 User name okay, need password.\r\n")
        elif data.startswith("PASS"):
            self.send_ftp_response(src_ip, dst_port, src_port, "230 User logged in, proceed.\r\n")
        elif data.startswith("RETR"):
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
        self.node.send_packet(dst_ip, response.encode('utf-8'), protocol="TCP", dscp=0,
                              source_port=source_port, destination_port=src_port, flags="PSH")
        print(f"FTP Server: Sent response: {response.strip()}")

