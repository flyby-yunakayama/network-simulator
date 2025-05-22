from sec14a.NetworkEventScheduler import NetworkEventScheduler
from sec14a.Node import Node
from sec14a.Switch import Switch
from sec14a.Router import Router
from sec14a.Server import DNSServer, DHCPServer
from sec14a.Link import Link
from sec14a.Application import DnsClient, DhcpClient, UDPApp, FTPClient, FTPServer

nes = NetworkEventScheduler(seed=7, log_enabled=True, verbose=False, tcp_verbose=True, link_verbose=False)

# ノードとルータの設定
node1 = Node(node_id="n1", ip_address="192.168.1.0/24", network_event_scheduler=nes)  # DHCP利用
node2 = Node(node_id="n2", ip_address="192.168.2.1/24", network_event_scheduler=nes)  # IPアドレスを静的に設定
switch1 = Switch(node_id="s1", ip_address="192.168.1.240/24", network_event_scheduler=nes)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "192.168.2.254/24"], network_event_scheduler=nes)
dns1 = DNSServer(node_id="dns1", ip_address="192.168.1.200/24", network_event_scheduler=nes)
dhcp1 = DHCPServer(node_id="dhcp1", ip_address="192.168.1.250/24", dns_server_ip="192.168.1.200/24", start_cidr="192.168.1.0/24", network_event_scheduler=nes)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=1000000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link2 = Link(switch1, router1, bandwidth=1000000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link3 = Link(dns1, switch1, bandwidth=1000000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link4 = Link(dhcp1, switch1, bandwidth=1000000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link5 = Link(node2, router1, bandwidth=1000000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)

# ネットワークのトポロジを描画
nes.draw()

# DNSサーバに対してDNSレコード設定
dns1.add_dns_record("www.example.com", "192.168.2.1/24")

# DHCPサーバに対して使用済みIPアドレス登録
used_ips = ["192.168.1.240/24", "192.168.1.254/24", "192.168.1.200/24", "192.168.1.250/24"]
dhcp1.mark_ips_as_used(used_ips)

# FTPトラフィック設定
ftp_server = FTPServer(node2, shared_files={}, verbose=True)  # FTPサーバインスタンス
node2.register_application(21, "TCP", ftp_server)  # 21/TCPポートでFTPサーバを起動（待ち受け）
ftp_client = FTPClient(node1, verbose=False)  # FTPクライアントインスタンス
node1.register_application(0, "TCP", ftp_client)  # FTPクライアントをApplicationManagerに登録

# ファイル読み込み（サーバ側ファイル想定）
file_path = 'data/cat.jpg'
with open(file_path, 'rb') as f:
    file_data = f.read()
ftp_server.shared_files["cat.jpg"] = file_data  # サーバにファイル登録

# クライアント側でFTP転送を開始する処理
def start_ftp_transfer():
    ftp_client.connect(server_url="www.example.com", server_port=21)
    ftp_client.retrieve_file("cat.jpg")
nes.schedule_event(1.0, start_ftp_transfer)

# UDP送信アプリケーションのインスタンス作成
#udp_app = UDPApp(node1)
#def start_udp_traffic():
#    udp_app.start_traffic(destination_url="www.example.com", bitrate=100000, start_time=2.0, duration=5.0, header_size=28, payload_size=1000, burstiness=1.0, dscp=16)
#nes.schedule_event(2.0, start_udp_traffic)

# イベントスケジューラを実行
nes.run_until(10.0)

# フォワーディングテーブルやルーティングテーブルを確認
node1.print_arp_table()
node1.print_url_to_ip_mapping()
node1.print_tcp_connections()
router1.print_arp_table()
router1.print_routing_table()
node2.print_arp_table()
node2.print_tcp_connections()

# 結果を確認
nes.generate_summary(nes.packet_logs)
nes.generate_throughput_graph(nes.packet_logs)
nes.generate_delay_histogram(nes.packet_logs)

# 転送進行状況のプロット
nes.plot_cwnd_log()
ftp_connections = [ck for ck, info in node2.tcp_connections.items() if info.get('transfer_info') and info['transfer_info'].get('progress')]
if ftp_connections:
    connection_key = ftp_connections[0]
    nes.plot_transfer_progress(node2, connection_key)