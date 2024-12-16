from sec14a.NetworkEventScheduler import NetworkEventScheduler
from sec14a.Node import Node
from sec14a.Switch import Switch
from sec14a.Link import Link
from sec14a.Application import UDPApp, FTPClient, FTPServer

nes = NetworkEventScheduler(seed=7, log_enabled=True, verbose=False, tcp_verbose=True, link_verbose=False)

# ノードの設定（サーバ側）
server1 = Node(node_id="server1", ip_address="192.168.1.250/24", network_event_scheduler=nes)
# FTPサーバインスタンス
ftp_server = FTPServer(server1, shared_files={}, verbose=True)
# 21/TCPポートでFTPサーバを起動（待ち受け）
server1.register_application(21, "TCP", ftp_server)

# ノードの設定（クライアント側）
client1 = Node(node_id="client1", ip_address="192.168.1.1/24", network_event_scheduler=nes)
# FTPクライアントインスタンス
ftp_client = FTPClient(client1, verbose=False)
# FTPクライアントをApplicationManagerに登録
client1.register_application(0, "TCP", ftp_client)

# UDP送信アプリケーションのインスタンス作成
udp_app = UDPApp(client1)

# リンクの設定
link1 = Link(client1, server1, bandwidth=1000000, delay=0.01, loss_rate=0.04, network_event_scheduler=nes)

# ネットワークのトポロジを描画
#nes.draw()

# ファイル読み込み（サーバ側ファイル想定）
file_path = '/content/sample_data/california_housing_test.csv'
with open(file_path, 'rb') as f:
    file_data = f.read()

# サーバにファイル登録
ftp_server.shared_files["testfile.txt"] = file_data

# クライアント側でFTP転送を開始する処理
# ここでは1.0秒後に実行されるようスケジューリング
def start_ftp_transfer():
    ftp_client.connect(server_ip="192.168.1.250/24", server_port=21)
    # コネクション確立後、USER/PASSとRETR testfile.txtを行うようなロジックをFTPClient内に実装
    ftp_client.retrieve_file("testfile.txt")

# UDPトラフィック開始処理
def start_udp_traffic():
    # 2.0秒後からUDPトラフィックを5秒間、bitrate=1Mbps, payload=72バイト、header_size=28バイトで送信
    udp_app.start_traffic(destination_url="192.168.1.250/24",
                          bitrate=100000,
                          start_time=2.0,
                          duration=5.0,
                          header_size=28,
                          payload_size=72,
                          burstiness=1.0,
                          dscp=16)

# 1秒後にFTP転送開始
nes.schedule_event(1.0, start_ftp_transfer)

# UDPトラフィックも2秒後から開始
#nes.schedule_event(2.0, start_udp_traffic)

# イベントスケジューラを実行
nes.run_until(10.0)

# 結果を確認
nes.generate_summary(nes.packet_logs)
nes.generate_throughput_graph(nes.packet_logs)
nes.generate_delay_histogram(nes.packet_logs)

# 転送進行状況のプロット
if server1.tcp_connections:
    connection_key = list(server1.tcp_connections.keys())[0]
    nes.plot_transfer_progress(server1, connection_key)
