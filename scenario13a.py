from sec13a.NetworkEventScheduler import NetworkEventScheduler
from sec13a.Node import Node
from sec13a.Switch import Switch
from sec13a.Link import Link

nes = NetworkEventScheduler(seed=7, log_enabled=True, verbose=False, tcp_verbose=False, link_verbose=True)

# ノードとルータの設定
src1 = Node(node_id="n1", ip_address="192.168.1.1/24", network_event_scheduler=nes)  # IPアドレスを静的に設定
src2 = Node(node_id="n2", ip_address="192.168.1.2/24", network_event_scheduler=nes)
switch1 = Switch(node_id="s1", ip_address="192.168.1.240/24", network_event_scheduler=nes)
dst1 = Node(node_id="d1", ip_address="192.168.1.250/24", network_event_scheduler=nes)

# リンクの設定
link1 = Link(src1, switch1, bandwidth=10000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link2 = Link(src2, switch1, bandwidth=10000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link3 = Link(switch1, dst1, bandwidth=1000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)

# ネットワークのトポロジを描画
nes.draw()

# 通信アプリケーションの設定
src1.start_udp_traffic(destination_url="192.168.1.250/24", bitrate=1000, start_time=1.0, duration=5.0, header_size=28, payload_size=72, dscp=16)  # 優先度高
src2.start_udp_traffic(destination_url="192.168.1.250/24", bitrate=1000, start_time=1.0, duration=5.0, header_size=28, payload_size=72, dscp=0)  # 優先度低

# イベントスケジューラを実行
nes.run_until(10.0)

# 結果を確認
nes.generate_summary(nes.packet_logs)
nes.generate_throughput_graph(nes.packet_logs)
nes.generate_delay_histogram(nes.packet_logs)
