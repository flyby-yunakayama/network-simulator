from sec8a.NetworkEventScheduler import NetworkEventScheduler
from sec8a.Node import Node
from sec8a.Switch import Switch
from sec8a.Router import Router
from sec8a.Link import Link

nes = NetworkEventScheduler(log_enabled=True, verbose=True, routing_verbose=False)

# ノードとルータの設定
node1 = Node(node_id="n1", ip_address="192.168.1.1/24", network_event_scheduler=nes)
node2 = Node(node_id="n2", ip_address="192.168.1.2/24", network_event_scheduler=nes)
node3 = Node(node_id="n3", ip_address="192.168.1.3/24", network_event_scheduler=nes)
node4 = Node(node_id="n4", ip_address="192.168.1.4/24", network_event_scheduler=nes)
switch1 = Switch(node_id="s1", ip_address="192.168.1.11/24", network_event_scheduler=nes)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link2 = Link(node2, switch1, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link3 = Link(node3, switch1, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link4 = Link(node4, switch1, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)

# ネットワークのトポロジを描画
nes.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_ip="192.168.1.2/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)
node2.set_traffic(destination_ip="192.168.1.3/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)
node3.set_traffic(destination_ip="192.168.1.4/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)
node4.set_traffic(destination_ip="192.168.1.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# イベントスケジューラを実行
nes.run_until(5.0)

# フォワーディングテーブルやルーティングテーブルを確認
node1.print_arp_table()
node2.print_arp_table()
node3.print_arp_table()
node4.print_arp_table()
switch1.print_forwarding_table()

# 結果を確認
nes.generate_summary(nes.packet_logs)
#nes.generate_throughput_graph(nes.packet_logs)
#nes.generate_delay_histogram(nes.packet_logs)
