from sec6c.NetworkEventScheduler import NetworkEventScheduler
from sec6c.Node import Node
from sec6c.Router import Router
from sec6c.Link import Link

# routing_verbose=Trueでルーティング関連情報を出力
network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True, routing_verbose=True)

# ノードとルータの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", ip_address="192.168.1.1/24", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", ip_address="192.168.2.1/24", network_event_scheduler=network_event_scheduler)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "10.1.2.1/24"], network_event_scheduler=network_event_scheduler)
router2 = Router(node_id="r2", ip_addresses=["10.1.2.2/24", "10.2.3.2/24"], network_event_scheduler=network_event_scheduler)
router3 = Router(node_id="r3", ip_addresses=["10.2.3.3/24", "10.3.4.3/24"], network_event_scheduler=network_event_scheduler)
router4 = Router(node_id="r4", ip_addresses=["192.168.2.254/24", "10.3.4.4/24"], network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, router1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(router1, router2, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(router2, router3, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link4 = Link(router3, router4, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link5 = Link(router4, node2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# 通信アプリケーションの設定
node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", destination_ip="192.168.2.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# イベントスケジューラを実行
network_event_scheduler.run_until(20.0)

# ルーティングテーブルの確認
router1.print_routing_table()
router2.print_routing_table()
router3.print_routing_table()
router4.print_routing_table()

# ノードから宛先IPアドレスまでの経路を出力して確認
node1.print_route("192.168.2.1/24")

# 結果を確認
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
