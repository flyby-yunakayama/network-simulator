from sec5b.NetworkEventScheduler import NetworkEventScheduler
from sec5b.Node import Node
from sec5b.Router import Router
from sec5b.Link import Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True, stp_verbose=False)

# ノードとルータの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", ip_address="192.168.1.1/24", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", ip_address="192.168.2.1/24", network_event_scheduler=network_event_scheduler)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "10.0.0.1/24"], network_event_scheduler=network_event_scheduler)
router2 = Router(node_id="r2", ip_addresses=["10.0.0.2/24", "192.168.2.254/24"], network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, router1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(router1, router2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(router2, node2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# ルーティングテーブルの設定
# ルータ1のルーティングテーブルに直接接続されているネットワークへのルートを追加
router1.add_route("192.168.1.0/24", None, link1)  # node1への直接ルート
router1.add_route("192.168.2.0/24", "10.0.0.2", link2)  # router2へのルート

# ルータ2のルーティングテーブルに直接接続されているネットワークへのルートを追加
router2.add_route("192.168.2.0/24", None, link3)  # node2への直接ルート
router2.add_route("192.168.1.0/24", "10.0.0.1", link2)  # router1へのルート

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", destination_ip="192.168.2.1", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# イベントスケジューラを実行
network_event_scheduler.run()

# 結果を確認
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
