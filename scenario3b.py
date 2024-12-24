from sec3b.NetworkEventScheduler import NetworkEventScheduler
from sec3b.Node import Node
from sec3b.Switch import Switch
from sec3b.Link import Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=False)

# ノードとスイッチの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", network_event_scheduler=network_event_scheduler)
switch1 = Switch(node_id="s1", network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(node2, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# スイッチのフォワーディングテーブルを設定
switch1.update_forwarding_table(node1.mac_address, link1)
switch1.update_forwarding_table(node2.mac_address, link2)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", bitrate=10000, start_time=1.0, duration=10.0, burstiness=1.0, header_size=40, payload_size=85)

# イベントスケジューラを実行
network_event_scheduler.run()

# 結果を確認
# ネットワーク上でのパケットの流れとパフォーマンスに関するサマリを生成
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
