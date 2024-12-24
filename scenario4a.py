from sec4a.NetworkEventScheduler import NetworkEventScheduler
from sec4a.Node import Node
from sec4a.Switch import Switch
from sec4a.Link import Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True)

# ノードとスイッチの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", network_event_scheduler=network_event_scheduler)
node3 = Node(node_id="n3", mac_address="00:1A:2B:3C:4D:60", network_event_scheduler=network_event_scheduler)
node4 = Node(node_id="n4", mac_address="00:1A:2B:3C:4D:61", network_event_scheduler=network_event_scheduler)
switch1 = Switch(node_id="s1", network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(node2, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(node3, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link4 = Link(node4, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# スイッチのフォワーディングテーブルを設定しない

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", bitrate=1000, start_time=1.0, duration=2.0, burstiness=1.0, header_size=40, payload_size=85)
node2.set_traffic(destination_mac="00:1A:2B:3C:4D:61", bitrate=1000, start_time=1.0, duration=2.0, burstiness=1.0, header_size=40, payload_size=85)

# イベントスケジューラを実行
network_event_scheduler.run()

# 結果を確認
# フォワーディングテーブルを確認
switch1.print_forwarding_table()

# ネットワーク上でのパケットの流れとパフォーマンスに関するサマリを生成
#network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
