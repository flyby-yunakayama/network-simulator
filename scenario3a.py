from sec3a.NetworkEventScheduler import NetworkEventScheduler
from sec3a.Node import Node
from sec3a.Switch import Switch
from sec3a.Link import Link

# ネットワークイベントスケジューラのインスタンスを作成
network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=False)

# ノードとスイッチの設定
node1 = Node(node_id="n1", address="00:01", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", address="00:02", network_event_scheduler=network_event_scheduler)
switch1 = Switch(node_id="s1", network_event_scheduler=network_event_scheduler)

# リンクの設定
# node1とswitch1、node2とswitch1をそれぞれリンクで接続
link1 = Link(node1, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(node2, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# スイッチのフォワーディングテーブルを設定
# node1のアドレス宛のパケットはlink1を通じて、node2のアドレス宛のパケットはlink2を通じて転送される
switch1.update_forwarding_table(node1.address, link1)
switch1.update_forwarding_table(node2.address, link2)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
# node1からnode2へのトラフィックを設定
node1.set_traffic(destination="00:02", bitrate=10000, start_time=1.0, duration=10.0, burstiness=1.0, header_size=40, payload_size=85)

# イベントスケジューラを実行
network_event_scheduler.run()

# 結果を確認
# ネットワーク上でのパケットの流れとパフォーマンスに関するサマリを生成
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
