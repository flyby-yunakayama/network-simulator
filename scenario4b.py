from sec4b.NetworkEventScheduler import NetworkEventScheduler
from sec4b.Node import Node
from sec4b.Switch import Switch
from sec4b.Link import Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=False, stp_verbose=True)

# ノードとスイッチの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", network_event_scheduler=network_event_scheduler)
switch1 = Switch(node_id="s1", network_event_scheduler=network_event_scheduler)
switch2 = Switch(node_id="s2", network_event_scheduler=network_event_scheduler)
switch3 = Switch(node_id="s3", network_event_scheduler=network_event_scheduler)
switch4 = Switch(node_id="s4", network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(switch1, switch2, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(switch1, switch3, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link4 = Link(switch1, switch4, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link5 = Link(switch2, switch3, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link6 = Link(switch2, switch4, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link7 = Link(switch3, switch4, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link8 = Link(node2, switch3, bandwidth=100000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
#node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", bitrate=1000, start_time=1.0, duration=2.0, burstiness=1.0, header_size=40, payload_size=85)

# イベントスケジューラを実行
network_event_scheduler.run()

# 結果を確認
# リンクの状態を確認
switch1.print_link_states()
switch2.print_link_states()
switch3.print_link_states()
switch4.print_link_states()
# リンクの状態を可視化
switches = [switch1, switch2, switch3, switch4]
network_event_scheduler.draw_with_link_states(switches)

# フォワーディングテーブルを確認
switch1.print_forwarding_table()
switch2.print_forwarding_table()
switch3.print_forwarding_table()
switch4.print_forwarding_table()

# ネットワーク上でのパケットの流れとパフォーマンスに関するサマリを生成
#network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
