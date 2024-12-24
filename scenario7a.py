from sec7a.NetworkEventScheduler import NetworkEventScheduler
from sec7a.Node import Node
from sec7a.Switch import Switch
from sec7a.Router import Router
from sec7a.Link import Link

nes = NetworkEventScheduler(log_enabled=True, verbose=True, routing_verbose=False)

# ノードとルータの設定
node1 = Node(node_id="n1", ip_address="192.168.1.1/24", network_event_scheduler=nes)
node2 = Node(node_id="n2", ip_address="192.168.2.1/24", network_event_scheduler=nes)
# スイッチにも管理用のIPアドレスが設定されることが一般的です（実世界では遠隔ログインなどに利用します）
switch1 = Switch(node_id="s1", ip_address="192.168.1.11/24", network_event_scheduler=nes)
switch2 = Switch(node_id="s2", ip_address="192.168.2.11/24", network_event_scheduler=nes)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "10.1.1.1/24"], network_event_scheduler=nes)
router2 = Router(node_id="r2", ip_addresses=["192.168.2.254/24", "10.1.1.2/24"], network_event_scheduler=nes)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link2 = Link(switch1, router1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link3 = Link(router1, router2, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link4 = Link(router2, switch2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)
link5 = Link(switch2, node2, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=nes)

# ノードとルータに宛先IPアドレスとMACアドレスの対応テーブルを設定
node1.add_to_arp_table(node2.ip_address, router1.get_mac_address(link2))
node2.add_to_arp_table(node1.ip_address, router2.get_mac_address(link4))
router1.add_to_arp_table(node1.ip_address,node1.mac_address)
router1.add_to_arp_table(node2.ip_address,router2.get_mac_address(link3))
router2.add_to_arp_table(node1.ip_address,router1.get_mac_address(link3))
router2.add_to_arp_table(node2.ip_address,node2.mac_address)

# ネットワークのトポロジを描画
nes.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_ip="192.168.2.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# イベントスケジューラを実行
nes.run_until(5.0)

# フォワーディングテーブルやルーティングテーブルを確認
switch1.print_forwarding_table()
switch2.print_forwarding_table()

router1.print_interfaces()
router2.print_interfaces()

router1.print_routing_table()
router2.print_routing_table()

# 結果を確認
nes.generate_summary(nes.packet_logs)
#nes.generate_throughput_graph(nes.packet_logs)
#nes.generate_delay_histogram(nes.packet_logs)
