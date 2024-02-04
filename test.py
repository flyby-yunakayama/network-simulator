from sec7a.NetworkEventScheduler import NetworkEventScheduler
from sec7a.Node import Node
from sec7a.Switch import Switch
from sec7a.Router import Router
from sec7a.Link import Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True, routing_verbose=True)

# ノードとルータの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", ip_address="192.168.1.1/24", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", ip_address="192.168.2.1/24", network_event_scheduler=network_event_scheduler)
switch1 = Switch(node_id="s1", ip_address="192.168.1.11/24", network_event_scheduler=network_event_scheduler)
switch2 = Switch(node_id="s2", ip_address="192.168.2.11/24", network_event_scheduler=network_event_scheduler)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "10.1.1.1/24"], network_event_scheduler=network_event_scheduler)
router2 = Router(node_id="r2", ip_addresses=["192.168.2.254/24", "10.1.1.2/24"], network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, switch1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(switch1, router1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(router1, router2, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link4 = Link(router2, switch2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link5 = Link(switch2, node2, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
#node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", destination_ip="192.168.2.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)
#node1.set_traffic(destination_mac=router1.get_mac_address(link2), destination_ip="192.168.2.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# イベントスケジューラを実行
network_event_scheduler.run_until(5.0)

router1.print_interfaces()
router1.print_routing_table()

node1.print_route("192.168.2.1/24")


# 結果を確認
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
