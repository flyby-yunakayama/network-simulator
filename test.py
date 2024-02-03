from simplenetwork_sec6a import NetworkEventScheduler, Node, Router, Link

network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True, routing_verbose=True)

# ノードとルータの設定
node1 = Node(node_id="n1", mac_address="00:1A:2B:3C:4D:5E", ip_address="192.168.1.1/24", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id="n2", mac_address="00:1A:2B:3C:4D:5F", ip_address="192.168.2.1/24", network_event_scheduler=network_event_scheduler)
router1 = Router(node_id="r1", ip_addresses=["192.168.1.254/24", "10.1.3.1/24", "10.1.4.1/24"], network_event_scheduler=network_event_scheduler)
router2 = Router(node_id="r2", ip_addresses=["192.168.2.254/24", "10.2.3.1/24", "10.2.4.1/24"], network_event_scheduler=network_event_scheduler)
router3 = Router(node_id="r3", ip_addresses=["10.1.3.2/24", "10.2.3.2/24"], network_event_scheduler=network_event_scheduler)
router4 = Router(node_id="r4", ip_addresses=["10.1.4.2/24", "10.2.4.2/24"], network_event_scheduler=network_event_scheduler)

# リンクの設定
link1 = Link(node1, router1, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link2 = Link(router2, node2, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link3 = Link(router1, router3, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link4 = Link(router1, router4, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link5 = Link(router2, router3, bandwidth=200000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)
link6 = Link(router2, router4, bandwidth=100000, delay=0.01, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# ネットワークのトポロジを描画
#network_event_scheduler.draw()

# 通信アプリケーションの設定
node1.set_traffic(destination_mac="00:1A:2B:3C:4D:5F", destination_ip="192.168.2.1/24", bitrate=10000, start_time=1.0, duration=2.0, header_size=50, payload_size=10000, burstiness=1.0)

# イベントスケジューラを実行
network_event_scheduler.run_until(5.0)

router1.print_interfaces()
router1.print_topology_database()
router1.print_routing_table()

print(network_event_scheduler.find_node_by_ip("10.1.3.2/24"))

#link_state_info = router1.get_link_state_info()
#print("Link State Information:", link_state_info)

# 結果を確認
network_event_scheduler.generate_summary(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_throughput_graph(network_event_scheduler.packet_logs)
#network_event_scheduler.generate_delay_histogram(network_event_scheduler.packet_logs)
