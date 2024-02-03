class Node:
    def __init__(self, node_id, address, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.address = address
        self.links = []
        label = f'Node {node_id}\n{address}'
        self.network_event_scheduler.add_node(node_id, label)

    def add_link(self, link):
        if link not in self.links:
            self.links.append(link)

    def receive_packet(self, packet):
        if packet.arrival_time == -1:
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)  # パケットロスをログに記録
            return
        if packet.header["destination"] == self.address:
            self.network_event_scheduler.log_packet_info(packet, "arrived", self.node_id)  # パケット受信をログに記録
            packet.set_arrived(self.network_event_scheduler.current_time)
        else:
            self.network_event_scheduler.log_packet_info(packet, "received", self.node_id)  # パケット受信をログに記録
            # パケットの宛先が自分自身でない場合の処理
            pass

    def send_packet(self, packet):
        self.network_event_scheduler.log_packet_info(packet, "sent", self.node_id)  # パケット送信をログに記録
        if packet.header["destination"] == self.address:
            self.receive_packet(packet)
        else:
            for link in self.links:
                next_node = link.node_x if self != link.node_x else link.node_y
                link.enqueue_packet(packet, self)
                break

    def create_packet(self, destination, header_size, payload_size):
        packet = Packet(source=self.address, destination=destination, header_size=header_size, payload_size=payload_size, network_event_scheduler=self.network_event_scheduler)
        self.network_event_scheduler.log_packet_info(packet, "created", self.node_id)  # パケット生成をログに記録
        self.send_packet(packet)

    def set_traffic(self, destination, bitrate, start_time, duration, header_size, payload_size, burstiness=1.0):
        end_time = start_time + duration
        def generate_packet():
            if self.network_event_scheduler.current_time < end_time:
                self.create_packet(destination, header_size, payload_size)
                packet_size = header_size + payload_size
                interval = (packet_size * 8) / bitrate * burstiness
                self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + interval, generate_packet)

        self.network_event_scheduler.schedule_event(start_time, generate_packet)

    def __str__(self):
        connected_nodes = [link.node_x.node_id if self != link.node_x else link.node_y.node_id for link in self.links]
        connected_nodes_str = ', '.join(map(str, connected_nodes))
        return f"ノード(ID: {self.node_id}, アドレス: {self.address}, 接続: {connected_nodes_str})"
