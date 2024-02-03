class Switch:
    def __init__(self, node_id, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.links = []
        self.forwarding_table = {}
        label = f'Switch {node_id}'
        self.network_event_scheduler.add_node(node_id, label)

    def add_link(self, link):
        if link not in self.links:
            self.links.append(link)

    def update_forwarding_table(self, source_address, link):
        self.forwarding_table[source_address] = link

    def receive_packet(self, packet, received_link):
        if packet.arrival_time == -1:
            self.network_event_scheduler.log_packet_info(packet, "lost", self.node_id)
            return
        self.network_event_scheduler.log_packet_info(packet, "received", self.node_id)

        source_address = packet.header["source_mac"]
        self.update_forwarding_table(source_address, received_link)
        self.forward_packet(packet, received_link)

    def forward_packet(self, packet, received_link):
        destination_address = packet.header["destination_mac"]
        if destination_address in self.forwarding_table:
            link = self.forwarding_table[destination_address]
            self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
            link.enqueue_packet(packet, self)
        else:
            for link in self.links:
                if link != received_link:
                    self.network_event_scheduler.log_packet_info(packet, "broadcast", self.node_id)
                    link.enqueue_packet(packet, self)

    def print_forwarding_table(self):
        print(f"フォワーディングテーブル for Switch {self.node_id}:")
        for mac_address, link in self.forwarding_table.items():
            linked_node = link.node_x.node_id if link.node_x.node_id != self.node_id else link.node_y.node_id
            print(f"  MACアドレス: {mac_address} -> リンク先ノード: {linked_node}")

    def __str__(self):
        connected_nodes = [link.node_x.node_id if self.node_id != link.node_x.node_id else link.node_y.node_id for link in self.links]
        connected_nodes_str = ', '.join(map(str, connected_nodes))
        return f"スイッチ(ID: {self.node_id}, 接続: {connected_nodes_str})"
