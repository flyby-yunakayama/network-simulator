class Link:
    def __init__(self, node_x, node_y, network_graph, bandwidth=10000, delay=0.001, packet_loss=0.0):
        self.node_x = node_x
        self.node_y = node_y
        self.bandwidth = bandwidth
        self.delay = delay
        self.packet_loss = packet_loss
        self.network_graph = network_graph

        node_x.add_link(self)
        node_y.add_link(self)

        # グラフにリンクを追加
        label = f'{bandwidth/1000000} Mbps, {delay} s'
        self.network_graph.add_link(node_x.node_id, node_y.node_id, label, self.bandwidth, self.delay)

    def transfer_packet(self, packet, from_node):
        next_node = self.node_x if from_node != self.node_x else self.node_y
        next_node.receive_packet(packet)

    def __str__(self):
        return f"リンク({self.node_x.node_id} ↔ {self.node_y.node_id}, 帯域幅: {self.bandwidth}, 遅延: {self.delay}, パケットロス率: {self.packet_loss})"

class Packet:
    def __init__(self, source, destination, payload):
        self.source = source
        self.destination = destination
        self.payload = payload

    def __str__(self):
        return f"パケット(送信元: {self.source}, 宛先: {self.destination}, ペイロード: {self.payload})"
