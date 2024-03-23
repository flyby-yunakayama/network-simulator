import heapq
import random
from sec11a.Switch import Switch
from sec11a.Router import Router

class Link:
    def __init__(self, node_x, node_y, bandwidth, delay, loss_rate, network_event_scheduler):
        self.node_x = node_x
        self.node_y = node_y
        self.bandwidth = bandwidth
        self.delay = delay
        self.loss_rate = loss_rate
        self.is_active = True
        self.network_event_scheduler = network_event_scheduler

        self.packet_queue_xy = []
        self.packet_queue_yx = []
        self.current_queue_time_xy = 0
        self.current_queue_time_yx = 0

        # IPアドレスの選択とリンクの設定
        ip_x, ip_y = self.setup_link_ips(node_x, node_y)

        # リンクとIPアドレスをノードに追加
        node_x.add_link(self, ip_x)
        node_y.add_link(self, ip_y)
        
        label = f'{bandwidth/1000000} Mbps, {delay} s'
        self.network_event_scheduler.add_link(node_x.node_id, node_y.node_id, label, self.bandwidth, self.delay)

    def set_active(self, active):
        # リンクの状態を設定する
        self.is_active = active

    def setup_link_ips(self, node_x, node_y):
        # ノードから利用可能なIPアドレスリスト（CIDR表記）を取得
        ip_list_x = self.get_available_ip_list(node_x)
        ip_list_y = self.get_available_ip_list(node_y)

        # 互換性のある IP アドレスを選択
        selected_ip_x, selected_ip_y = self.select_compatible_ip(ip_list_x, ip_list_y)
        if selected_ip_x is None or selected_ip_y is None:
            raise ValueError("互換性のある IP アドレスのペアが見つかりませんでした。")

        # 使用済みIPアドレスにフラグを設定
        node_x.mark_ip_as_used(selected_ip_x)
        node_y.mark_ip_as_used(selected_ip_y)

        return selected_ip_x, selected_ip_y

    def get_available_ip_list(self, node):
        # 各ノードタイプに応じて利用可能なIPアドレスリストを返す
        if isinstance(node, Router):
            return node.get_available_ip_addresses()
        elif isinstance(node, Switch):
            return [node.ip_address]  # Switchの場合
        else:
            return [node.ip_address]  # Nodeの場合

    def select_compatible_ip(self, ip_list_x, ip_list_y):
        # CIDR表記で提供されるIPアドレスリストから互換性のあるIPアドレスを選択
        for ip_cidr_x in ip_list_x:
            for ip_cidr_y in ip_list_y:
                if self.is_compatible(ip_cidr_x, ip_cidr_y):
                    return ip_cidr_x, ip_cidr_y
        return None, None  # 互換性のあるアドレスが見つからない場合

    def is_compatible(self, ip_cidr_x, ip_cidr_y):
        """
        二つのIPアドレス（CIDR表記）が同じネットワークに属しているかどうかを判断する。
        :param ip_cidr_x: ノードXのIPアドレス（CIDR表記）
        :param ip_cidr_y: ノードYのIPアドレス（CIDR表記）
        :return: 同じネットワークに属している場合はTrue、そうでない場合はFalse
        """
        ip_address_x, subnet_mask_x = ip_cidr_x.split('/')
        ip_address_y, subnet_mask_y = ip_cidr_y.split('/')

        # CIDR表記のサブネットマスクを整数に変換
        mask_int_x = self.subnet_mask_to_int(subnet_mask_x)
        mask_int_y = self.subnet_mask_to_int(subnet_mask_y)

        # ネットワークアドレスの計算
        network_x = self.ip_to_int(ip_address_x) & mask_int_x
        network_y = self.ip_to_int(ip_address_y) & mask_int_y

        # ネットワークアドレスが一致する場合、同じネットワークに属していると判断
        return network_x == network_y

    def get_network_address(self, ip_address, subnet_mask):
        """
        IPアドレスとサブネットマスクからネットワークアドレスを計算する。

        :param ip_address: 計算するIPアドレス
        :param subnet_mask: 使用するサブネットマスク
        :return: ネットワークアドレス
        """
        # IPアドレスとサブネットマスクをビット演算できるように整数に変換
        ip_addr_int = self.ip_to_int(ip_address)
        mask_int = self.ip_to_int(subnet_mask)

        # ネットワークアドレスの計算
        return ip_addr_int & mask_int

    def ip_to_int(self, ip_address):
        """
        IPアドレスを整数に変換する。

        :param ip_address: 変換するIPアドレス
        :return: 対応する整数
        """
        octets = ip_address.split('.')
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(octets)))

    def subnet_mask_to_int(self, subnet_mask):
        """
        サブネットマスク（CIDR表記）を整数に変換する。
        :param subnet_mask: サブネットマスク（例: "24"）
        :return: 対応する整数
        """
        return (0xffffffff >> (32 - int(subnet_mask))) << (32 - int(subnet_mask))

    def enqueue_packet(self, packet, from_node):
        if from_node == self.node_x:
            queue = self.packet_queue_xy
            current_queue_time = self.current_queue_time_xy
        else:
            queue = self.packet_queue_yx
            current_queue_time = self.current_queue_time_yx

        packet_transfer_time = (packet.size * 8) / self.bandwidth
        dequeue_time = self.network_event_scheduler.current_time + current_queue_time
        heapq.heappush(queue, (dequeue_time, packet, from_node))
        self.add_to_queue_time(from_node, packet_transfer_time)
        if len(queue) == 1:
            self.network_event_scheduler.schedule_event(dequeue_time, self.transfer_packet, from_node)

    def transfer_packet(self, from_node):
        if from_node == self.node_x:
            queue = self.packet_queue_xy
        else:
            queue = self.packet_queue_yx

        if queue:
            dequeue_time, packet, _ = heapq.heappop(queue)
            packet_transfer_time = (packet.size * 8) / self.bandwidth

            if random.random() < self.loss_rate:
                packet.set_arrived(-1)

            next_node = self.node_x if from_node != self.node_x else self.node_y
            self.network_event_scheduler.schedule_event(self.network_event_scheduler.current_time + self.delay, next_node.receive_packet, packet, self)
            self.network_event_scheduler.schedule_event(dequeue_time + packet_transfer_time, self.subtract_from_queue_time, from_node, packet_transfer_time)

            if queue:
                next_packet_time = queue[0][0]
                self.network_event_scheduler.schedule_event(next_packet_time, self.transfer_packet, from_node)

    def add_to_queue_time(self, from_node, packet_transfer_time):
        if from_node == self.node_x:
            self.current_queue_time_xy += packet_transfer_time
        else:
            self.current_queue_time_yx += packet_transfer_time

    def subtract_from_queue_time(self, from_node, packet_transfer_time):
        if from_node == self.node_x:
            self.current_queue_time_xy -= packet_transfer_time
        else:
            self.current_queue_time_yx -= packet_transfer_time

    def __str__(self):
        return f"リンク({self.node_x.node_id} ↔ {self.node_y.node_id}, 帯域幅: {self.bandwidth}, 遅延: {self.delay}, パケットロス率: {self.loss_rate})"
