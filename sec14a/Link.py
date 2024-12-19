import heapq
import random
from collections import defaultdict
from sec14a.Switch import Switch
from sec14a.Router import Router
from sec14a.Packet import Packet, TCPPacket, UDPPacket

class Link:
    def __init__(self, node_x, node_y, bandwidth, delay, loss_rate, network_event_scheduler):
        self.node_x = node_x
        self.node_y = node_y
        self.bandwidth = bandwidth
        self.delay = delay
        self.loss_rate = loss_rate
        self.dropped_packets = 0  # パケットロスのカウント用
        self.total_packets = 0    # 総パケット数のカウント用
        self.is_active = True
        self.network_event_scheduler = network_event_scheduler
        self.local_seed = self.network_event_scheduler.get_seed()
        if self.local_seed is not None:
            random.seed(self.local_seed)

        # 優先度付きキューの初期化
        self.priority_queues_xy = defaultdict(list)
        self.priority_queues_yx = defaultdict(list)

        # 転送中フラグの初期化
        self.is_transferring_xy = False
        self.is_transferring_yx = False

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
        """
        # IPアドレスとサブネットマスクをビット演算できるように整数に変換
        ip_addr_int = self.ip_to_int(ip_address)
        mask_int = self.ip_to_int(subnet_mask)

        # ネットワークアドレスの計算
        return ip_addr_int & mask_int

    def ip_to_int(self, ip_address):
        """
        IPアドレスを整数に変換する。
        """
        octets = ip_address.split('.')
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(octets)))

    def subnet_mask_to_int(self, subnet_mask):
        """
        サブネットマスク（CIDR表記）を整数に変換する。
        """
        return (0xffffffff >> (32 - int(subnet_mask))) << (32 - int(subnet_mask))

    def enqueue_packet(self, packet, from_node):
        priority = packet.get_priority()
        if from_node == self.node_x:
            queue = self.priority_queues_xy[priority]
            is_transferring = self.is_transferring_xy
        else:
            queue = self.priority_queues_yx[priority]
            is_transferring = self.is_transferring_yx

        # 現在の時刻を使用してキューにパケットを追加
        dequeue_time = self.network_event_scheduler.current_time
        heapq.heappush(queue, (dequeue_time, packet, from_node))

        if self.network_event_scheduler.link_verbose:
            print(f"{self.network_event_scheduler.current_time}, enqueue packet {packet.size} bytes, priority: {priority}")

        # キューが1になった場合、最初の transfer_packet をスケジュール
        if len(queue) == 1 and not is_transferring:
            self.network_event_scheduler.schedule_event(
                self.network_event_scheduler.current_time,
                self.transfer_packet,
                from_node
            )

    def transfer_packet(self, from_node):
        if from_node == self.node_x:
            priority_queues = self.priority_queues_xy
            self.is_transferring_xy = True
        else:
            priority_queues = self.priority_queues_yx
            self.is_transferring_yx = True

        # 最高優先度の非空キューを見つける
        for priority in sorted(priority_queues.keys(), reverse=True):
            queue = priority_queues[priority]
            if queue:
                dequeue_time, packet, _ = heapq.heappop(queue)
                packet_transfer_time = (packet.size * 8) / self.bandwidth  # 秒単位
                if self.network_event_scheduler.link_verbose:
                    print(f"{self.network_event_scheduler.current_time:.6f}: Packet transferred from Link {self.node_x.node_id}-{self.node_y.node_id} to {from_node.node_id}. Packet size: {packet.size} bytes, Priority: {packet.get_priority()}")

                self.total_packets += 1
                if self.should_drop_packet(packet):
                    self.dropped_packets += 1
                    if self.network_event_scheduler.link_verbose:
                        print(f"{self.network_event_scheduler.current_time:.6f}: Packet dropped at Link {self.node_x.node_id}-{self.node_y.node_id}. "
                              f"Total drops: {self.dropped_packets}/{self.total_packets} "
                              f"({self.dropped_packets/self.total_packets*100:.2f}%)")
                    packet.set_arrived(-1)

                next_node = self.node_x if from_node != self.node_x else self.node_y

                # 遅延計算
                propagation_delay = self.delay
                transmission_time = (packet.size * 8) / self.bandwidth
                total_delay = propagation_delay + transmission_time

                if getattr(packet, 'send_time', None) is None and from_node.ip_address == packet.header["source_ip"]:
                    packet.send_time = self.network_event_scheduler.current_time
                self.network_event_scheduler.log_packet_info(packet, "sent", from_node.node_id)

                self.network_event_scheduler.schedule_event(
                    self.network_event_scheduler.current_time + total_delay,
                    next_node.receive_packet,
                    packet,
                    self
                )

                # 現在のパケットの転送時間後に次のパケット送信をスケジュール
                if self.network_event_scheduler.link_verbose:
                    print(f"{self.network_event_scheduler.current_time:.6f}, packet_transfer_time: {packet_transfer_time}")
                if any(priority_queues.values()):
                    self.network_event_scheduler.schedule_event(
                        self.network_event_scheduler.current_time + packet_transfer_time,
                        self.transfer_packet,
                        from_node
                    )
                    if self.network_event_scheduler.link_verbose:
                        print(f"{self.network_event_scheduler.current_time:.6f}: Schedule next packet transfer after {packet_transfer_time} seconds")
                else:
                    if from_node == self.node_x:
                        self.is_transferring_xy = False
                    else:
                        self.is_transferring_yx = False

                break  # 一度に一つのパケットのみ処理
        else:
            if from_node == self.node_x:
                self.is_transferring_xy = False
            else:
                self.is_transferring_yx = False

    def should_drop_packet(self, packet):
        """パケットをドロップするかどうかを決定する"""
        if not isinstance(packet, (TCPPacket, UDPPacket)):
            return False

        # TCPパケットの場合、PSHフラグがある場合のみドロップ対象
        if isinstance(packet, TCPPacket):
            if "PSH" not in packet.header.get('flags', ''):
                return False

        return random.random() < self.loss_rate

    def __str__(self):
        return f"リンク({self.node_x.node_id} ↔ {self.node_y.node_id}, 帯域幅: {self.bandwidth}, 遅延: {self.delay}, パケットロス率: {self.loss_rate})"
