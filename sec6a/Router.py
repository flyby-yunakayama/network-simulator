import heapq
import random
import ipaddress
from sec6a.Packet import HelloPacket, LSAPacket

class Router:
    def __init__(self, node_id, ip_addresses, network_event_scheduler, hello_interval=10, lsa_interval=10, default_route = None):
        self.network_event_scheduler = network_event_scheduler
        self.node_id = node_id
        self.links = []
        self.available_ips = {ip: False for ip in ip_addresses} # CIDR表記のIPアドレスを辞書に変換し、使用状況をFalse（未使用）に初期化
        self.interfaces = {}  # インターフェース（リンクとIPアドレスのマッピング）
        self.routing_table = {}  # ルーティングテーブル
        self.default_route = default_route  # デフォルトルート
        self.neighbors = {}  # 隣接ルータの状態を格納
        self.hello_interval = hello_interval
        self.lsa_sequence_number = 0  # LSAシーケンス番号の初期化
        self.lsa_interval = lsa_interval  # LSA送信のインターバル
        self.lsa_database = {}  # LSA情報を格納
        self.is_topology_initialized = False
        self.topology_database = {}  # トポロジデータベースの初期化
        label = f'Router {node_id}'
        self.network_event_scheduler.add_node(node_id, label, ip_addresses=ip_addresses)
        self.schedule_hello_packet()
        self.schedule_lsa()

    def print_interfaces(self):
        print(f"インターフェース情報（ルータ {self.node_id}）:")
        for link, ip_address in self.interfaces.items():
            print(f"  リンク: {link}, IPアドレス: {ip_address}")

    def add_link(self, link, ip_address=None):
        if link not in self.interfaces:
            self.interfaces[link] = ip_address

    def mark_ip_as_used(self, ip_address):
        if ip_address in self.available_ips:
            self.available_ips[ip_address] = True  # 辞書の値をTrue（使用済み）に更新
        else:
            raise ValueError(f"IPアドレス {ip_address} はこのルータに存在しません。")

    def get_available_ip_addresses(self):
        return [ip for ip in self.available_ips if ip not in self.interfaces.values()]

    def add_route(self, destination_cidr, next_hop, link):
        self.routing_table[destination_cidr] = (next_hop, link)

    def get_route(self, destination_ip):
        if destination_ip == "224.0.0.5":
            return "multicast", None

        for network_cidr, route_info in self.routing_table.items():
            if '/' in network_cidr:
                network_address, mask_length = network_cidr.split('/')
                subnet_mask = self.cidr_to_subnet_mask(mask_length)
                if self.matches_subnet(destination_ip, network_address, subnet_mask):
                    next_hop, link = route_info
                    return next_hop, link
            else:
                # CIDR 形式でないエントリに対するエラーハンドリング
                print(f"Warning: Invalid CIDR format in routing table: {network_cidr}")

        return None, None

    def matches_subnet(self, ip_address, network_address, subnet_mask):
        ip_addr_only = ip_address.split('/')[0] if '/' in ip_address else ip_address
        ip_addr_int = self.ip_to_int(ip_addr_only)
        network_int = self.ip_to_int(network_address)
        mask_int = self.ip_to_int(subnet_mask)

        network_subnet = network_int & mask_int
        return ip_addr_int & mask_int == network_subnet

    def schedule_hello_packet(self):
        # 最初の Hello パケット送信をスケジュール
        initial_delay = random.uniform(0, 0.1)
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + initial_delay,
            self.send_hello_packet
        )

    def schedule_lsa(self):
        # LSA送信のスケジューリング
        initial_delay = random.uniform(0.3, 0.5)
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + initial_delay,
            self.send_lsa
        )

    def send_hello_packet(self):
        for link, interface_cidr in self.interfaces.items():
            network_address, mask_length = interface_cidr.split('/')
            hello_packet = HelloPacket(
                source_mac="00:00:00:00:00:00",  # ダミーMACアドレス
                source_ip=network_address,
                network_mask=self.cidr_to_subnet_mask(mask_length),
                router_id=self.node_id,
                hello_interval=self.hello_interval,  # 適切なHelloインターバルを設定
                neighbors=list(self.neighbors.keys()),  # 隣接ルータのリスト
                network_event_scheduler=self.network_event_scheduler
            )
            link.enqueue_packet(hello_packet, self)

        # 定期的に Hello パケットを送信するためのイベントをスケジュール
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + self.hello_interval,
            self.send_hello_packet
        )

    def send_lsa(self):
        # シーケンス番号のインクリメント
        seq_number = self.increment_lsa_sequence_number()

        # リンク状態情報の取得
        link_state_info = self.get_link_state_info()
        
        # 各インターフェースに対応する隣接ルータへLSAパケットを送信
        for link, ip_address in self.interfaces.items():
            source_ip = ip_address
            lsa_packet = LSAPacket(
                source_mac="00:00:00:00:00:00",  # ダミーMACアドレス
                source_ip=source_ip,  # インターフェースのIPアドレス
                router_id=self.node_id,
                sequence_number=seq_number,  # インクリメントしたシーケンス番号
                link_state_info=link_state_info,  # リンク状態情報
                network_event_scheduler=self.network_event_scheduler
            )
            link.enqueue_packet(lsa_packet, self)

        # 次回のLSA送信をスケジュール
        self.network_event_scheduler.schedule_event(
            self.network_event_scheduler.current_time + self.lsa_interval,
            self.send_lsa
        )

    def flood_lsa(self, original_lsa_packet):
        # リンク状態情報の取得
        link_state_info = self.get_link_state_info()
        
        # 元のLSAパケットの送信元ルータIDを取得
        original_sender_id = original_lsa_packet.payload["router_id"]
        
        # 各インターフェースをループしてLSAパケットを送信
        for link, ip_address in self.interfaces.items():
            # 送信元ルータを除外
            if link.node_x.node_id != original_sender_id and link.node_y.node_id != original_sender_id:
                lsa_packet = original_lsa_packet
                link.enqueue_packet(lsa_packet, self)

    def increment_lsa_sequence_number(self):
        self.lsa_sequence_number += 1
        return self.lsa_sequence_number

    def get_link_state_info(self):
        link_state_info = {}
        for link, ip_address in self.interfaces.items():
            link_state_info[link] = {
                "ip_address": ip_address,
                "cost": self.calculate_link_cost(link),
                "state": self.get_link_state(link)
            }
        return link_state_info

    def calculate_link_cost(self, link):
        # リンクコストを計算する簡単なロジック
        return 1 / link.bandwidth

    def get_link_state(self, link):
        # リンクの状態を取得するロジック（例: アクティブかどうか）
        return "active" if link.is_active else "inactive"

    def forward_packet(self, packet):
        destination_ip = packet.header["destination_ip"]
        next_hop, link = self.get_route(destination_ip)

        if destination_ip == "224.0.0.5":
            for link in self.interfaces.keys():
                self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
                link.enqueue_packet(packet, self)
        elif link:  # unicast
            self.network_event_scheduler.log_packet_info(packet, "forwarded", self.node_id)
            link.enqueue_packet(packet, self)
        elif self.default_route:  # default route
            self.network_event_scheduler.log_packet_info(packet, "forwarded via default route", self.node_id)
            self.default_route.enqueue_packet(packet, self)
        else:
            self.network_event_scheduler.log_packet_info(packet, "dropped", self.node_id)

    def cidr_to_network_address(self, cidr):
        network, mask_length = cidr.split('/')
        subnet_mask = self.cidr_mask_to_int(mask_length)
        return network, subnet_mask

    def receive_packet(self, packet, received_link):
        # 特定のパケットタイプ（HelloやLSA）を先に処理
        if isinstance(packet, HelloPacket):
            self.receive_hello_packet(packet, received_link)
            return  # Helloパケットの場合、処理を終了
        elif isinstance(packet, LSAPacket):
            self.receive_lsa(packet)
            return  # LSAパケットの場合、処理を終了

        # 一般のパケットの場合、TTLを減らす
        packet.header["ttl"] -= 1

        # TTLが0以下になったら、パケットを破棄
        if packet.header["ttl"] <= 0:
            self.network_event_scheduler.log_packet_info(packet, "dropped due to TTL expired", self.node_id)
            return
        else:
            destination_ip = packet.header["destination_ip"]
            if '/' in destination_ip:
                destination_ip, _ = destination_ip.split('/')
            for link, interface_cidr in self.interfaces.items():
                network_address, mask_length = interface_cidr.split('/')
                subnet_mask = self.cidr_to_subnet_mask(mask_length)
                if self.matches_subnet(destination_ip, network_address, subnet_mask):
                    if self.is_final_destination(packet, network_address):
                        pass
                    else:
                        self.forward_packet(packet)
                    return
            print(packet)
            self.forward_packet(packet)

    def is_final_destination(self, packet, network_address):
        destination_ip = packet.header["destination_ip"]
        if '/' in destination_ip:
            destination_ip, _ = destination_ip.split('/')
        return destination_ip == network_address

    def process_packet(self, packet, received_link):
        print(f"Packet {packet.id} processed at router {self.node_id}")

    def receive_hello_packet(self, packet, received_link):
        router_id = packet.payload["router_id"]
        new_neighbor = False

        # 隣接ルータの情報を更新
        if router_id not in self.neighbors:
            new_neighbor = True
            self.neighbors[router_id] = {
                "last_hello_time": self.network_event_scheduler.current_time,
                "link": received_link,
                "neighbor_info": packet.payload
            }
        else:
            last_hello_time = self.neighbors[router_id]["last_hello_time"]
            if self.network_event_scheduler.current_time > last_hello_time:
                new_neighbor = True
                self.neighbors[router_id]["last_hello_time"] = self.network_event_scheduler.current_time
                self.neighbors[router_id]["link"] = received_link
                self.neighbors[router_id]["neighbor_info"] = packet.payload

        # 隣接情報が更新された場合、情報を表示
        if new_neighbor:
            self.print_neighbor_info()

    def print_neighbor_info(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"隣接ルータの情報（ルータ {self.node_id}）:")
            if not self.neighbors:
                print("  隣接ルータはありません。")
                return
            for router_id, info in self.neighbors.items():
                last_hello_time = info["last_hello_time"]
                link = info["link"]
                neighbor_info = info["neighbor_info"]
                print(f"  ルータID: {router_id}")
                print(f"    最後のHello受信時刻: {last_hello_time}")
                print(f"    隣接ルータへのリンク: {link}")
                print(f"    追加情報: {neighbor_info}")

    def receive_lsa(self, lsa_packet):
        lsa_info = lsa_packet.payload["link_state_info"]

        if not self.is_topology_initialized:
            self.initialize_topology_database()
            self.is_topology_initialized = True

        if "sequence_number" in lsa_packet.payload:
            seq_number = lsa_packet.payload["sequence_number"]
            current_lsa_info = self.topology_database.get(lsa_packet.payload["router_id"], {})

            if seq_number > current_lsa_info.get("sequence_number", -1):
                # トポロジデータベースを更新
                self.topology_database[lsa_packet.payload["router_id"]] = {
                    "sequence_number": seq_number,
                    "link_state_info": lsa_info
                }

                # ルーティングテーブルの再計算
                self.update_routing_table_with_dijkstra()

                # LSAを隣接ルータに再送信
                self.flood_lsa(lsa_packet)

            else:
                # 既知のLSAは無視する
                pass

    def initialize_topology_database(self):
        # 自身のルータのリンク状態情報を初期化
        link_state_info = {}
        for link, ip_address in self.interfaces.items():
            link_state_info[link] = {
                "ip_address": ip_address,  # インターフェースのIPアドレス
                "cost": self.calculate_link_cost(link),
                "state": "active"  # 初期状態はアクティブとする
            }

        # トポロジデータベースに自身のルータの情報を登録
        self.topology_database = {
            self.node_id: {'link_state_info': link_state_info}
        }

    def print_topology_database(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"トポロジデータベース（ルータ {self.node_id}）:")
            for router_id, router_info in self.topology_database.items():
                print(f"  ルータID: {router_id}")
                link_state_info = router_info.get("link_state_info", {})
                for link, info in link_state_info.items():
                    if isinstance(info, dict):
                        print(f"    リンク: {link}")
                        print(f"      IPアドレス: {info.get('ip_address')}")
                        print(f"      コスト: {info.get('cost')}")
                        print(f"      状態: {info.get('state')}")
                    else:
                        print(f"    不正なデータ型: {info}")

    def calculate_shortest_paths(self, start_router_id):
        # 最短経路コストの辞書を初期化
        shortest_paths = {router_id: float('inf') for router_id in self.topology_database}
        shortest_paths[start_router_id] = 0
        previous_nodes = {router_id: None for router_id in self.topology_database}

        # プライオリティキューを使用して最小コストのルータを探索
        queue = [(0, start_router_id)]
        while queue:
            current_cost, current_router_id = heapq.heappop(queue)

            # 現在のルータから到達可能なルータに対してコストを更新
            if current_router_id in self.topology_database:
                for link, link_info in self.topology_database[current_router_id]['link_state_info'].items():
                    neighbor_router_id = self.get_neighbor_router_id(link, current_router_id)
                    if neighbor_router_id and neighbor_router_id in self.topology_database:
                        new_cost = current_cost + link_info['cost']
                        if new_cost < shortest_paths[neighbor_router_id]:
                            shortest_paths[neighbor_router_id] = new_cost
                            previous_nodes[neighbor_router_id] = current_router_id
                            heapq.heappush(queue, (new_cost, neighbor_router_id))

        return shortest_paths, previous_nodes

    def update_routing_table_with_dijkstra(self):
        shortest_paths, previous_nodes = self.calculate_shortest_paths(self.node_id)
        print(self.node_id)
        print("Shortest paths:", shortest_paths)  # デバッグ情報の出力
        print("Previous nodes:", previous_nodes)  # デバッグ情報の出力

        # ルーティングテーブルを更新
        for destination, cost in shortest_paths.items():
            if destination != self.node_id:
                destination_cidr = self.get_destination_cidr(destination)
                next_hop = previous_nodes[destination]
                link_to_next_hop = None

                if next_hop == self.node_id:
                    next_hop = None
                    destination_router = self.topology_database.get(destination)
                    if destination_router:
                        ip_address_list = destination_router['link_state_info'].values()
                        # 自身のインターフェースを検索し、ip_addressと同じネットワークに属するリンクを探す
                        for ip_info in ip_address_list:
                            for intf_link, intf_cidr in self.interfaces.items():
                                if self.is_same_network(intf_cidr, ip_info['ip_address']):
                                    link_to_next_hop = intf_link
                                    break
                            if link_to_next_hop:
                                break
                else:
                    link_to_next_hop = self.get_link_to_neighbor(next_hop)

                if destination_cidr and link_to_next_hop:
                    self.add_route(destination_cidr, next_hop, link_to_next_hop)

                print(f"Updating route to {destination} at {destination_cidr} via {next_hop} on link {link_to_next_hop}")  # ルート更新のデバッグ情報

        # ルータ自身のインターフェースに接続されているネットワークに対するルートを追加
        for link, interface_cidr in self.interfaces.items():
            # 既存のルートがない場合、またはルートがNoneの場合のみ追加
            if interface_cidr not in self.routing_table or self.routing_table[interface_cidr][0] is None:
                self.add_route(interface_cidr, None, link)  # 直接接続されているため、next_hopはNone

        # ルーティングテーブルの内容を出力
        print("Updated Routing Table:")
        for destination_cidr, (next_hop, link) in self.routing_table.items():
            print(f"Destination: {destination_cidr}, Next hop: {next_hop}, Link: {link}")

    def get_destination_cidr(self, router_id):
        if router_id in self.topology_database:
            link_info = self.topology_database[router_id]['link_state_info']
            for link, info in link_info.items():
                return info["ip_address"]
        return None

    def is_same_network(self, cidr1, cidr2):
        # CIDR表記のIPアドレスが同じネットワークに属するか判断
        net1 = ipaddress.ip_network(cidr1, strict=False)
        net2 = ipaddress.ip_network(cidr2, strict=False)
        return net1.overlaps(net2)

    def get_neighbor_router_id(self, link, current_router_id):
        if link.node_x.node_id == current_router_id:
            return link.node_y.node_id
        elif link.node_y.node_id == current_router_id:
            return link.node_x.node_id
        else:
            return None  # 現在のルータとリンクしていない場合

    def get_link_to_neighbor(self, neighbor_router_id):
        # next_hopがNoneの場合、直接接続されたリンクを返す
        if neighbor_router_id is None:
            for link in self.links:
                if link.node_x.node_id == self.node_id or link.node_y.node_id == self.node_id:
                    return link
            return None

        # next_hopが他のルータの場合の処理
        if neighbor_router_id in self.neighbors:
            return self.neighbors[neighbor_router_id]['link']
        
        for link in self.links:
            if link.node_x.node_id == neighbor_router_id or link.node_y.node_id == neighbor_router_id:
                return link
        
        return None  # 指定された隣接ルータに接続するリンクが見つからない場合

    def print_routing_table(self):
        if self.network_event_scheduler.routing_verbose:
            print(f"ルーティングテーブル（ルータ {self.node_id}）:")
            for destination, route_info in self.routing_table.items():
                next_hop, link = route_info
                print(f"  宛先IPアドレス: {destination}, Next hop: {next_hop}, リンク: {link}")

    def ip_to_int(self, ip_address):
        octets = ip_address.split('.')
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(octets)))

    def subnet_mask_to_int(self, subnet_mask):
        return (0xffffffff >> (32 - int(subnet_mask))) << (32 - int(subnet_mask))

    def cidr_mask_to_int(self, mask_length):
        mask_length = int(mask_length)
        mask = (1 << 32) - (1 << (32 - mask_length))
        return mask

    def cidr_to_subnet_mask(self, mask_length):
        mask_length = int(mask_length)
        mask = (0xffffffff >> (32 - mask_length)) << (32 - mask_length)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
