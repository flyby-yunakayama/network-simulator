import uuid

class Packet:
    def __init__(self, source_mac, destination_mac, header_size, payload_size, network_event_scheduler):
        self.network_event_scheduler = network_event_scheduler
        self.id = str(uuid.uuid4())
        self.header = {
            "source_mac": source_mac,
            "destination_mac": destination_mac,
        }
        self.payload = 'X' * payload_size
        self.size = header_size + payload_size
        self.creation_time = self.network_event_scheduler.current_time
        self.arrival_time = None

    def set_arrived(self, arrival_time):
        self.arrival_time = arrival_time

    def __lt__(self, other):
        return False  # heapqでの比較のため

    def __str__(self):
        return f'パケット(送信元: {self.header["source_mac"]}, 宛先: {self.header["destination_mac"]}, ペイロード: {self.payload})'

class BPDU(Packet):
    def __init__(self, source_mac, destination_mac, root_id, bridge_id, path_cost, network_event_scheduler):
        # Packetクラスのコンストラクタを呼び出す
        super().__init__(source_mac, destination_mac, header_size=20, payload_size=50, network_event_scheduler=network_event_scheduler)
        # BPDU特有のペイロード情報を追加
        self.payload = {
            "root_id": root_id,
            "bridge_id": bridge_id,
            "path_cost": path_cost
        }

    def __str__(self):
        # BPDUの文字列表現をカスタマイズ
        return f'BPDU(送信元: {self.header["source_mac"]}, 宛先: {self.header["destination_mac"]}, ルートID: {self.payload["root_id"]}, ブリッジID: {self.payload["bridge_id"]}, パスコスト: {self.payload["path_cost"]})'
