from sec2.NetworkEventScheduler import NetworkEventScheduler
from sec2.Node import Node
from sec2.Link import Link

# グローバルネットワークイベントスケジューラのインスタンスを作成
network_event_scheduler = NetworkEventScheduler(log_enabled=True, verbose=True)

# ノードとリンクの設定
node1 = Node(node_id=1, address="00:01", network_event_scheduler=network_event_scheduler)
node2 = Node(node_id=2, address="00:02", network_event_scheduler=network_event_scheduler)
link1 = Link(node1, node2, bandwidth=10000, delay=0.001, loss_rate=0.0, network_event_scheduler=network_event_scheduler)

# ネットワークのトポロジを描画
network_event_scheduler.draw()

# 通信アプリケーションの設定
header_size = 40  # ヘッダサイズを40バイトとする
payload_size = 85  # ペイロードサイズを設定 (パケットサイズを 40 + 85 = 125バイト = 1000ビット に設定)
node1.set_traffic(destination="00:02", bitrate=1000, start_time=1.0, duration=10.0, burstiness=1.0, header_size=header_size, payload_size=payload_size)

# イベントスケジューラを実行
network_event_scheduler.run()
