import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

class NetworkGraph:
    def __init__(self):
        self.graph = nx.Graph()

    def add_node(self, node_id, label):
        self.graph.add_node(node_id, label=label)

    def add_link(self, node1_id, node2_id, label, bandwidth, delay):
        self.graph.add_edge(node1_id, node2_id, label=label, bandwidth=bandwidth, delay=delay)

    def draw(self):
        # リンクの帯域幅に基づいて線の太さを決定する関数
        def get_edge_width(bandwidth):
            return np.log10(bandwidth) + 1  # bps単位での対数スケール

        # リンクの遅延に基づいて線の色を決定する関数
        def get_edge_color(delay):
            if delay <= 0.001:  # 1ms以下
                return 'green'
            elif delay <= 0.01:  # 1-10ms
                return 'yellow'
            else:  # 10ms以上
                return 'red'

        pos = nx.spring_layout(self.graph)
        edge_widths = [get_edge_width(self.graph[u][v]['bandwidth']) for u, v in self.graph.edges()]
        edge_colors = [get_edge_color(self.graph[u][v]['delay']) for u, v in self.graph.edges()]

        nx.draw(self.graph, pos, with_labels=False, node_color='lightblue', node_size=2000, width=edge_widths, edge_color=edge_colors)
        nx.draw_networkx_labels(self.graph, pos, labels=nx.get_node_attributes(self.graph, 'label'))
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=nx.get_edge_attributes(self.graph, 'label'))
        plt.show()
