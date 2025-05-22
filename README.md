# network-simulator

このリポジトリは、Python で実装された簡易的なネットワークシミュレータです。ノードやリンクを組み合わせてネットワークを構築し、パケット転送や各種プロトコルの挙動を学習することを目的としています。

## 特長
- `networkx` を利用したトポロジの描画
- シンプルなシナリオから応用例までを含む `scenario*.py`
- イベント駆動型のシミュレーションを行う `NetworkEventScheduler`
- 解説用ノートブックを収録した `doc` ディレクトリ

## 必要なパッケージ
- Python 3
- networkx
- matplotlib
- numpy

## 使い方
1. 依存パッケージをインストールします。
   ```bash
   pip install networkx matplotlib numpy
   ```
2. 実行したいシナリオを指定して Python スクリプトを起動します。例として `scenario1.py` を実行する場合は次の通りです。
   ```bash
   python scenario1.py
   ```

各シナリオではノードの追加やリンクの帯域幅設定、パケット転送の様子を確認できます。複雑な動作を試したい場合は `scenario14a.py` なども参考にしてください。
