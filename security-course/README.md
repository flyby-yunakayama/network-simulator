# CONECOLAB Security Course Foundation

`security-course/` は、前作のネットワークシミュレータを踏まえた次期企画
**「Pythonで攻防しながら学ぶネットワークセキュリティ」**の開発・執筆基盤です。

現段階では、次の一連の成果物をつないだ最小の垂直スライスとして、`SEC-04 ARPスプーフィングと中間者攻撃` を実装しています。

- 章仕様
- 決定的なインメモリシミュレータ
- 正常系・攻撃系・防御系テスト
- Colab用Notebook
- 書籍原稿の初稿
- 出典カタログ
- 仕様から成果物への追跡表
- AIエージェント向け作業規約とCI

## 安全境界

このサブプロジェクトは**実ネットワークへ一切送信しないシミュレータ専用教材**です。

`socket`、raw packet、Scapy、OSのARPキャッシュ操作、外部ホストへの接続は使用しません。攻撃・検知・防御はすべてPythonオブジェクトの状態遷移として表現します。実環境向けの攻撃ツールを作ることは、このプロジェクトの対象外です。

## すぐに試す

Python 3.11以上の環境で、次を実行します。

```bash
cd security-course
python -m pip install -e ".[dev]"
python examples/arp_spoofing.py --mode compare
```

イベント列も表示する場合は次の通りです。

```bash
python examples/arp_spoofing.py --mode compare --events
```

防御なしでは、被害端末とゲートウェイのARPキャッシュが攻撃者のMACアドレスへ更新され、攻撃者が攻撃後のメッセージを観測します。攻撃者はデータを本来の宛先へ中継するため、サービスは継続します。

防御ありでは、信頼済みのIP–MAC対応と矛盾する更新を拒否し、攻撃者はメッセージを観測できません。同時に、競合検知センサーは防御の有無にかかわらず、不一致するARP主張を記録します。

## 検証

```bash
cd security-course
ruff check src tests examples scripts
ruff format --check src tests examples scripts
pytest
python scripts/validate_catalog.py
python scripts/validate_notebooks.py
python scripts/validate_references.py
python scripts/validate_traceability.py
```

`tests/test_safety_boundary.py` は、ランタイムパッケージが実ネットワークや外部プロセスを扱う代表的なモジュールをインポートしていないことも確認します。これは完全なセキュリティ証明ではありませんが、安全境界を破る変更を早期に検出するための機械的なガードです。

## ディレクトリ構成

```text
security-course/
├── catalog.json                 # 章ID・状態・成果物の機械可読な台帳
├── pyproject.toml               # 独立したPythonサブプロジェクト
├── src/conecolab_security/      # 共通シミュレータと公開API
├── tests/                       # 挙動・再現性・安全境界テスト
├── examples/                    # ターミナルから実行する短い例
├── notebooks/                   # Colab教材。出力は保存しない
├── specs/                       # 学習目標・要件・受入条件
├── manuscript/                  # 書籍原稿の正本
├── references/                  # 出典メタデータ
├── scripts/                     # 台帳とNotebookの検証
└── docs/                        # 企画・設計・執筆・追跡資料
```

## 前作との関係

前作は、`sec1` から `sec15a` まで章ごとの完成状態を複製し、学習者が段階的な差分を追える設計です。この方式は教材として有効ですが、次期企画を複数のAIエージェントで並行開発する場合、共通修正の反映漏れや原稿との不整合が起きやすくなります。

そこで次期企画では、次の二層を分けます。

1. **共通コア**：テスト可能なパッケージ、イベントモデル、指標、検知・防御インターフェース
2. **教材スナップショット**：Notebookと原稿で、その章までに見せるコードや差分

前作の `NetworkEventScheduler`、`Node`、`Switch`、`Router` との接続は将来のアダプタとして扱います。最初の原型は、前作へ横断的な変更を加えず、安全境界と教材制作フローを確立するため、独立した小さなモデルになっています。

## 成果物の正本

- 章の要件と受入条件：`specs/`
- 実行可能な挙動：`src/` と `tests/`
- 章の状態と成果物パス：`catalog.json`
- 書籍本文：`manuscript/`
- Colab実験：`notebooks/`
- 外部事実の根拠：`references/sources.json`
- 対応関係：`docs/TRACEABILITY.md`

同じ説明を複数の場所へコピーせず、それぞれの役割を守ります。たとえば、Notebookは実験手順、原稿は原理と解釈、テストは再現可能な事実を担当します。

## 現在の到達点

`SEC-04` では、次を実行できます。

1. 被害端末がARPリクエストでゲートウェイのMACアドレスを解決する
2. 正常なデータがゲートウェイへ直接届く
3. 攻撃者がゲートウェイと被害端末になりすました偽装ARPリプライを送る
4. 防御なしでは、双方のARPキャッシュが攻撃者のMACアドレスへ変わる
5. 攻撃者がデータを観測して本来の宛先へ中継する
6. センサーが一つのIPアドレスに対する複数MAC主張を検知する
7. 防御ありでは、信頼済みバインディングと矛盾する更新を拒否する
8. 攻撃成功、通信継続、検知数、拒否数を比較する

このモデルは、OS固有のARPキャッシュ、タイムアウト、スイッチの詳細、暗号化、複数セグメントを省略しています。教材本文では、必ず「このシミュレータで示したこと」と「現実の実装で追加確認が必要なこと」を分けます。

## 次に実装する候補

最初の基盤を固定した後は、次の順で小さな垂直スライスを追加します。

1. `SEC-02`：イベントログ、フローログ、ベースライン、指標の共通化
2. `SEC-03`：MACテーブル容量とMACフラッディング
3. `SEC-08`：半開き接続、SYN Flood、バックログ、防御
4. `SEC-14`：証明書検証を省略したTLSモデルと中間者状態

全体計画は `docs/PROJECT.md`、実装方針は `docs/ENGINEERING.md` を参照してください。
