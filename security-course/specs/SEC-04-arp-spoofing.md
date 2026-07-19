# SEC-04 ARPスプーフィングと中間者攻撃 — 章仕様

## 1. メタデータ

- 章ID：`SEC-04`
- 状態：`prototype`
- 対応する前作章：第8章「アドレスの問い合わせ」
- 最終更新：2026-07-19
- 安全区分：`S1`（閉じたインメモリ状態遷移）
- 実装正本：`src/conecolab_security/arp_lab.py`

## 2. 章の問い

ARPで受け取ったIPアドレスとMACアドレスの対応を無条件に信頼すると、通信経路はどのように変わり、検知と防御はそれぞれ何を解決するのでしょうか。

## 3. 学習目標

- `SEC04-LO-01`：正常なARP解決とARPキャッシュ更新を、イベント列を使って説明できる。
- `SEC04-LO-02`：偽装ARP主張が受理され、中継位置が成立する条件を説明できる。
- `SEC04-LO-03`：競合検知と信頼済みバインディングによる更新拒否を、役割と結果の違いから比較できる。

## 4. 前提知識

- Pythonの関数、クラス、辞書、タプルを読める。
- MACアドレスとIPアドレスの役割を区別できる。
- ブロードキャストとARPリクエスト／リプライの概念を知っている。
- 前作第8章の受講は推奨するが、章内で正常系を復習する。

## 5. 安全境界

- すべてのホスト、ARPメッセージ、データフレームはPythonオブジェクトである。
- 実ネットワーク、OSのARPキャッシュ、raw socket、Scapy、外部ホストを使用しない。
- IPアドレス、MACアドレス、ペイロードは教材用の架空値である。
- 学習者の演習は、ポリシー、イベント、シナリオ設定の変更に限定する。
- 実環境でARPスプーフィングを実施する手順やツール操作は扱わない。

## 6. 正常系

### 6.1 トポロジ

同一のインメモリLANに三台を置きます。

| 役割 | 名前 | IP | MAC | forwarding |
|---|---|---|---|---:|
| 被害端末 | `victim` | `10.0.0.10` | `02:00:00:00:00:10` | false |
| ゲートウェイ | `gateway` | `10.0.0.1` | `02:00:00:00:00:01` | false |
| 攻撃者役 | `attacker` | `10.0.0.66` | `02:00:00:00:00:66` | true |

### 6.2 正常なイベント列

1. 被害端末がゲートウェイIPのMACアドレスを解決する。
2. 被害端末がARPリクエストをブロードキャストする。
3. 各ホストが送信者の主張を観測し、対象であるゲートウェイがリプライする。
4. 被害端末がゲートウェイの正規対応をARPキャッシュへ保存する。
5. `baseline-message` がゲートウェイへ直接配送される。

### 6.3 正常系の成功定義

`baseline_delivered is True` かつ、ゲートウェイの受信ペイロードに `baseline-message` が含まれること。

## 7. 脅威モデル

### 7.1 守る資産

- 被害端末とゲートウェイ間の通信経路の完全性
- データ内容の機密性
- 通信サービスの可用性
- ARPキャッシュのIP–MAC対応の正当性

### 7.2 攻撃者の能力

- 同一のインメモリLAN上に存在する。
- 被害端末とゲートウェイ宛てのARPリプライを作れる。
- リプライの送信元IPを相手側のIP、送信元MACを自分のMACとして主張できる。
- 自分宛てに届いたデータを観測し、正規の宛先へ中継できる。

### 7.3 攻撃者に与えない能力

- 実ネットワークへの送信や受信。
- 暗号化された内容の復号。
- OS、スイッチ、ルータの設定変更。
- LAN外からの到達、ルーティング、無線環境への干渉。
- 任意コード実行、認証情報取得、永続化。

### 7.4 攻撃成立条件

この教材モデルでは、次がそろうと攻撃が成立します。

1. 被害端末とゲートウェイが、受信した送信者主張をキャッシュ更新候補として扱う。
2. 更新ポリシーが偽装主張を拒否しない。
3. 攻撃者のMACアドレス宛てにデータフレームを配送できる。
4. 攻撃者が正規宛先のMACアドレスを知り、中継を有効にしている。

## 8. 機能要件

- `SEC04-FR-01`：被害端末はARPリクエストと正規リプライにより、ゲートウェイのMACアドレスを解決できる。
- `SEC04-FR-02`：攻撃者は、ゲートウェイになりすます主張を被害端末へ、被害端末になりすます主張をゲートウェイへ送信できる。
- `SEC04-FR-03`：防御なしでは、双方のARPキャッシュが攻撃者MACへ更新され、攻撃後データを攻撃者が観測して正規宛先へ中継できる。
- `SEC04-FR-04`：検知器は、一つのIPアドレスに複数のMACアドレスが主張された場合に、重複しない競合アラートを生成する。
- `SEC04-FR-05`：防御ありでは、信頼済みIP–MAC対応と矛盾する主張を拒否し、正規対応を維持する。
- `SEC04-FR-06`：結果は、防御条件、正常系成功、攻撃成功、攻撃後可用性、検知数、拒否数、最終キャッシュ、観測ペイロード、イベント列を返す。

## 9. 非機能要件

- `SEC04-NFR-01`：同じ引数で実行した二回の結果は、要約とイベント列が一致する。
- `SEC04-NFR-02`：ランタイムは実ネットワーク、外部プロセス、OS設定へアクセスしない。
- `SEC04-NFR-03`：Notebookと原稿は `run_arp_poisoning_scenario`、`compare_defense`、`ScenarioResult` の公開APIだけに依存する。
- `SEC04-NFR-04`：Python 3.11以上とGoogle Colabで、外部サービスの認証なしに実行できる。
- `SEC04-NFR-05`：重要な状態変更を順序付きイベントとして観測できる。

## 10. イベント

| kind | actor | 必須data | 意味 |
|---|---|---|---|
| `topology.host.added` | host | IP、MAC、forwarding | ホストをシミュレータへ登録した |
| `phase.started` | scenario | phase | 測定フェーズを開始した |
| `arp.sent` | host | operation、sender、target | ARPメッセージを送信した |
| `arp.received` | host | operation、sender、target | ARPメッセージを受信した |
| `arp.cache.updated` | host | sender IP/MAC、previous | キャッシュ対応が変化した |
| `arp.cache.rejected` | host | sender IP/MAC、reason | 防御が更新を拒否した |
| `detector.alert` | detector | IP、観測MAC集合 | 競合主張を検知した |
| `attack.started` | attacker | victim、gateway | 攻撃フェーズを開始した |
| `attack.completed` | attacker | 二つの偽装主張 | 偽装リプライ送信を完了した |
| `data.sent` | host | source/destination、payload、hop | データを送った |
| `data.intercepted` | attacker | destination、payload、hop | 中継位置で観測した |
| `data.forwarded` | attacker | next MAC、payload、hop | 正規宛先へ中継した |
| `data.delivered` | destination | source、payload、hop | 最終宛先へ届いた |
| `data.dropped` | actor | reason | 配送できなかった |

## 11. 指標

| 指標 | 定義 | 型・単位 | 対象フェーズ | 注意点 |
|---|---|---|---|---|
| `baseline_delivered` | 正常系のペイロードがゲートウェイへ届いた | bool | baseline | 正常系成立の前提 |
| `attack_succeeded` | 攻撃後ペイロードを攻撃者が観測した | bool | post-attack | 実環境一般の成功率ではない |
| `service_available_after_attack` | 攻撃後ペイロードがゲートウェイへ届いた | bool | post-attack | 中継による可用性だけを表す |
| `detection_alerts` | 重複抑止後の競合アラート数 | count | 全フェーズ | 真陽性・偽陽性率ではない |
| `rejected_arp_updates` | 防御ポリシーが拒否した更新数 | count | attack | 受理済み更新の取消しは扱わない |
| 最終ARP対応 | 双方が相手IPへ保持するMAC | MAC | 終了時 | キャッシュ期限を扱わない |

## 12. 公開API

```python
from conecolab_security import compare_defense, run_arp_poisoning_scenario

unprotected = run_arp_poisoning_scenario(defense_enabled=False)
protected = run_arp_poisoning_scenario(defense_enabled=True)
unprotected, protected = compare_defense()

unprotected.summary()
unprotected.event_rows()
```

公開結果のフィールド削除・意味変更は、Notebookと原稿を壊す変更として扱います。

## 13. 受入条件

- `SEC04-AC-01`：防御なしで実行すると、正常系が成功し、双方の相手IPに対するARPキャッシュが攻撃者MACへ変わり、攻撃者が `after-poisoning` を観測する。
- `SEC04-AC-02`：防御ありで実行すると、偽装主張を二件拒否し、双方の正規対応を維持し、攻撃者は `after-poisoning` を観測しない。
- `SEC04-AC-03`：防御なし・ありの両方で、`baseline-message` と `after-poisoning` がゲートウェイへ届く。
- `SEC04-AC-04`：防御なし・ありの両方で、被害端末IPとゲートウェイIPの競合に対応するアラートを合計二件生成する。
- `SEC04-AC-05`：二回の同条件実行で、イベント列が完全一致し、sequenceは1から連続する。
- `SEC04-AC-06`：ランタイムパッケージは、禁止された実ネットワーク・外部プロセス関連モジュールをimportしない。
- `SEC04-AC-07`：Notebookは出力と実行回数を保存せず、仕様・原稿・テストの成果物パスが台帳と一致する。

## 14. テスト計画

| 受入条件 | テスト | 確認内容 |
|---|---|---|
| AC-01 | `test_unprotected_host_is_poisoned_but_service_remains_available` | 攻撃成功、最終キャッシュ、中継、検知 |
| AC-02 | `test_static_binding_guard_rejects_both_forged_claims` | 二件拒否、正規対応維持、非観測 |
| AC-03 | 上記二テスト | 正常系と攻撃後の配送 |
| AC-04 | 上記二テスト | アラート数 |
| AC-05 | `test_timeline_is_deterministic_and_sequence_numbers_are_contiguous` | 再現性とイベント種別 |
| AC-06 | `test_runtime_package_has_no_real_network_or_process_primitives` | 禁止import |
| AC-07 | `validate_catalog.py`, `validate_notebooks.py` | 成果物とNotebook構造 |

## 15. Notebook構成

1. 学習目標と安全境界
2. セットアップ
3. 防御なし・ありの一括実行
4. 要約比較
5. 攻撃前後のARPキャッシュ確認
6. 競合アラートと拒否イベントのタイムライン
7. 検知と防御の役割整理
8. ポリシー変更演習
9. 現実との差

## 16. 原稿構成

- 問いと学習目標
- ARPの正常動作
- 信頼前提と攻撃成立条件
- 閉じたモデルのトポロジ
- 防御なしの結果
- 競合検知
- 静的バインディング防御
- 比較と可用性の解釈
- 現実との差
- まとめと演習

## 17. 現実との差・省略点

- ARPメッセージの全フィールド、フレーム形式、タイミングを再現しない。
- キャッシュ期限、更新規則、OS差、gratuitous ARPの正当用途を詳細には扱わない。
- スイッチの転送表、VLAN、無線、複数セグメントを扱わない。
- 暗号化とアプリケーション層の相手認証を扱わない。
- 静的バインディングは、製品のDynamic ARP Inspectionを完全実装したものではない。
- 競合検知は、実環境の誤検知、観測欠落、センサー配置を評価していない。
- 同期配送のため、競合、遅延、パケット損失を扱わない。

したがって、結果は「この信頼前提と防御不変条件を理解する」ためのものです。実環境へ性能や検知率を一般化しません。

## 18. 出典

- `[RFC-0826]`：ARPの基本形式と目的。
- `[RFC-5227]`：IPv4アドレス競合検知とARP主張の背景。
- `[MITRE-T1557-002]`：ARP Cache Poisoningを中間者技法として整理する根拠。
- `[MITRE-DET0387]`：ARP主張の不一致を監視する検知観点。
- `[NIST-SP-800-115]`：安全なテスト計画、実施、分析、報告の一般的な枠組み。

## 19. 未決事項

- 前作 `sec8b` と接続するアダプタをSEC-01/SEC-02後に作るか。
- 書籍版でコードをどこまで全文掲載し、どこからGitHub参照にするか。
- 公開版Notebookをタグ固定にするか、既定ブランチ追従にするか。
