# 要件・実装・教材の追跡表

## 1. 目的

この表は、学習目標と要件が、コードだけでなくテスト、Colab、書籍原稿まで反映されていることを確認するための正本です。章を変更するPRは、関連する行を同じPRで更新します。

## 2. 記号

- **実装済み**：成果物が存在し、テストで確認できる。
- **説明済み**：Notebookまたは原稿に、学習者向けの説明がある。
- **未着手**：台帳にはあるが、仕様・成果物がまだない。

## 3. SEC-04 ARPスプーフィング

| ID | 要件・学習目標 | 実装 | テスト | Colab | 原稿 | 状態 |
|---|---|---|---|---|---|---|
| SEC04-LO-01 | 正常なARP解決とキャッシュ更新をイベント列で説明する | `Host.send_arp_request`, `Host.receive_arp`, `Host.learn_arp` | `test_unprotected_host_is_poisoned_but_service_remains_available` | 「正常系を観測する」 | 「正常なARP解決」 | 実装済み |
| SEC04-LO-02 | 偽装ARP主張が受理される成立条件を説明する | `AcceptAllArpUpdates`, `ArpPoisoningAttack` | 防御なしシナリオ | 「防御なし」 | 「成立条件」 | 実装済み |
| SEC04-LO-03 | 検知と防御の違いを結果で比較する | `ArpConflictDetector`, `StaticBindingGuard` | 防御あり・比較テスト | 比較表 | 「検知と防御」 | 実装済み |
| SEC04-FR-01 | 被害端末がゲートウェイをARPで解決できる | `run_arp_poisoning_scenario` のbaseline | baseline assertion | baselineセル | 正常系の節 | 実装済み |
| SEC04-FR-02 | 攻撃者が双方へ偽装リプライを送れる | `ArpPoisoningAttack.execute` | attack success assertion | 攻撃セル | 攻撃モデルの節 | 実装済み |
| SEC04-FR-03 | 防御なしでは攻撃者が中継位置を得る | `Host.receive_data` のforwarding | intercepted payload assertion | 要約・イベント表 | 結果の解釈 | 実装済み |
| SEC04-FR-04 | 同一IPに複数MAC主張があればアラートを出す | `ArpConflictDetector.observe` | detection alert assertion | アラート確認 | 検知の節 | 実装済み |
| SEC04-FR-05 | 信頼済み対応と矛盾する更新を拒否する | `StaticBindingGuard.evaluate` | rejection and cache assertions | 防御ありセル | 防御の節 | 実装済み |
| SEC04-FR-06 | 攻撃成功、通信継続、検知数、拒否数を返す | `ScenarioResult` | summary assertions | 比較表 | 比較評価 | 実装済み |
| SEC04-NFR-01 | 同じ入力で同じイベント列を返す | `EventLog`, 決定的な同期配送 | deterministic test | 注記 | 再現性の注記 | 実装済み |
| SEC04-NFR-02 | 実ネットワーク機能を使わない | インメモリモデルのみ | `test_safety_boundary.py` | 冒頭警告 | 安全境界 | 実装済み |
| SEC04-NFR-03 | Notebookと原稿が安定結果APIを使う | `ScenarioResult.summary/event_rows` | compare order test | 公開APIのみ使用 | 値の出典を明記 | 実装済み |
| SEC04-NFR-04 | Python 3.11以上とColabで認証なしに実行できる | 標準ライブラリのみ、`pyproject.toml` | CIのPython行列、Notebook構造検査 | セットアップセル | 実行環境の注記 | 実装済み |
| SEC04-NFR-05 | 重要な状態変更を順序付きイベントで観測できる | `SecurityEvent`, `EventLog` | deterministic event test | タイムラインセル | 各結果節 | 実装済み |
| SEC04-AC-01 | 防御なしで双方のキャッシュが攻撃者MACになる | `run_arp_poisoning_scenario(False)` | 明示assertion | 結果表 | 結果表 | 実装済み |
| SEC04-AC-02 | 防御ありで正規対応を維持し、二件拒否する | `run_arp_poisoning_scenario(True)` | 明示assertion | 結果表 | 結果表 | 実装済み |
| SEC04-AC-03 | 両条件で正常系と攻撃後配送が成立する | relayまたは直接配送 | availability assertions | 比較表 | 可用性の解釈 | 実装済み |
| SEC04-AC-04 | 両条件で競合アラートを二件生成する | detector fingerprints | alert assertions | イベント表 | 検知の限界 | 実装済み |
| SEC04-AC-05 | 同条件でイベント列が一致し、sequenceが連続する | 決定的な同期配送 | deterministic event test | 同じAPIを使用 | 再現性の注記 | 実装済み |
| SEC04-AC-06 | 禁止された実ネットワーク・外部プロセスimportがない | インメモリ実装 | `test_safety_boundary.py` | 安全警告 | 安全な学習範囲 | 実装済み |
| SEC04-AC-07 | 台帳成果物が存在し、Notebookに出力を保存しない | 検証スクリプト | catalog / notebook validators | 出力なし | 原稿正本あり | 実装済み |

## 4. 外部根拠

| 主張 | source ID | 使用箇所 |
|---|---|---|
| ARPの基本的なアドレス解決形式 | `RFC-0826` | SEC-04仕様・原稿 |
| IPv4アドレス競合検知の背景 | `RFC-5227` | SEC-04原稿の現実との差 |
| ARP Cache Poisoningの脅威分類 | `MITRE-T1557-002` | SEC-04脅威モデル |
| ARP主張の不一致を用いた検知観点 | `MITRE-DET0387` | SEC-04検知節 |
| セキュリティテストの計画・実施・報告の一般原則 | `NIST-SP-800-115` | 全体の安全・評価方針 |

## 5. 章追加時の手順

1. 仕様のIDをこの表へ追加する。
2. 実装シンボルとテスト名を具体的に記す。
3. Notebookと原稿の節名を記す。
4. 外部事実はsource IDへ対応させる。
5. 未実装を「実装済み」としない。
6. 名前変更時は検索で参照漏れを確認する。

将来は、仕様IDをコード・Notebook・原稿へ機械可読な形で埋め込み、追跡表の一部を自動生成することを検討します。原型段階では、人間が読める表を正本とします。
