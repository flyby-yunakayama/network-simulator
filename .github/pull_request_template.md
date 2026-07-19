## 対象

- 章IDまたは基盤ID：
- 変更種別：`spec / code / test / notebook / manuscript / reference / infrastructure`

## 変更した学習体験

この変更によって、学習者が新しく観測・説明・実装・評価できることを書いてください。

## 成果物

- [ ] `catalog.json`
- [ ] 章仕様
- [ ] 実装
- [ ] テスト
- [ ] Colab Notebook
- [ ] 書籍原稿
- [ ] 出典台帳
- [ ] `docs/TRACEABILITY.md`

該当しない項目には理由を書いてください。

## 安全境界

- [ ] 攻撃は閉じたシミュレータ内の状態遷移だけである。
- [ ] 実ネットワーク、OS設定、外部プロセスへ触れない。
- [ ] 架空のアドレス・データだけを使う。
- [ ] 攻撃と対になる検知・防御・限界を説明した。
- [ ] 新しい依存の安全性とライセンスを確認した、または依存追加なし。

## 検証

```text
# 実行したコマンドと結果
```

- [ ] `ruff check src tests examples scripts`
- [ ] `ruff format --check src tests examples scripts`
- [ ] `pytest`
- [ ] `python scripts/validate_catalog.py`
- [ ] `python scripts/validate_notebooks.py`
- [ ] `python scripts/validate_references.py`
- [ ] `python scripts/validate_traceability.py`

## 出典・来歴

追加・変更したsource ID、前作から再利用したファイル、外部素材のライセンスを書いてください。

## 既知の省略点と後続課題

このPRでは意図的に扱わない現実の条件、互換性、次のIssueを書いてください。

## 著者判断が必要な事項

ライセンス、別リポジトリ化、販売条件、公開APIの大規模変更などがなければ「なし」と書いてください。
