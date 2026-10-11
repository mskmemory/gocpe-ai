# gocpe-ai

SBOMのパッケージ名・ベンダー名からAIでCPE/PURL候補を推論し、NVD/OSVの根拠とともに提示するツール。

GoのHTTP API基盤とPostgreSQLの永続化層・番号付きマイグレーションを実装しています。DATABASE_URLを設定するとAPIからPostgreSQLへ接続します。HTTPと実DBの統合テストを追加しています。外部AI4社のアダプターは実装済みです。実推論ワーカーとNVD/OSVクライアントは未接続のため、新規推論受付は503を返します。辞書検索・既存ジョブの取得とキャンセルはDB接続時に利用できます。

- [基本設計](docs/design.md)：処理フロー、検証状態、AI連携、実装計画
- [Jev拡張仕様](docs/jev-design.md)：TypeSafe AIによる候補評価・順位付けの導入計画（未実装）
- [判断用AIの比較・共通仕様](docs/decision-ai-comparison.md)：Jev / Solar Decide / Drex / Laya / Kevの機能・用途・交換可能な評価設計（未実装）
- 大規模辞書：検索で候補を絞ってAI評価し、検索・候補削減の取りこぼしも検証する（上記共通仕様の第8節）
- [API設計](docs/api-design.md) / [OpenAPI定義](api/openapi.json)
- [API実装・起動・DB接続契約](docs/api-implementation.md)
- [DB実装・接続手順](docs/db-integration.md)
- [DB設計](docs/database-design.md) / [PostgreSQL DDL](db/schema.sql)
- [外部AI実装・ワーカー接続契約](docs/provider-implementation.md)
- [共通AI開発ルール](AGENTS.md)
- [類似検索API 試作](cmd/fuzzy-search-api/main.go)：ローカル辞書に対するtrigram/Levenshtein検索
- 実装言語：Go（確定）
- 初期構成案：HTTP API + ワーカー + PostgreSQL、共通サービス層を使うCLI
- 単体検索：`POST /v1/package-searches` にパッケージ名・ベンダー名を指定（SBOM不要）
- 入出力：CycloneDX/SPDX JSON、パッケージ配列、根拠付きJSON結果
- AI：OpenAI / Gemini / Claude / DeepSeekを設定で選択

CPEのNVD登録確認と、SBOM内のパッケージとの同一性判定は別に扱います。OSVは脆弱性データベースであり、照会結果が空でもPURLの不存在や安全性を意味しません。

## 類似検索APIの試作

この実験用APIはJSON形式のローカル辞書を読み込み、名前のtrigram類似度とRune単位のLevenshtein距離で候補を返します。辞書レコードには`id`, `identifier`, `name`が必要で、CPEは任意の`vendor`、PURLは任意の`vendor`と`ecosystem`を指定できます。例は合成データです。

```sh
SEARCH_API_TOKEN=dev-token go run ./cmd/fuzzy-search-api \
  -cpes testdata/fuzzy-search/cpes.json \
  -purls testdata/fuzzy-search/purls.json
```

```sh
curl -s http://127.0.0.1:8080/v1/search/purls \
  -H 'Authorization: Bearer dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"query":"log4j-cor","ecosystem":"Maven","limit":10}'
```

`rank_score`は試作用にtrigram類似度と編集距離から得た類似度を50%ずつ合成します。閾値・重みは正解データで調整していません。返却候補は検索用であり、識別子の同一性・NVD/OSV確認・採用判定を意味しません。試作はメモリに辞書全体をロードし、各レコードとの編集距離を計算します。実運用の数十万件規模ではDB索引等の性能評価が必要です。Go標準ライブラリだけを使うためUnicode NFC正規化は未対応です。

開発用CIとローカル検証手順は [docs/ci.md](docs/ci.md) を参照してください。
