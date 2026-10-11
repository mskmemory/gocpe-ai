# gocpe-ai

SBOMのパッケージ名・ベンダー名からAIでCPE/PURL候補を推論し、NVD/OSVの根拠とともに提示するツール。

GoのHTTP API基盤とPostgreSQLの永続化層・番号付きマイグレーションを実装しています。DATABASE_URLを設定するとAPIからPostgreSQLへ接続します。HTTPと実DBの統合テストを追加しています。外部AI4社のアダプターは実装済みです。実推論ワーカーとNVD/OSVクライアントは未接続のため、新規推論受付は503を返します。辞書検索・既存ジョブの取得とキャンセルはDB接続時に利用できます。

- [基本設計](docs/design.md)：処理フロー、検証状態、AI連携、実装計画
- [API設計](docs/api-design.md) / [OpenAPI定義](api/openapi.json)
- [API実装・起動・DB接続契約](docs/api-implementation.md)
- [DB実装・接続手順](docs/db-integration.md)
- [DB設計](docs/database-design.md) / [PostgreSQL DDL](db/schema.sql)
- [外部AI実装・ワーカー接続契約](docs/provider-implementation.md)
- [共通AI開発ルール](AGENTS.md)
- 実装言語：Go（確定）
- 初期構成案：HTTP API + ワーカー + PostgreSQL、共通サービス層を使うCLI
- 単体検索：`POST /v1/package-searches` にパッケージ名・ベンダー名を指定（SBOM不要）
- 入出力：CycloneDX/SPDX JSON、パッケージ配列、根拠付きJSON結果
- AI：OpenAI / Gemini / Claude / DeepSeekを設定で選択

CPEのNVD登録確認と、SBOM内のパッケージとの同一性判定は別に扱います。OSVは脆弱性データベースであり、照会結果が空でもPURLの不存在や安全性を意味しません。

開発用CIとローカル検証手順は [docs/ci.md](docs/ci.md) を参照してください。
