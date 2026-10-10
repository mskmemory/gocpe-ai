# gocpe-ai

SBOMのパッケージ名・ベンダー名からAIでCPE/PURL候補を推論し、NVD/OSVの根拠とともに提示するツール。

現在は設計段階です。実装・実APIによる動作検証はまだ行っていません。

- [基本設計](docs/design.md)：処理フロー、検証状態、AI連携、実装計画
- [API設計](docs/api-design.md) / [OpenAPI定義](api/openapi.json)
- [DB設計](docs/database-design.md) / [PostgreSQL DDL](db/schema.sql)
- [共通AI開発ルール](AGENTS.md)
- 実装言語：Go（確定）
- 初期構成案：HTTP API + ワーカー + PostgreSQL、共通サービス層を使うCLI
- 単体検索：`POST /v1/package-searches` にパッケージ名・ベンダー名を指定（SBOM不要）
- 入出力：CycloneDX/SPDX JSON、パッケージ配列、根拠付きJSON結果
- AI：OpenAI / Gemini / Claude / DeepSeekを設定で選択

CPEのNVD登録確認と、SBOM内のパッケージとの同一性判定は別に扱います。OSVは脆弱性データベースであり、照会結果が空でもPURLの不存在や安全性を意味しません。
