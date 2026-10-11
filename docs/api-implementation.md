# API基盤の実装とDB接続契約

2026-10-11 / このブランチの実装範囲

## 実装済み

- Go net/httpによるOpenAPIの8操作、単体検索・SBOM・パッケージ配列の受付。
- サービス層、入出力型、ストレージ・認証インターフェース。
- Bearer認証、読み取り/書き込み権限、所有者チェック、期限、キャンセル。
- サイズ・深さ・重複JSONキー・未知フィールド・対応SBOM版・CPE/PURLの検証。
- 名前/ベンダー検索の既定値と共通ジョブへの変換。
- 改ざん・別所有者・別ジョブ・別検索条件で利用できない期限付きカーソル。
- fakeストレージによるHTTP/サービス層テスト、OpenAPI定義・例・スキーマハッシュ検査。

## 未接続の機能

PostgreSQLの接続アダプターはinternal/apistoreに実装済み。実推論ワーカーは未実装。AI4社の実通信は独立パッケージに実装済み（[接続契約](provider-implementation.md)）。API起動コマンドには未接続。NVD・OSVの実通信はこのAPI担当範囲外。`cmd/gocpe-api` はDATABASE_URL設定時にPostgreSQLへ接続し、未設定時はUnavailableStoreを使用する。`/v1/providers` のitemsは空で、新規推論受付は503を返す。DB接続時には辞書検索、既存ジョブ照会、キャンセル、結果取得が可能。fakeはテスト専用で、サーバー実行時には組み込まない。

## 起動・検証

Go 1.25以上を使用する。環境変数は `.env.example` の名前と形式を参照し、実行前に設定する。

```sh
go run ./cmd/gocpe-api -listen 127.0.0.1:8080
go test ./...
go vet ./...
go test -race ./...
```

`GOCPE_API_TOKENS` は秘密トークンからowner IDへのJSONマップ。トークンは32バイト以上。`GOCPE_CURSOR_KEY` は32バイト以上の独立した秘密値。アプリ認証とAI APIキーは別物。公開運用ではHTTPSを終端する。

`httpapi.NewStaticAuth` のPrincipalでRead/Writeを設定できる。起動コマンドのトークンはRead/Write両方を許可する。別の認証方式はAuthenticatorインターフェースで追加する。

通常テストは外部通信もDBも不要。初回の依存取得はネットワークが必要。テスト内の完了状態はfixtureで設定しており、実推論を実行したことを意味しない。

## PostgreSQL担当との接続点

正の契約は `internal/service/store.go` のStore、Admission、Component、PageQuery、CPEQuery、PURLQuery。レスポンス型はmodels.go。DB側でAPIのSQL実装を重複させず、このインターフェースを実装するアダプターを追加する。

| 操作 | 実装要件 |
|---|---|
| Admit | 入力・ジョブ・コンポーネント・冪等キーを一トランザクションで保存。owner+keyの競合を直列化。同じhashは元のStoredJobを返す |
| GetJob | owner、UUID、expires_at > nowで取得。別主体・期限切れもErrNotFound |
| Cancel | ownerと期限を検査し、行ロックで状態更新。queued→cancelled、running→cancelling、cancellingは冪等。終端は不変 |
| Results | ownerと期限を再検査。Afterは末尾ordinalの10進文字列、空なら先頭。昇順でLimit件まで |
| CPEs | Afterは末尾cpe_name_id。フィルターはAND、Deprecatedは等値条件。UUID昇順でLimit件まで |
| PURLs | Afterは末尾内部UUID。非withdrawnのOSV関連があるものに限定。UUID昇順でLimit件まで |

DBエラーはErrNotFound / ErrConflict / ErrUnavailable / ErrRateLimitedへ変換する。想定外のエラーは外部に内容を出さず500になる。ストアは返却値を独立した値として返し、共有メモリーを返さない。

ページ取得はAPI側がLimit+1を渡す。cursor文字列自体をDBで解釈せず、検証済みAfterだけを使う。SQLは必ずパラメーター化する。応答JSONの必須配列はnilではなく空配列にし、PURL.qualifiersは空オブジェクトにする。構造がOpenAPIと一致しないDB応答はHTTP層で500にする。

Admission.InputDocumentは受信JSONの原文、Components.RawValuesは各入力成分、SourcePointerは元JSON位置。単体検索ではsource_pointerは空、入力内component IDはcomponent-1。Optionsには既定値が適用済み、RequestHashには入口と既定値適用前の正規化JSONが含まれる。オブジェクトキー順は無視し、配列順と数値の表記は保持する。

Store.Admitは新規ジョブを受付する前にワーカーの稼働可否と同時ジョブ数を検査する。同じキーの再送はワーカー停止中でも既存ジョブを返す。認証・入力検証・モデル許可検査は再送でも実施する。API層は推論ワーカーのlease処理を実装しない。

Cancelのboolは「要求を受理したか」。queuedから即時cancelledに変わった場合もtrueで202、すでに終端ならfalseで200。更新時刻とfinished_atはDB側が設定する。

Service.Config.Providersは実行可能なプロバイダー/モデルだけを設定する。APIキーやモデルの存在だけで実行可能と扱わない。DBとワーカーの準備ができたら、cmdのUnavailableStoreを実ストアに差し替え、Providersを接続する。

## 依存とスキーマ

- kin-openapi：OpenAPI定義と例・入出力の検証。
- santhosh-tekuri/jsonschema：公式CycloneDX/SPDXスキーマによる検証。
- go-cpe：CPEのエスケープを理解した解析とSPDX CPE URIからの変換。
- packageurl-go：PURLの構文解析。

バージョンはgo.mod/go.sumで固定。公式SBOMスキーマと必要な参照先をapi/schemasに同梱し、schema loaderは外部アクセスを禁止する。1.5と1.6のライセンス一覧は各版に対応したリソースを使う。取得元・SHA-256はmanifest.json、ライセンスは同ディレクトリに保存。

SBOMはschema検証後にmetadata.component、ネストしたcomponents、SPDX packagesを抽出する。supplier/originator等の原文はRawValuesに残し、ベンダー名をnamespaceに代入しない。追加の正規化・ベンダー役割の判定は推論側で行う。

## 検証結果

このブランチで `go test ./...`、`go vet ./...`、`go test -race ./...` と起動コマンドのビルドを実施。実サーバーのローカル起動でもproviders=200、未認証=401、未接続辞書=503、SIGTERMによる正常終了を確認した。実DB・実AI・NVD・OSVへの接続検証は未実施。

## APIと実DBの統合検証

```sh
DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' go run ./cmd/gocpe-api -migrate
# 専用テストDBのみを指定する。テストごとに独立schemaを作成・削除する。
CI_REQUIRE_DB_TESTS=1 TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST/TEST_DB' go test -race -count=1 ./...
```

-migrateは明示的に番号付きmigrationを適用する。指定しない場合、起動前にDBのmigration状態を確認し、未適用なら起動に失敗する。

HTTPテストはhttptest.Serverの実ソケットを介してPostgreSQLにアクセスする。単体検索、パッケージ配列、CycloneDX SBOM、同時冪等性、所有者分離、queued/runningキャンセル、期限切れ、結果/根拠取得、201件の辞書ページング、withdrawn除外、入力不正時の保存防止、DB停止時の503を検証する。結果生成にはテスト専用の外部記録fixtureをDBワーカー契約で保存する。外部AIの実推論を実行した検証ではない。

internal/apistoreはAPIのlimit+1取得をDBの最大200件に合わせて分割し、DBエラー・型・nil配列を公開契約へ変換する。ワーカー未準備時は新規受付を拒否するが冪等再送は維持する。キャンセルの受理フラグはDB行ロック下で判定する。
