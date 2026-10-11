# NVD・OSV 外部照合と全件同期

2026-10-11。HTTPクライアント、照合サービス、永続化契約は `internal/nvd`、`internal/osv`、`internal/resolve`、`internal/store`。実推論ワーカーはここで定義する `resolve.External` を呼び、対象ごとの `store.TargetResult` と新規 `store.Evidence` を `store.Queue.CompleteComponent` に渡す。DBコネクションを保持したまま外部通信をしてはならない。

```go
external := resolve.External{NVD: nvd.New(nvd.Config{APIKey: os.Getenv("NVD_API_KEY")}),
    OSV: osv.New(osv.Config{}), Dictionary: repository}
cpe, err := external.CPE(ctx, nvd.Query{Keyword: component.Name}, component.ExistingCPE)
purl, err := external.PURL(ctx, component.ExistingPURL)
// すべての要求targetとEvidenceをまとめてCompleteComponentへ渡す。
```

CPE APIの `cpeName` を登録済みCPEとして保存し、`cpeMatchString` は検索条件に限定する。登録の有無と入力CPEとの完全一致を分ける。照合はescape-aware CPE parserで全属性を比較する。deprecated CPEは元レコードとして残し、`deprecatedBy`にあるUUIDを別リクエストで取得・保存・提示する。置換を自動選択しない。検索候補からバージョンを補完しない。

OSV照会は既知のecosystemだけを受ける。PURL照会はpackage-level同一性を見るため、version・qualifiers・subpathを照会用PURLから除く。元のPURLと実際のリクエスト、確認できたtype/namespace/name、未確認のversion/qualifiers/subpathを根拠に残す。トップレベルversionはバージョンなしPURLと組み合わせ、バージョン付きPURLには設定しない。照合APIで返った`vulns[]`全レコードをaffected照合の前に`UpsertOSV`へ保存し、別途全件同期では公式dumpの全レコードを取り込む。NVD照合でも各検索ページの全CPEレコードを`UpsertCPE`へ保存してから入力との一致を判定する。OSVの全ページを追い、同一 `affected[]` 要素のpackage metadataとPURLを検証する。空応答は `no_evidence` であり、PURL不存在や安全性を示さない。withdrawnを含め全レコードは辞書に保存するが、withdrawn単独では候補を確認しない。

照会結果の全ページには予算設定がある。`MaxPages`到達、HTTP障害、無効な応答、contextキャンセルは`Complete=false`となり、理由コードでページ上限と障害を区別する。NVD/OSV外部I/OはcontextとHTTP timeoutを用い、429/5xx/通信失敗にだけ最大回数のリトライを行う。`Retry-After`を尊重する。NVDキーは任意。未設定時はヘッダーなし、設定時は`apiKey`ヘッダーを使用する。ログへキーや応答内容を出さない。

## 全件データ同期

全件同期は明示実行する別CLIである。APIサーバー起動時には走らない。NVDの登録CPE・CVE・CPE Match Criteria・CVE変更履歴・source assignersを取得する。CPEは既存 `Dictionary.UpsertCPE`、残りは新設 `SyncStore.UpsertSourceRecord`に全レコードのraw JSONを格納する。OSVは公式のglobal `all.zip`をstreamingで読み、全ecosystem、withdrawn、未対応ecosystemを含めて既存 `UpsertOSV`へ渡す。archive pathからファイルを展開しない。

履歴APIは開始・終了期間が必要なので119日窓で2002年から取得し、各窓をページングする。NVDのoffsetページは固定スナップショットではない。同期中にtotalが変化した場合は同期を失敗扱いにし、同じストリームの次回実行でページを先頭から再走査する。完了watermarkは取得開始時刻であり、外部APIの一括snapshotを保証するものではない。次回同期で最新全件を再走査する。OSVの再開位置はarchive SHA-256とZIP entry indexに結び付け、アーカイブが置換された場合は先頭から読み直す。レコードUPSERTはsource modified timeで古い応答を拒否する。

```sh
# DB migrationを先に適用し、全データを同期する（NVDはキー任意）
DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/DB?sslmode=disable' go run ./cmd/gocpe-sync -migrate -source all -stream all -osv-archive /data/osv-all.zip -download-osv -timeout 72h
# APIキーを使う場合は同じコマンドに環境変数を追加する:
NVD_API_KEY='your-key' DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/DB?sslmode=disable' go run ./cmd/gocpe-sync -source nvd -stream all -timeout 72h

# 既に取得したOSV archiveで再開・再実行
DATABASE_URL='...' go run ./cmd/gocpe-sync -source osv -osv-archive /data/osv-all.zip

# まず小さな範囲で動作確認。上限到達時は同期状態をfailedのまま残し、同じコマンドで再開する。
DATABASE_URL='...' go run ./cmd/gocpe-sync -source nvd -stream cve -max-pages 2
```

APIキーなしのNVDは低い公開レート制限に合わせ、既定で6秒の呼出間隔を設ける。キーありでも同じ間隔を使う保守的な初期値である。実際の全件同期は長時間かつ大量の通信・DB容量を必要とする。本変更の検証では全データ同期自体は実行していない。

## 検証

```sh
go test ./...
go vet ./...
./db/test-postgres.sh
# 外部実サービスへの通信は通常CIには含まれない。明示実行時のみ:
GOCPE_LIVE_EXTERNAL=1 go test -count=1 ./internal/nvd ./internal/osv -run Live
```

外部HTTPテストは `httptest.Server` で実際のrequest body/header・ページング・429/5xx・Retry-After・timeout・キャンセル・異常JSONを確認する。PostgreSQLテストは一時schemaにmigrationを適用し、同期resume、辞書のupsert/search、withdrawn/raw record、ジョブ結果・根拠を検証する。

仕様参照（公式）：[NVD Product APIs](https://nvd.nist.gov/developers/products)、[NVD Vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities)、[NVD Data Sources API schema](https://csrc.nist.gov/schema/nvd/api/2.0/source_api_json_2.0.schema)、[OSV Query API](https://google.github.io/osv.dev/post-v1-query/)、[OSV data dumps](https://google.github.io/osv.dev/data/)、[Package URL specification](https://github.com/package-url/purl-spec)。
