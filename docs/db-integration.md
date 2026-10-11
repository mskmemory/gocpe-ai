# DB実装とAPI側との接続

2026-10-11 / DB担当ブランチ：codex/db-development

## 接続契約

共有型・インターフェースは `internal/store/store.go` に定義した。HTTP DTOではなく永続化契約のため、API側でOpenAPI形式に変換する。

```go
pool, err := postgres.OpenPool(ctx, os.Getenv("DATABASE_URL"))
if err != nil { return err }
defer pool.Close()
if err := db.Migrate(ctx, pool); err != nil { return err }
repository := postgres.New(pool, postgres.Config{})
// repository implements store.Dictionary, store.Jobs, store.Queue.
```

- API・サービス：store.Jobs（CreateJob / GetJob / CancelJob / ListResults）とstore.Dictionary。
- ワーカー：store.Queue。AcquireJobで得たLeaseをHeartbeat / NextComponents / CompleteComponent / AddUsage / FinishJobへ渡す。
- 定期保守：ReapExpired（deadline・再試行上限・キャンセル停止）、PurgeExpired（期限切れジョブと冪等キー）。
- Goモジュール：github.com/mskmemory/gocpe-ai、Go 1.25。API/CIブランチのgo.modが競合したら、同じmoduleを維持して依存を統合する。

NewJobはサービス層でSBOMや名前・ベンダーの入力を正規化した後に渡す。Requestはデフォルト適用前の受信JSON、Inputは保存する入力、Optionsは実効設定。provider/modelとOptionsの一致、許可モデル、SBOMスキーマ、入力サイズはAPI・サービス側で検証する。Componentsの並び順がordinalになる。

名前・ベンダー検索はEndpointPackageSearch、component-1、root source pointerの空文字を使う。既存resolutions受付はEndpointResolution。冪等キーは認証主体内で共有し、ハッシュにはendpointも含む。CreateJobのcreated=falseは202で元ジョブを返す。

## APIへマッピングする値

- store.ErrNotFound→404。ownerを必須で渡す。
- store.ErrInvalid→422（無効cursor等のHTTP入力はAPI側で400）。
- store.ErrIdempotencyConflict / ErrConflict→409。
- store.ErrNotReady→409 RESULTS_NOT_READY。
- ErrLeaseLost / ErrNoJobはワーカー用で公開HTTPエラーにしない。
- sentinelの判定はerrors.Isを使う。SQLエラー原文をクライアントに出さない。

Jobは公開JSON向けにstatus/options/progress/run_metadata等へ変換する。保存したErrorEntryにはrequest_idがなくpointerが直下にあるため、公開Errorのrequest_idとdetailsへAPI側で変換する。

ResultQueryは最初のページにAfterOrdinal=-1を指定する。ResultPage.HasMore=trueならNextAfterOrdinalを署名付きcursorに含める。辞書検索のNextAfterも同様に、API側で検索条件とともに署名する。保存層は公開cursorの署名・復号を担当しない。

候補のSelectedからselected_candidate_idsを作る。Evidence.Snapshotは監査用で、公開Evidenceには含めない。TargetResult.Evidenceは候補なしの照会根拠を含み、Lookup.EvidenceIDsと一致する。公開APIの現在のResultSetにはlookup根拠の詳細配列がないため、詳細を公開したい場合はAPI担当でOpenAPIへの追加を検討する。要求していないtargetは省略する。

## ワーカー側の注意

CompleteComponentは要求した全targetをまとめて保存する。外部I/Oは先に行い、結果と根拠を一トランザクションで確定する。Evidence.IDはstore.NewIDで事前生成し、Verification.EvidenceIDsに同一ジョブのIDを指定する。レスポンスハッシュは正規化JSONのSHA-256をDB層が計算する（明示値がある場合は一致を検証）。

confirmedには観測時刻と根拠が必要。acceptedには確認済み・strongの候補を1件だけSelectedにする。CPE/PURL構文と辞書ID・候補値の整合性も保存層で検証する。ただし「入力と同一の製品か」の業務評価は推論・判定層の責務。

期限切れleaseは古いworkerを拒否する。再取得時は新しいtokenとなり、doneコンポーネントは再処理しない。取消要求後は新規コンポーネント結果を書かず、FinishJobでcancelledに確定する。期限・試行上限での停止はReapExpiredを実行する。外部AIの二重呼出費用を防ぐexactly-once保証はない。

NextComponentsは同一leaseで未完了のrunningも返す。呼出側は一度返されたバッチの完了前に同じleaseで再取得しない。コンポーネント並列処理はバッチ内で行い、結果更新はjob行ロックで直列化する。

## マイグレーション

```sh
DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' go run ./db/cmd/migrate -action up
DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' go run ./db/cmd/migrate -action status
# データを削除する操作。明示的なロールバック時のみ実施する。
DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' go run ./db/cmd/migrate -action down -steps 1
```

初期DDLは000001。適用済みupファイルの改変はchecksumエラーとして拒否する。追加変更は000002以降を作り、db/schema.sqlも更新する。migration runnerはsession advisory lockで同時実行を直列化する。downも各migration単位のトランザクションで実行する。

## テスト

```sh
go test ./...
go vet ./...
# Dockerの一時PostgreSQL 16で全テストとrace検査。終了時にコンテナ削除。
./db/test-postgres.sh
# 既に用意したテスト専用DBを使う場合
TEST_DATABASE_URL='postgres://postgres@127.0.0.1:5432/TEST_DB?sslmode=disable' go test -race -count=1 ./...
```

TEST_DATABASE_URLがない場合、実DBテストはskipし、識別子・冪等ハッシュの単体テストを実行する。テストは独立schemaを作り、終了時にそのschemaのみ削除する。テスト用DBにはschema作成権限が必要。実NVD/OSV/AIへの通信は行わない。

検証対象：migration同時実行、up/down/up、checksum不一致拒否、DDLとmigrationのcatalog一致、辞書の古い更新拒否、PURLの重複排除、withdrawn除外、同時冪等受付、owner分離、lease takeover、旧worker拒否、候補/根拠のatomic rollback、終端結果不変性、結果ページング、キャンセル、期限切れ確定、保持期限削除、FK・ハッシュ・採用件数制約。

## 担当範囲と残る統合

DB担当ではNVD/OSVのHTTP取得・全件同期スケジューラー・AI推論・公開HTTPハンドラー・GitHub Actionsを実装していない。外部クライアント側は取得済みレコードをDictionaryへ渡す。source_sync_stateのDDLは保持しているが、同期管理メソッドは同期開発時に追加する。

API担当は上記インターフェースのDI、HTTP DTO変換、cursor署名、外部I/O・判定サービスとの接続を行う。CI担当はGo依存のキャッシュと、PostgreSQL serviceを使うTEST_DATABASE_URL設定を行う。別チャットへのメッセージ送信は行っていない。
