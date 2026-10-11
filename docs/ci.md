# 開発用CI

`.github/workflows/ci.yml` はpull request、`main`へのpush、手動実行で起動する。作業ブランチへのpushだけでは起動しないため、GitHub上の検査結果が必要な場合はPRを作成するか、Actionsから手動実行する。必須チェック名は `CI required`。権限はcontents:readで、同一PR/ブランチの古い実行をキャンセルする。デプロイやAI API呼出は含まない。

## 実行する検査

最初のジョブはOpenAPIの仕様・ローカル参照・インライン例を検証し、固定版PostgreSQL 17.4へ `db/schema.sql` を適用してFK、一意性、採用・バージョン制約、削除連鎖を確認する。Go統合状態を判定し、ルートのgo.modとgit管理されたGoソースの両方が存在するときGoジョブを有効にする。片方だけの状態は失敗する。

Goジョブはgo.mod記載のGoを使い、git管理されたGoファイルをgofmt検査する。依存を取得・検証した後、`GOPROXY=off`、`GOSUMDB=off`、`-mod=readonly` で `go vet ./...` と `go test ./...` を実行する。続いて固定版PostgreSQLサービスを使い、`CI_REQUIRE_DB_TESTS=1` と `TEST_DATABASE_URL` を設定して `go test -race -count=1 -timeout=5m ./...` を実行する。DB統合テストが環境不足で黙ってskipされることを防ぐ。通常テストはAIを含む外部APIを呼ばず、資格情報も不要。

ActionはコミットSHA、コンテナはdigest、Python依存は推移依存も含め固定する。依存取得にはネットワークが必要だが、テストの実行とAIプロバイダーのテストにAPIキーは必要ない。

## ローカル実行

Go検査はgo.mod記載のGoを使い、リポジトリのルートで実行する。gofmt検査対象はgit管理ファイルなので、新しいGoファイルはgit addしてからスクリプトを実行する。

```sh
bash scripts/ci/check_go.sh
```

DB統合テストも実行する場合は、CIと同じ固定版PostgreSQLサービスを用意して環境変数を渡す。

```sh
TEST_DATABASE_URL='postgresql://ci:ci@localhost:5432/ci?sslmode=disable' \
CI_REQUIRE_DB_TESTS=1 go test -race -count=1 -timeout=5m ./...
```

OpenAPIとDDLの専用検査はPython 3.12とDockerを用意し、以下を実行する。

```sh
python3.12 -m venv /tmp/gocpe-ci-venv
/tmp/gocpe-ci-venv/bin/python -m pip install -r scripts/ci/requirements.lock
/tmp/gocpe-ci-venv/bin/python scripts/ci/check_openapi.py
/tmp/gocpe-ci-venv/bin/python scripts/ci/go_state.py
```

DDL検査は専用の使い捨てDBで行う。スクリプトはランダムな専用スキーマを作り、終了時にそのスキーマだけ削除する。業務DBでは実行しない。CIと同じPostgreSQLイメージを起動する例：

```sh
docker run --detach --rm --name gocpe-ci-postgres \
  -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci -e POSTGRES_DB=ci \
  -p 127.0.0.1:55432:5432 \
  postgres:17.4-bookworm@sha256:304ab813518754228f9f792f79d6da36359b82d8ecf418096c636725f8c930ad
docker exec gocpe-ci-postgres pg_isready -U ci -d ci
CI_DB_DISPOSABLE=1 DATABASE_URL=postgresql://ci:ci@localhost:55432/ci \
  /tmp/gocpe-ci-venv/bin/python scripts/ci/check_db.py
docker stop gocpe-ci-postgres
```

## 検証結果の報告

ローカルで成功した検査とGitHub Actionsの結果を区別する。GitHub上の成功はActionsの対象runを確認した場合だけ報告する。外部AIサービスのライブ呼出は通常CIに含めず、資格情報なしで未検証のままにする。

外部AIプロバイダーの変更では `go test ./...`、`go vet ./...`、`go test -race ./...` がローカルで成功した。プロバイダーの通常テストはhttptest.ServerでHTTPを検査し、外部サービスへ接続しない。ライブテストはbuild tagとプロバイダー・モデルの明示指定が必要。
