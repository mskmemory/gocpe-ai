# 開発用CI

pull_request、mainへのpush、手動実行で `.github/workflows/ci.yml` を実行する。
必須チェックとして設定するジョブ名は `CI required`。権限はcontents:read、同一PR/ブランチの古い実行をキャンセルする。デプロイやAI API呼出は含まない。

## 現在実行する検証

- OpenAPI専用validatorで仕様、ローカル参照、インライン例を検証する。
- PostgreSQL 17.4サービスにdb/schema.sqlを適用し、FK、一意性、採用・バージョン制約、削除連鎖を検証する。
- Go統合状態をサマリーに表示する。go.modとGoソースが未作成なので、現段階ではGoの検証は未実施。

ルートgo.modが追加されるとGoジョブを自動で有効化する。Goファイルだけ追加された状態や、go.modだけ存在する状態は失敗する。Goのバージョンはgo.modから取得する。gofmt、go vet、go testを実行し、依存取得後はGOPROXY/GOSUMDBを無効にしてテストする。通常テストが外部APIにアクセスしないことはアプリ実装側でも維持する。

ActionはコミットSHA、コンテナはdigest、Python依存は推移依存も含めた固定版で管理する。依存取得にはネットワークが必要だが検証にAIキーは不要。

## ローカル実行

Python 3.12とDockerを用意する。リポジトリのルートで実行する。

```sh
python3.12 -m venv /tmp/gocpe-ci-venv
/tmp/gocpe-ci-venv/bin/python -m pip install -r scripts/ci/requirements.lock
/tmp/gocpe-ci-venv/bin/python scripts/ci/check_openapi.py
/tmp/gocpe-ci-venv/bin/python scripts/ci/go_state.py
```

DB検証は専用の使い捨てDBで実行する。以下はCIと同じ固定イメージを利用する例。

```sh
docker run --detach --rm --name gocpe-ci-postgres \
  -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci -e POSTGRES_DB=ci \
  -p 127.0.0.1:55432:5432 \
  postgres:17.4-bookworm@sha256:304ab813518754228f9f792f79d6da36359b82d8ecf418096c636725f8c930ad
docker exec gocpe-ci-postgres pg_isready -U ci -d ci
# 起動完了後に実行する。
CI_DB_DISPOSABLE=1 DATABASE_URL=postgresql://ci:ci@localhost:55432/ci \
  /tmp/gocpe-ci-venv/bin/python scripts/ci/check_db.py
docker stop gocpe-ci-postgres
```

検証スクリプトはランダムな専用スキーマを作成し、終了時にそのスキーマだけ削除する。業務DBでは実行しない。
Go統合後はgo.modが指定するGoをインストールし、`bash scripts/ci/check_go.sh` を実行する。
新規Goファイルはgit addしてから実行する（検査対象はgit管理ファイル）。

## DB・APIブランチ統合時

DDLスナップショットの検証と番号付きmigrationの検証は別物。DB担当のmigration runner・Go統合テストが追加されたら、このPostgreSQLサービスを使う専用ステップを追加する。現段階でmigrationの適用/rollback、lease競合、owner越境テストを実施済みとは扱わない。

GoのDB統合テストには別の使い捨てDB接続を明示的に渡し、外部APIテストとは分離する。並行処理のテストが追加されたらrace検証も有効化する。必要な検査をcontinue-on-errorで隠さない。

## この変更での検証結果

- actionlint v1.7.7でworkflow検証：成功。
- OpenAPI仕様・内部参照・インライン例の検証：成功。
- 固定版PostgreSQL 17.4上でDDL・FK・一意性・採用/バージョン制約・CASCADE：成功。
- Go未実装、Goソースのみ、Goモジュールありの状態判定：期待どおり。
- Goのアプリテスト、番号付きmigration、GitHub上の実行は未実施。

Python依存はOpenAPIの仕様/例の検証とPostgreSQL接続のための開発専用依存。アプリ本体にPython依存は追加しない。
