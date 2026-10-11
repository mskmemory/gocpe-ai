# 外部AIプロバイダー実装

2026-10-11。`internal/provider` はAPI/DB/ワーカーに依存しないGoパッケージ。4社の実HTTPアダプターを実装。API起動コマンドへの接続、NVD/OSV照合、採用判定、実推論ワーカーは対象外。公開HTTP契約とDDLは変更しない。既存のjsonschema/v6、go-cpe、packageurl-goを再利用し、新規依存なし。

## 接続契約

```go
p, err := provider.NewFromEnv(provider.Config{
    Provider: "openai", // openai / gemini / claude / deepseek
    Timeout: 60 * time.Second,
    MaxRetries: 2,
})
if err != nil { return err }
proposal, err := p.Propose(ctx, provider.ProposalRequest{
    Name: component.Name,
    Vendor: vendor,
    Version: component.Version,
    Hints: map[string]string{"ecosystem": ecosystem},
})
// errの有無にかかわらずproposal.Metadata.Attemptsをジョブの使用量へ記録する。
// 成功時のCPEs/PURLsも未確認の提案。次に実NVD/OSV照合へ渡す。
```

`AIProvider` の `Propose` / `Rank` をDIする。NewはConfig.Model必須、NewFromEnvは空の場合だけ各社のMODEL環境変数を読む。APIキーはNew時に環境変数から取得。設定変更には再生成する。モデルの存在・対応能力・資格情報の有効性はコンストラクターだけでは確認できない。キーがあることをAPIのproviders readinessに使わない。

| provider | キー | モデル | HTTP契約 |
|---|---|---|---|
| openai | OPENAI_API_KEY | OPENAI_MODEL | POST /v1/responses、Bearer、text.format json_schema、store=false |
| gemini | GEMINI_API_KEY | GEMINI_MODEL | POST /v1beta/models/{model}:generateContent、x-goog-api-key、generationConfig.responseJsonSchema |
| claude | ANTHROPIC_API_KEY | ANTHROPIC_MODEL | POST /v1/messages、x-api-key、anthropic-version、output_config.format |
| deepseek | DEEPSEEK_API_KEY | DEEPSEEK_MODEL | POST /chat/completions、Bearer、response_format json_object |

モデルIDは固定しない。該当出力方式に対応するモデルを運用者が選ぶ。DeepSeekはJSONモードとプロンプト内スキーマを使用し、サーバー側スキーマ保証を仮定しない。他社も全出力をローカルJSONスキーマで検証する。送信スキーマは各社の共通構造部分に絞り、長さ・件数・重複制約はローカルで強制する。

ProposalRequestは名前必須、ベンダー/バージョン/補助情報は欠損可能。送信内容は16KiBまで。ワーカーが送信許可された必要最小限の情報だけを作り、SBOM全文をHintsに入れない。別名とCPE/PURLはそれぞれ最大5件。各候補のvalueはパーサーで検証した識別子、reasonは短い説明。PURLは専用パーサーで構造化できる文字列として受け渡し、共有辞書への登録は行わない。バージョンを省略できるが、出力の具体的バージョンが入力と異なる場合は失敗にする。CPEのエスケープなどで単純な同一性を保証できない場合も保守的に拒否する。

Rankには最大50件のCandidate（ワーカーが発番したID、値、当該候補の根拠ID）を渡す。戻り値は上位からの部分集合で、空配列も有効。未知・重複候補ID、当該候補にない根拠IDは拒否し、出力全体を破棄する。返却されない候補は不適合確定ではない。CPEとPURLは別のRank呼出に分けることを推奨する。

確認状態・confidence・採用フラグは出力契約に存在せず、余分なフィールドは拒否する。理由文、別名、識別子、Hintsは常に未信頼データ。理由文が確認済みと主張しても根拠として扱わない。AIの順位を採用判定へ直結させず、外部取得結果と独立した入力情報を使ってワーカー/decision層が判定する。

## エラー・予算・監査

`errors.As(err, *provider.Error)` でKind/Statusを取得できる。invalid_input、invalid_output、refused、empty_response、truncated、rate_limited、unauthorized、unsupported、unavailable、cancelled、timeoutを区別。400/404/422は要求モデル・出力方式等のunsupportedであり、原因を断定しない。構造的に有効な空配列は成功で、HTTP空本文や空生成と区別する。timeout/cancelledはerrors.Isでcontextエラーも検出できる。

タイムアウトは待機・全再試行を含む1操作全体（既定60秒、上限10分）。親contextのキャンセルを伝播。MaxRetriesは既定0、上限3。429/408/5xxと通信失敗にだけ指数バックオフ＋ジッター、Retry-After秒数/HTTP日時で再試行。認証、拒否、打ち切り、不正JSON・スキーマ違反は再試行しない。JSON修復は初版では自動実行しない（追加費用と意味変更を避け、失敗を呼出元へ返す）。別プロバイダーへの自動フォールバックなし。

MaxOutputTokens既定4096、上限32768。応答本文は1MiB上限。リダイレクトは拒否し、キーの別ホスト転送を防ぐ。BaseURLは運用者の信頼済み設定のみ許可し、ユーザー入力から設定しない。HTTPS必須、ローカルHTTPはhttptest向け。HTTPClientはコピーしリダイレクトを拒否する。カスタムTransportやObserveの秘密情報管理は呼出元の責任。

Metadataにはプロバイダー、設定モデル、プロンプト版、全試行のUTC時刻・経過時間・HTTP状態・使用量・通信/エンベロープ結果を保持。最終ローカル検証の成否はメソッドのerrorで記録する。Observeは試行終了時の同じ安全な数値情報を通知する（最終スキーマ検証前）。並行呼出可能なのでコールバックはスレッドセーフかつ短時間にする。通常ログは自動出力せず、Observeで安全なメトリクスを接続可能。本文・キー・HTTPエラー本文・生の通信エラー・モデルの理由文をログに出さない。

Usage.Known=falseは未報告であり無料/ゼロ消費ではない。InputTokens/OutputTokens等は各社報告値で、Claudeのキャッシュ読み出し/作成は別カウンター。Geminiのthinkingも別カウンター。単純合算して料金とみなさない。外部POSTはexactly-onceではなく通信再試行で二重費用の可能性がある。ワーカー再取得をまたぐ累積・費用換算・同時実行数/ジョブ全体の予算制御はワーカーの責任。エラー時もMetadataを保存する。

## 検証

```sh
go test ./internal/provider
go test ./...
go vet ./...
go test -race ./...
# 明示した1社だけで課金を伴うライブ検査。認証情報は環境から設定する。
GOCPE_LIVE_PROVIDER=openai GOCPE_LIVE_MODEL=MODEL_ID go test -tags live -run TestLive -v ./internal/provider
```

通常テストはhttptest.Serverで実際のHTTP送受信を行い、外部通信・キーは不要。パス、認証、構造化出力、使用量、拒否、空応答、不正スキーマ/識別子、未知ID、再試行上限、キャンセル、同時利用、リダイレクト拒否、サイズ制限を検証。ライブはbuild tagとprovider/modelの明示指定が必要で、資格情報がなければ「未検証」としてskipする。今回 `go test ./...`、`go vet ./...`、`go test -race ./...` は成功。DB接続を要求する既存テストはTEST_DATABASE_URL未設定時のskip条件に従う。今回実サービスへの呼出は未実施。モデル固有の互換性と推論精度は未検証。

## 確認した公式仕様

2026-10-11閲覧。仕様・対応モデルは変わり得るため、モデル変更時にライブ検査を実施する。

- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) / [Responses](https://developers.openai.com/api/reference/resources/responses/methods/create)
- [Gemini Structured Output](https://ai.google.dev/gemini-api/docs/structured-output) / [generateContent](https://ai.google.dev/api/generate-content)
- [Claude Structured Outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs) / [Messages](https://platform.claude.com/docs/en/api/messages/create)
- [DeepSeek JSON Output](https://api-docs.deepseek.com/guides/json_mode/)
