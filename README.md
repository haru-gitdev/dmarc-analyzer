# DMARC Analyzer

📧 **DMARC レポート分析ツール** - XMLファイルを自動解析し、エラーのあるレコードのみを瞬時に表示

## 🚀 機能

- **自動ファイル処理**: ZIP/GZ ファイルの自動検出・解凍・削除
- **エラーフィルタリング**: エラーのあるレコードのみを自動抽出・表示
- **DMARC評価**: SPF/DKIM アライメント考慮の正確な結果判定
- **視覚的表示**: カラー付きテーブル形式での見やすい結果表示
- **レスポンシブ表示**: ターミナル幅に自動調整される最適化されたテーブル
- **統計サマリー**: 総件数、エラー率、ドメイン別分析
- **ワンコマンド実行**: 複雑な手動プロセスを一発実行で自動化

## 📦 インストール

### 必要な依存関係

```bash
pip install pandas tabulate colorama
```

### インストール方法

#### 方法1: 自動インストールスクリプト（推奨）

```bash
# リポジトリをクローン
git clone https://github.com/haru-gitdev/dmarc-analyzer.git
cd dmarc-analyzer

# 自動インストール実行
chmod +x install.sh
./install.sh
```

#### 方法2: 手動インストール

```bash
# 1. リポジトリをクローン
git clone https://github.com/haru-gitdev/dmarc-analyzer.git
cd dmarc-analyzer

# 2. 依存関係をインストール
pip3 install pandas tabulate colorama

# 3. シンボリックリンクを作成（管理者権限必要）
sudo ln -s $(pwd)/dmarc-analyzer.py /usr/local/bin/dmarc-analyzer

# 4. 実行権限を付与
chmod +x /usr/local/bin/dmarc-analyzer
```

## 🔧 使用方法

### 基本的な使い方

1. DMARC レポートファイル（ZIP/GZ形式）を `~/Downloads/DMARC` に配置
2. コマンドを実行

```bash
# エラーレコードのみ表示（基本）
dmarc-analyzer

# 全レコード表示
dmarc-analyzer --all

# 詳細分析付き
dmarc-analyzer --details

# 特定ディレクトリのファイルを分析
dmarc-analyzer --dir /path/to/dmarc/files

# カラー表示を無効化
dmarc-analyzer --no-color
```

### コマンドオプション

| オプション | 説明 |
|-----------|------|
| `--all` | エラーの有無に関わらず全レコードを表示 |
| `--details` | 詳細分析結果を表示 |
| `--dir DIR` | DMARCレポートディレクトリのパス指定 |
| `--no-color` | カラー表示を無効にする |
| `--help` | ヘルプメッセージを表示 |

## 📊 出力例

### エラーレコードがある場合

```
🔍 DMARC レポート分析を開始します...
✅ 解凍・削除完了: google.com!example.com!1749772800!1749859199.zip
📄 3個のXMLファイルを処理します

📊 分析結果: 総レコード数 10件

================================================================================
⚠️  エラーのあるレコード
================================================================================
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+
| Source IP      |   Count | Header From   | SPF Domain           | SPF Result   | DKIM Domain   | DKIM Result   | DKIM Selector   | DMARC Result   |
+================+=========+===============+======================+==============+===============+===============+=================+================+
| 209.85.167.72  |       1 | example.com   | brains.link          | softfail     | example.com   | pass          | google          | pass           |
| 49.212.180.58  |      10 | test.com      | www.sakura.ne.jp     | none         | test.com      | pass          | rs20240131      | pass           |
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+

❌ 2件のレコードでエラーが発生しました。
✅ 8件のレコードはエラーがないため表示を省略しました。

詳細な分析結果を表示しますか？(Y/n):
```

### 全てのレコードでエラーがない場合

```
🔍 DMARC レポート分析を開始します...
📊 分析結果: 総レコード数 5件

✅ 全てのレコードでエラーがありませんでした
```

## 🎯 従来の手動プロセスとの比較

| 項目 | 従来の手動プロセス | DMARC Analyzer |
|------|------------------|----------------|
| 実行時間 | 数分〜数十分 | 数秒 |
| 操作手順 | 複雑な多段階プロセス | ワンコマンド |
| エラー発見 | 手動での目視確認 | 自動フィルタリング |
| ファイル処理 | 手動解凍・削除 | 完全自動化 |
| 結果表示 | XMLを直接確認 | 整理されたテーブル |

## 🔍 分析ロジック

### DMARC 結果評価

1. **policy_evaluated 優先**: XMLの `policy_evaluated` セクションが存在する場合は優先利用
2. **SPF アライメント**: SPF結果 + ドメインアライメントをチェック
3. **DKIM アライメント**: DKIM結果 + ドメインアライメントをチェック  
4. **最終判定**: SPF または DKIM のいずれかが pass であれば DMARC pass

### アライメントルール

- **Strict**: 完全一致のみ
- **Relaxed**: 組織ドメインレベルでの一致も許可
  - 例: `mail.example.com` と `example.com` は一致とみなす

## 🛠️ 開発・貢献

### 開発環境のセットアップ

```bash
git clone https://github.com/haru-gitdev/dmarc-analyzer.git
cd dmarc-analyzer
pip3 install -r requirements.txt
```

### テスト実行

```bash
# テスト用DMARCファイルでの動作確認
python3 dmarc-analyzer.py --dir ./test-data
```

## 📝 ライセンス

MIT License - 詳細は [LICENSE](LICENSE) ファイルを参照

## 🤝 貢献

プルリクエストやイシューの報告を歓迎します！

1. このリポジトリをフォーク
2. 機能ブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## 📞 サポート

- **Issue報告**: [GitHub Issues](https://github.com/haru-gitdev/dmarc-analyzer/issues)
- **機能要望**: 同じく GitHub Issues で

## 📈 バージョン履歴

- **v1.1.0** - テーブル表示改善
  - ターミナル幅に合わせた動的な列幅調整
  - 長いテキストの自動省略機能（ドメイン名、IPアドレス等）
  - デバッグ情報の追加（ファイル検出プロセス表示）
  - レイアウト崩れの大幅な改善

- **v1.0.0** - 初回リリース
  - 基本的なDMARC分析機能
  - ZIP/GZ ファイル自動処理
  - エラーフィルタリング
  - カラー表示対応

---

**Made with ❤️ for better email security**