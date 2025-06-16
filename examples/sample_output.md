# サンプル出力例

このドキュメントでは、DMARC Analyzer の実行結果の例を示します。

## 1. エラーレコードがある場合の基本出力

```
🔍 DMARC レポート分析を開始します...
✅ 解凍・削除完了: google.com!example.com!1749772800!1749859199.zip
✅ 解凍・削除完了: google.com!demo-site.com!1749686400!1749772799.zip
✅ 解凍・削除完了: protection.outlook.com!example.com!1749772800!1749859200.xml.gz
📄 8個のXMLファイルを処理します
📖 処理中: google.com!example.com!1749772800!1749859199.xml
📖 処理中: google.com!demo-site.com!1749686400!1749772799.xml
📖 処理中: protection.outlook.com!example.com!1749772800!1749859200.xml

📊 分析結果: 総レコード数 5件

================================================================================
⚠️  エラーのあるレコード
================================================================================
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+
| Source IP      |   Count | Header From   | SPF Domain           | SPF Result   | DKIM Domain   | DKIM Result   | DKIM Selector   | DMARC Result   |
+================+=========+===============+======================+==============+===============+===============+=================+================+
| 192.168.1.100  |      10 | example.com   | example.com          | softfail     | example.com   | pass          | google          | pass           |
| 10.0.0.50      |       4 | demo-site.com | mail.hosting.com     | none         | demo-site.com | pass          | selector1       | pass           |
| 203.0.113.45   |       1 | test-org.net  | mail.provider.net    | none         | test-org.net  | pass          | selector2       | pass           |
| 198.51.100.20  |       1 | example.com   | example.com          | pass         | example.com   | temperror     | selector1       | pass           |
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+

❌ 4件のレコードでエラーが発生しました。
✅ 1件のレコードはエラーがないため表示を省略しました。

詳細な分析結果を表示しますか？(Y/n):
```

## 2. 全レコードでエラーがない場合

```
🔍 DMARC レポート分析を開始します...
✅ 解凍・削除完了: google.com!example.com!1749772800!1749859199.zip
📄 3個のXMLファイルを処理します
📖 処理中: google.com!example.com!1749772800!1749859199.xml

📊 分析結果: 総レコード数 8件

✅ 全てのレコードでエラーがありませんでした
```

## 3. 全レコード表示（--all オプション）

```
🔍 DMARC レポート分析を開始します...
📄 5個のXMLファイルを処理します

📊 分析結果: 総レコード数 12件

================================================================================
📋 全レコード表示
================================================================================
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+
| Source IP      |   Count | Header From   | SPF Domain           | SPF Result   | DKIM Domain   | DKIM Result   | DKIM Selector   | DMARC Result   |
+================+=========+===============+======================+==============+===============+===============+=================+================+
| 209.85.167.44  |       1 | example.com   | example.com          | pass         | example.com   | pass          | google          | pass           |
| 209.85.215.174 |       3 | example.com   | example.com          | pass         | example.com   | pass          | google          | pass           |
| 192.168.1.100  |      10 | demo-site.com | demo-site.com        | softfail     | demo-site.com | pass          | google          | pass           |
| 10.0.0.50      |       4 | test-org.net  | mail.hosting.com     | none         | test-org.net  | pass          | selector1       | pass           |
| 203.0.113.45   |       1 | sample.org    | mail.provider.net    | none         | sample.org    | pass          | selector2       | pass           |
| 198.51.100.20  |       1 | demo-site.com | demo-site.com        | pass         | demo-site.com | temperror     | selector1       | pass           |
+----------------+---------+---------------+----------------------+--------------+---------------+---------------+-----------------+----------------+

詳細な分析結果を表示しますか？(Y/n):
```

## 4. 詳細分析結果表示

```
================================================================================
🔍 詳細分析結果
================================================================================
📊 統計情報:
  - 総レコード数: 6
  - SPF失敗: 3件 (50.0%)
  - DKIM失敗: 1件 (16.7%)
  - DMARC失敗: 0件 (0.0%)

📋 ドメイン別分析:
  - example.com: 2件中0件失敗 (0.0%)
  - demo-site.com: 2件中0件失敗 (0.0%)
  - test-org.net: 1件中0件失敗 (0.0%)
  - sample.org: 1件中0件失敗 (0.0%)
```

## 5. ヘルプ表示（--help オプション）

```
usage: dmarc-analyzer [-h] [--all] [--details] [--dir DIR] [--no-color]

DMARC レポート分析ツール

options:
  -h, --help  show this help message and exit
  --all       エラーの有無に関わらず全レコードを表示
  --details   詳細分析結果を表示
  --dir DIR   DMARCレポートディレクトリのパス (デフォルト: ~/Downloads/DMARC)
  --no-color  カラー表示を無効にする
```

## 6. エラー発生時の例

### 依存関係不足の場合

```
❌ 必要なライブラリがインストールされていません:
不足ライブラリ: pandas, tabulate

以下のコマンドでインストールしてください:
pip install pandas tabulate

または:
pip3 install pandas tabulate
```

### ディレクトリが見つからない場合

```
🔍 DMARC レポート分析を開始します...
❌ ディレクトリが見つかりません: ~/Downloads/DMARC
```

### 処理対象ファイルがない場合

```
🔍 DMARC レポート分析を開始します...
❌ 処理対象のXMLファイルが見つかりません
```

## 色分け表示の説明

実際の実行時には、以下のように色分けされて表示されます：

- **🟢 pass**: 緑色で表示（正常）
- **🔴 fail**: 赤色で表示（エラー）
- **🟡 その他**: 黄色で表示（警告・不明）

例：
- SPF Result: `pass` は緑、`fail`、`softfail`、`none` は赤で表示
- DKIM Result: `pass` は緑、`fail`、`temperror` は赤で表示
- DMARC Result: `pass` は緑、`fail` は赤で表示

## 一般的な問題とその意味

### SPF関連
- **softfail**: SPF設定に問題があるが、メールは配信される
- **none**: SPFレコードが設定されていない
- **fail**: SPF認証に完全に失敗

### DKIM関連
- **temperror**: 一時的な技術的問題（DNS障害など）
- **fail**: DKIM署名の検証に失敗

### 推奨対応
1. **SPF none/softfail**: SPFレコードの設定・修正
2. **DKIM temperror**: 時間をおいて再確認、持続する場合はDKIM設定の確認
3. **DMARC fail**: SPFまたはDKIMの設定を確認・修正