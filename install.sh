#!/bin/bash

# DMARC Analyzer インストールスクリプト
# 使用方法: chmod +x install.sh && ./install.sh

set -e  # エラー時に終了

echo "🚀 DMARC Analyzer インストールを開始します..."

# Python3の存在確認
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3がインストールされていません。"
    echo "   macOS: brew install python3"
    echo "   Ubuntu: sudo apt install python3 python3-pip"
    exit 1
fi

# pipの存在確認
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3がインストールされていません。"
    echo "   Python3と一緒にインストールされるはずですが、見つかりません。"
    exit 1
fi

echo "✅ Python3およびpip3が確認できました"

# 依存関係のインストール
echo "📦 依存関係をインストール中..."
pip3 install -r requirements.txt

echo "✅ 依存関係のインストールが完了しました"

# スクリプトファイルの存在確認
if [ ! -f "dmarc-analyzer.py" ]; then
    echo "❌ dmarc-analyzer.py が見つかりません。"
    echo "   このスクリプトはdmarc-analyzerリポジトリのルートディレクトリで実行してください。"
    exit 1
fi

# 実行権限の付与
chmod +x dmarc-analyzer.py
echo "✅ 実行権限を付与しました"

# シンボリックリンクの作成
SCRIPT_PATH="$(pwd)/dmarc-analyzer.py"
SYMLINK_PATH="/usr/local/bin/dmarc-analyzer"

echo "🔗 グローバルコマンドとして設定中..."
echo "   管理者権限が必要です。パスワードの入力を求められる場合があります。"

if sudo ln -sf "$SCRIPT_PATH" "$SYMLINK_PATH"; then
    echo "✅ グローバルコマンドの設定が完了しました"
    echo "   どこからでも 'dmarc-analyzer' コマンドが使用可能です"
else
    echo "⚠️  グローバル設定に失敗しました。"
    echo "   以下のコマンドを手動で実行してください:"
    echo "   sudo ln -sf $SCRIPT_PATH $SYMLINK_PATH"
    echo ""
    echo "   または、以下の方法でローカルで使用できます:"
    echo "   python3 $SCRIPT_PATH"
fi

# インストール確認
echo ""
echo "🧪 インストール確認中..."

if command -v dmarc-analyzer &> /dev/null; then
    echo "✅ インストールが正常に完了しました！"
    echo ""
    echo "📋 使用方法:"
    echo "   dmarc-analyzer                  # エラーレコードのみ表示"
    echo "   dmarc-analyzer --all            # 全レコード表示"
    echo "   dmarc-analyzer --details        # 詳細分析付き"
    echo "   dmarc-analyzer --help           # ヘルプ表示"
    echo ""
    echo "📁 DMARCレポートファイル(ZIP/GZ)を ~/Downloads/DMARC に配置してから実行してください"
else
    echo "⚠️  グローバルコマンドとして設定されていませんが、以下の方法で使用可能です:"
    echo "   python3 $SCRIPT_PATH"
fi

echo ""
echo "🎉 インストール処理が完了しました！"