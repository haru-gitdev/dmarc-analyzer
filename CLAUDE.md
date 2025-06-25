# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

DMARC Analyzer は、XMLファイルからDMARCレポートを自動解析し、エラーのあるレコードを抽出・表示するセキュリティツールです。単一のPythonスクリプト（dmarc-analyzer.py）で構成され、647行のコードで完全な分析機能を提供します。

## 開発環境セットアップ

### 依存関係インストール
```bash
pip3 install -r requirements.txt
```

必要なライブラリ：
- pandas>=2.0.0 (データ処理)
- tabulate>=0.9.0 (テーブル表示)  
- colorama>=0.4.0 (カラー表示)

### インストール・実行
```bash
# 自動インストール（推奨）
chmod +x install.sh
./install.sh

# 手動インストール後にシンボリックリンク作成
sudo ln -s $(pwd)/dmarc-analyzer.py /usr/local/bin/dmarc-analyzer

# 実行テスト
dmarc-analyzer --help
```

## アーキテクチャ

### メインクラス：DMARCAnalyzer

**ファイル処理レイヤー**
- `extract_files()`: ZIP/GZ自動解凍、XMLファイル検出
- `cleanup()`: 一時ファイルの自動削除

**XML解析レイヤー** 
- `parse_xml()`: DMARCレポートXMLの構造解析
- `parse_record()`: 個別レコードの詳細解析（policy_published, policy_evaluated, auth_results）

**DMARC評価エンジン**
- `evaluate_dmarc()`: policy_evaluated優先の結果判定
- `check_alignment()`: ドメインアライメント（strict/relaxed）チェック
- `evaluate_spf_alignment()`, `evaluate_dkim_alignment()`: 個別認証結果評価

**表示・レポート生成**
- `format_table()`: ターミナル幅対応の動的テーブル生成
- `calculate_column_widths()`: 列幅の最適化計算
- `show_detailed_analysis()`: 統計情報とドメイン別分析

### 重要なワークフロー

1. **分析フロー**: ファイル解凍 → XML解析 → DMARC評価 → レコード統合 → エラーフィルタリング
2. **評価ロジック**: policy_evaluatedが存在する場合は優先、なければSPF/DKIMアライメント手動評価
3. **表示制御**: エラーレコードのみ表示がデフォルト、`--all`で全レコード表示

## 開発時の注意点

### DMARC仕様の実装
- **アライメントモード**: policy_publishedのadkim/aspf設定を考慮（デフォルトrelaxed）
- **組織ドメイン**: relaxedモードでは`mail.example.com`と`example.com`を同一視
- **最終判定**: SPFまたはDKIMのいずれかがpassすればDMARC pass

### 表示最適化
- `get_terminal_width()`: ターミナル幅自動検出
- `truncate_text()`: 長いドメイン名の省略処理
- カラーコード対応: pass（緑）、fail（赤）、その他（黄）

### エラーハンドリング
- 依存関係チェック機能内蔵（`check_dependencies()`）
- XMLパースエラー、ファイル処理エラーの適切な処理
- 一時ファイルの確実なクリーンアップ

## テスト・検証

```bash
# 基本動作確認
dmarc-analyzer --dir ./test-data

# 全機能テスト
dmarc-analyzer --all --details --dir /path/to/test/files

# カラー無効でのテスト
dmarc-analyzer --no-color
```

## バージョン管理

- v1.0.0: 基本機能
- v1.1.0: テーブル表示改善  
- v1.2.0: エラードメイン完全一覧表示機能

READMEのバージョン履歴セクションを必ず更新すること。

## セキュリティ考慮事項

このツールは防御的セキュリティ分析専用です。DMARC設定の改善とメールセキュリティ向上が目的であり、悪用可能な機能は含まれていません。