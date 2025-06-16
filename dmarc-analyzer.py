#!/usr/bin/env python3
"""
DMARC レポート分析ツール

XMLファイルを自動解析し、エラーのあるレコードのみを表形式で表示します。
"""

import sys
import os
import xml.etree.ElementTree as ET
import zipfile
import gzip
import glob
import argparse
from pathlib import Path
import json
import shutil
from typing import List, Dict, Any, Optional

# 依存関係チェック
def check_dependencies():
    """必要なライブラリの存在チェック"""
    missing_libs = []
    
    try:
        import pandas as pd
    except ImportError:
        missing_libs.append('pandas')
    
    try:
        from tabulate import tabulate
    except ImportError:
        missing_libs.append('tabulate')
    
    try:
        from colorama import Fore, Style, init
    except ImportError:
        missing_libs.append('colorama')
    
    if missing_libs:
        print("❌ 必要なライブラリがインストールされていません:")
        print(f"不足ライブラリ: {', '.join(missing_libs)}")
        print("\n以下のコマンドでインストールしてください:")
        print(f"pip install {' '.join(missing_libs)}")
        print("\nまたは:")
        print(f"pip3 install {' '.join(missing_libs)}")
        sys.exit(1)
    
    return True

# 依存関係チェック実行
check_dependencies()

# 依存関係チェック後にインポート
import pandas as pd
from tabulate import tabulate
from colorama import Fore, Style, init

# colorama初期化
init(autoreset=True)

class DMARCAnalyzer:
    """DMARC レポート分析クラス"""
    
    def __init__(self, dmarc_dir: str = None):
        self.dmarc_dir = dmarc_dir or os.path.expanduser("~/Downloads/DMARC")
        self.temp_files = []  # 解凍したファイルを追跡
        
    def extract_files(self) -> List[str]:
        """ZIP/GZ ファイルを解凍してXMLファイルのパスを返す"""
        xml_files = []
        
        if not os.path.exists(self.dmarc_dir):
            print(f"❌ ディレクトリが見つかりません: {self.dmarc_dir}")
            return xml_files
        
        # 既存のXMLファイルを取得
        xml_files.extend(glob.glob(os.path.join(self.dmarc_dir, "*.xml")))
        
        # ZIPファイルを解凍
        zip_files = glob.glob(os.path.join(self.dmarc_dir, "*.zip"))
        for zip_path in zip_files:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    for member in zip_ref.namelist():
                        if member.endswith('.xml'):
                            extract_path = os.path.join(self.dmarc_dir, member)
                            zip_ref.extract(member, self.dmarc_dir)
                            xml_files.append(extract_path)
                            self.temp_files.append(extract_path)
                
                # 解凍後にZIPファイルを削除
                os.remove(zip_path)
                print(f"✅ 解凍・削除完了: {os.path.basename(zip_path)}")
                
            except Exception as e:
                print(f"❌ ZIP解凍エラー {zip_path}: {e}")
        
        # GZファイルを解凍
        gz_files = glob.glob(os.path.join(self.dmarc_dir, "*.gz"))
        for gz_path in gz_files:
            try:
                xml_path = gz_path.replace('.gz', '')
                with gzip.open(gz_path, 'rb') as gz_file:
                    with open(xml_path, 'wb') as xml_file:
                        shutil.copyfileobj(gz_file, xml_file)
                
                xml_files.append(xml_path)
                self.temp_files.append(xml_path)
                
                # 解凍後にGZファイルを削除
                os.remove(gz_path)
                print(f"✅ 解凍・削除完了: {os.path.basename(gz_path)}")
                
            except Exception as e:
                print(f"❌ GZ解凍エラー {gz_path}: {e}")
        
        return xml_files
    
    def parse_xml(self, xml_path: str) -> List[Dict[str, Any]]:
        """XMLファイルをパースしてレコード情報を取得"""
        records = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # policy_published情報を取得
            policy_published = {}
            policy_elem = root.find('policy_published')
            if policy_elem is not None:
                policy_published = {
                    'domain': policy_elem.find('domain').text if policy_elem.find('domain') is not None else '',
                    'adkim': policy_elem.find('adkim').text if policy_elem.find('adkim') is not None else 'r',
                    'aspf': policy_elem.find('aspf').text if policy_elem.find('aspf') is not None else 'r',
                    'p': policy_elem.find('p').text if policy_elem.find('p') is not None else '',
                }
            
            # 各レコードを処理
            for record in root.findall('record'):
                record_data = self.parse_record(record, policy_published)
                if record_data:
                    records.append(record_data)
                    
        except Exception as e:
            print(f"❌ XML解析エラー {xml_path}: {e}")
            
        return records
    
    def parse_record(self, record_elem, policy_published: Dict) -> Optional[Dict[str, Any]]:
        """個別レコードをパース"""
        try:
            # 基本情報
            row = record_elem.find('row')
            source_ip = row.find('source_ip').text if row.find('source_ip') is not None else ''
            count = int(row.find('count').text) if row.find('count') is not None else 1
            
            # policy_evaluated情報
            policy_evaluated = {}
            policy_eval_elem = row.find('policy_evaluated')
            if policy_eval_elem is not None:
                policy_evaluated = {
                    'disposition': policy_eval_elem.find('disposition').text if policy_eval_elem.find('disposition') is not None else '',
                    'dkim': policy_eval_elem.find('dkim').text if policy_eval_elem.find('dkim') is not None else '',
                    'spf': policy_eval_elem.find('spf').text if policy_eval_elem.find('spf') is not None else '',
                }
            
            # identifiers
            identifiers = record_elem.find('identifiers')
            header_from = identifiers.find('header_from').text if identifiers.find('header_from') is not None else ''
            envelope_from = identifiers.find('envelope_from').text if identifiers.find('envelope_from') is not None else ''
            
            # auth_results
            auth_results = record_elem.find('auth_results')
            
            # SPF結果
            spf_results = []
            if auth_results is not None:
                for spf in auth_results.findall('spf'):
                    spf_domain = spf.find('domain').text if spf.find('domain') is not None else ''
                    spf_result = spf.find('result').text if spf.find('result') is not None else ''
                    spf_results.append({'domain': spf_domain, 'result': spf_result})
            
            # DKIM結果
            dkim_results = []
            if auth_results is not None:
                for dkim in auth_results.findall('dkim'):
                    dkim_domain = dkim.find('domain').text if dkim.find('domain') is not None else ''
                    dkim_result = dkim.find('result').text if dkim.find('result') is not None else ''
                    dkim_selector = dkim.find('selector').text if dkim.find('selector') is not None else ''
                    dkim_results.append({
                        'domain': dkim_domain, 
                        'result': dkim_result, 
                        'selector': dkim_selector
                    })
            
            # レコードデータを作成
            record_data = {
                'source_ip': source_ip,
                'count': count,
                'header_from': header_from,
                'envelope_from': envelope_from,
                'policy_evaluated': policy_evaluated,
                'spf_results': spf_results,
                'dkim_results': dkim_results,
                'policy_published': policy_published
            }
            
            return record_data
            
        except Exception as e:
            print(f"❌ レコード解析エラー: {e}")
            return None
    
    def check_alignment(self, domain1: str, domain2: str, alignment_mode: str = 'r') -> bool:
        """ドメインアライメントをチェック"""
        if not domain1 or not domain2:
            return False
            
        # 完全一致
        if domain1.lower() == domain2.lower():
            return True
        
        # relaxed alignment (組織ドメインレベルでの一致)
        if alignment_mode == 'r':
            # サブドメインを除いた組織ドメインで比較
            org_domain1 = '.'.join(domain1.lower().split('.')[-2:]) if '.' in domain1 else domain1.lower()
            org_domain2 = '.'.join(domain2.lower().split('.')[-2:]) if '.' in domain2 else domain2.lower()
            return org_domain1 == org_domain2
        
        return False
    
    def evaluate_dmarc(self, record_data: Dict[str, Any]) -> Dict[str, Any]:
        """DMARC結果を評価"""
        header_from = record_data['header_from']
        policy_evaluated = record_data.get('policy_evaluated', {})
        policy_published = record_data.get('policy_published', {})
        
        # policy_evaluatedが存在する場合はそれを優先
        if policy_evaluated.get('dkim') and policy_evaluated.get('spf'):
            dmarc_result = 'pass' if (policy_evaluated.get('dkim') == 'pass' or 
                                    policy_evaluated.get('spf') == 'pass') else 'fail'
            note = 'policy_evaluated'
            
            # 表示用のSPF/DKIM情報を構築
            spf_info = self.build_spf_info(record_data)
            dkim_info = self.build_dkim_info(record_data)
            
            return {
                'source_ip': record_data['source_ip'],
                'count': record_data['count'],
                'header_from': header_from,
                'spf_domain': spf_info.get('domain', ''),
                'spf_result': spf_info.get('result', ''),
                'dkim_domain': dkim_info.get('domain', ''),
                'dkim_result': dkim_info.get('result', ''),
                'dkim_selector': dkim_info.get('selector', ''),
                'dmarc_result': dmarc_result,
                'note': note
            }
        
        # 手動評価
        spf_dmarc_result = self.evaluate_spf_alignment(record_data)
        dkim_dmarc_result = self.evaluate_dkim_alignment(record_data)
        
        # 最終DMARC結果
        dmarc_result = 'pass' if (spf_dmarc_result == 'pass' or dkim_dmarc_result == 'pass') else 'fail'
        
        # 表示用のSPF/DKIM情報を構築
        spf_info = self.build_spf_info(record_data)
        dkim_info = self.build_dkim_info(record_data)
        
        return {
            'source_ip': record_data['source_ip'],
            'count': record_data['count'],
            'header_from': header_from,
            'spf_domain': spf_info.get('domain', ''),
            'spf_result': spf_info.get('result', ''),
            'dkim_domain': dkim_info.get('domain', ''),
            'dkim_result': dkim_info.get('result', ''),
            'dkim_selector': dkim_info.get('selector', ''),
            'dmarc_result': dmarc_result,
            'note': 'manual_evaluation'
        }
    
    def build_spf_info(self, record_data: Dict[str, Any]) -> Dict[str, str]:
        """SPF表示情報を構築"""
        spf_results = record_data.get('spf_results', [])
        if spf_results:
            # 最初のSPF結果を使用
            return spf_results[0]
        return {'domain': '', 'result': ''}
    
    def build_dkim_info(self, record_data: Dict[str, Any]) -> Dict[str, str]:
        """DKIM表示情報を構築"""
        dkim_results = record_data.get('dkim_results', [])
        if dkim_results:
            # passの結果があればそれを優先、なければ最初の結果を使用
            for dkim in dkim_results:
                if dkim.get('result') == 'pass':
                    return dkim
            return dkim_results[0]
        return {'domain': '', 'result': '', 'selector': ''}
    
    def evaluate_spf_alignment(self, record_data: Dict[str, Any]) -> str:
        """SPFアライメントを評価"""
        header_from = record_data['header_from']
        spf_results = record_data.get('spf_results', [])
        policy_published = record_data.get('policy_published', {})
        aspf = policy_published.get('aspf', 'r')  # デフォルトはrelaxed
        
        for spf in spf_results:
            if spf.get('result') == 'pass':
                if self.check_alignment(spf.get('domain', ''), header_from, aspf):
                    return 'pass'
        
        return 'fail'
    
    def evaluate_dkim_alignment(self, record_data: Dict[str, Any]) -> str:
        """DKIMアライメントを評価"""
        header_from = record_data['header_from']
        dkim_results = record_data.get('dkim_results', [])
        policy_published = record_data.get('policy_published', {})
        adkim = policy_published.get('adkim', 'r')  # デフォルトはrelaxed
        
        for dkim in dkim_results:
            if dkim.get('result') == 'pass':
                if self.check_alignment(dkim.get('domain', ''), header_from, adkim):
                    return 'pass'
        
        return 'fail'
    
    def consolidate_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """同じIP・同じレコード内容のものを統合"""
        consolidated = {}
        
        for record in records:
            key = (
                record['source_ip'],
                record['header_from'],
                record['spf_domain'],
                record['spf_result'],
                record['dkim_domain'],
                record['dkim_result'],
                record['dkim_selector'],
                record['dmarc_result']
            )
            
            if key in consolidated:
                consolidated[key]['count'] += record['count']
            else:
                consolidated[key] = record.copy()
        
        return list(consolidated.values())
    
    def filter_error_records(self, records: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], int]:
        """エラーのあるレコードのみを抽出"""
        error_records = []
        total_count = len(records)
        
        for record in records:
            has_error = (
                record['spf_result'] != 'pass' or
                record['dkim_result'] != 'pass' or
                record['dmarc_result'] != 'pass'
            )
            
            if has_error:
                error_records.append(record)
        
        clean_count = total_count - len(error_records)
        return error_records, clean_count
    
    def format_table(self, records: List[Dict[str, Any]], show_colors: bool = True) -> str:
        """レコードをテーブル形式でフォーマット"""
        if not records:
            return ""
        
        headers = [
            'Source IP', 'Count', 'Header From', 'SPF Domain', 
            'SPF Result', 'DKIM Domain', 'DKIM Result', 
            'DKIM Selector', 'DMARC Result'
        ]
        
        table_data = []
        for record in records:
            row = [
                record['source_ip'],
                record['count'],
                record['header_from'],
                record['spf_domain'],
                self.colorize_result(record['spf_result'], show_colors),
                record['dkim_domain'],
                self.colorize_result(record['dkim_result'], show_colors),
                record['dkim_selector'],
                self.colorize_result(record['dmarc_result'], show_colors)
            ]
            table_data.append(row)
        
        return tabulate(table_data, headers=headers, tablefmt='grid')
    
    def colorize_result(self, result: str, show_colors: bool = True) -> str:
        """結果に色を付ける"""
        if not show_colors:
            return result
            
        if result.lower() == 'pass':
            return f"{Fore.GREEN}{result}{Style.RESET_ALL}"
        elif result.lower() == 'fail':
            return f"{Fore.RED}{result}{Style.RESET_ALL}"
        else:
            return f"{Fore.YELLOW}{result}{Style.RESET_ALL}"
    
    def analyze(self, show_all: bool = False, show_details: bool = False) -> None:
        """メイン分析処理"""
        print("🔍 DMARC レポート分析を開始します...")
        
        # ファイル解凍
        xml_files = self.extract_files()
        if not xml_files:
            print("❌ 処理対象のXMLファイルが見つかりません")
            return
        
        print(f"📄 {len(xml_files)}個のXMLファイルを処理します")
        
        # 全レコードを収集
        all_records = []
        for xml_file in xml_files:
            print(f"📖 処理中: {os.path.basename(xml_file)}")
            records = self.parse_xml(xml_file)
            
            # DMARC評価
            for record_data in records:
                evaluated_record = self.evaluate_dmarc(record_data)
                all_records.append(evaluated_record)
        
        if not all_records:
            print("❌ 処理可能なレコードが見つかりません")
            return
        
        # レコード統合
        consolidated_records = self.consolidate_records(all_records)
        
        print(f"\n📊 分析結果: 総レコード数 {len(consolidated_records)}件")
        
        if show_all:
            # 全レコード表示
            print("\n" + "="*80)
            print("📋 全レコード表示")
            print("="*80)
            table = self.format_table(consolidated_records)
            print(table)
        else:
            # エラーレコードのみ表示
            error_records, clean_count = self.filter_error_records(consolidated_records)
            
            if error_records:
                print("\n" + "="*80)
                print("⚠️  エラーのあるレコード")
                print("="*80)
                table = self.format_table(error_records)
                print(table)
                
                print(f"\n❌ {len(error_records)}件のレコードでエラーが発生しました。")
                if clean_count > 0:
                    print(f"✅ {clean_count}件のレコードはエラーがないため表示を省略しました。")
            else:
                print("\n✅ 全てのレコードでエラーがありませんでした")
                return
        
        # 詳細分析の確認
        if not show_details:
            response = input("\n詳細な分析結果を表示しますか？(Y/n): ").strip()
            if response.lower() in ['y', 'yes', '']:
                show_details = True
        
        if show_details:
            self.show_detailed_analysis(consolidated_records if show_all else error_records)
    
    def show_detailed_analysis(self, records: List[Dict[str, Any]]) -> None:
        """詳細分析結果を表示"""
        print("\n" + "="*80)
        print("🔍 詳細分析結果")
        print("="*80)
        
        # 統計情報
        total_records = len(records)
        spf_fails = sum(1 for r in records if r['spf_result'] != 'pass')
        dkim_fails = sum(1 for r in records if r['dkim_result'] != 'pass')
        dmarc_fails = sum(1 for r in records if r['dmarc_result'] != 'pass')
        
        print(f"📊 統計情報:")
        print(f"  - 総レコード数: {total_records}")
        print(f"  - SPF失敗: {spf_fails}件 ({spf_fails/total_records*100:.1f}%)")
        print(f"  - DKIM失敗: {dkim_fails}件 ({dkim_fails/total_records*100:.1f}%)")
        print(f"  - DMARC失敗: {dmarc_fails}件 ({dmarc_fails/total_records*100:.1f}%)")
        
        # ドメイン別分析
        domains = {}
        for record in records:
            domain = record['header_from']
            if domain not in domains:
                domains[domain] = {'total': 0, 'fails': 0}
            domains[domain]['total'] += 1
            if record['dmarc_result'] != 'pass':
                domains[domain]['fails'] += 1
        
        print(f"\n📋 ドメイン別分析:")
        for domain, stats in domains.items():
            fail_rate = stats['fails'] / stats['total'] * 100
            print(f"  - {domain}: {stats['total']}件中{stats['fails']}件失敗 ({fail_rate:.1f}%)")
    
    def cleanup(self) -> None:
        """一時ファイルをクリーンアップ"""
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                    print(f"🗑️  一時ファイル削除: {os.path.basename(temp_file)}")
                except Exception as e:
                    print(f"❌ ファイル削除エラー {temp_file}: {e}")

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description='DMARC レポート分析ツール')
    parser.add_argument('--all', action='store_true', 
                       help='エラーの有無に関わらず全レコードを表示')
    parser.add_argument('--details', action='store_true', 
                       help='詳細分析結果を表示')
    parser.add_argument('--dir', type=str, 
                       help='DMARCレポートディレクトリのパス (デフォルト: ~/Downloads/DMARC)')
    parser.add_argument('--no-color', action='store_true', 
                       help='カラー表示を無効にする')
    
    args = parser.parse_args()
    
    # 分析実行
    analyzer = DMARCAnalyzer(args.dir)
    
    try:
        analyzer.analyze(show_all=args.all, show_details=args.details)
    except KeyboardInterrupt:
        print("\n\n⚠️  処理が中断されました")
    except Exception as e:
        print(f"\n❌ エラーが発生しました: {e}")
    finally:
        analyzer.cleanup()

if __name__ == "__main__":
    main()