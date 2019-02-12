# cdir-analyzer (parser)

## 概要

cdir-analyzer (parser)はcdir-collectorで収集したデータのパーサ群です。

## 内容

* browsinghistoryview-x64
  * BrowsingHistoryView.exe - Webブラウザ履歴のパーサ
* lpslib
  * LPSLibrary_CDI.XML - Log Parser Studio用のライブラリ
  * evtx_イベントID.sql - 特定のイベントIDのログを抽出するクエリ
* networkusageview-x64
  * NetworkUsageView.exe - SRUM(SRUDB.dat)のパーサ
* PyWMIPersistenceFinder
  * PyWMIPersistenceFinder.exe - WMI(OBJECTS.DATA)のパーサ
* Secure2Csv64
  * Secure2Csv64.exe - $SECUREのパーサ
* amcache.exe - Amcacheのパーサ
* mft.exe - MFTのパーサ
* ntuser.txt - regruns.exeで読み込むリストファイル
* prefetch.exe - プリフェッチのパーサ
* regruns.exe - Runキーなどの自動実行設定用キーのパーサ
* shimcache.exe - AppCompatCacheキーのパーサ
* software.txt - regruns.exeで読み込むリストファイル
* system.txt - regruns.exeで読み込むリストファイル
* usnjrnl.exe - UsnJrnlのパーサ

## 使い方

### BrowsingHistoryView.exe

https://www.nirsoft.net/utils/browsing_history_view.html を参照してください。

### NetworkUsageView.exe

https://www.nirsoft.net/utils/network_usage_view.html を参照してください。

### PyWMIPersistenceFinder.exe

https://github.com/davidpany/WMI_Forensics を参照してください。

### Secure2Csv64

https://github.com/jschicht/Secure2Csv を参照してください。

### その他のパーサ

コマンドプロンプト上で以下の形式で実行します。

`> プログラム -o 出力フォルダ 入力ファイルもしくは入力フォルダ`

入力ファイルは解析したいファイル、入力フォルダの場合はcdir-collectorで収集したデータフォルダを指定します。パース結果は、出力フォルダ配下に「プログラム名_output.csv」のファイル名規則で、タブ区切り、UTF-8で結果を出力します。
