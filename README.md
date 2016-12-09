# cdir-analyzer (parser)

cdir-analyzer (parser)はcdir-collectorで収集したデータのパーサ群です。それぞれのファイルの役割は以下の通りです。

* regruns_src - regruns.exeのソースコード
* shimcache_src - shimcache.exeのソースコード
* LPSLibrary_CDI.XML - Log Parser Studio用のライブラリ
* amcache.py - Amcacheのパーサ
* ntuser.txt - regruns.exeで読み込むリストファイル
* prefetch.py - プリフェッチのパーサ
* regruns.exe - Runキーなどの自動実行設定用キーのパーサ
* requirements.txt - Pythonのパーサ実行に必要なモジュールを記載
* shimcache.exe - AppCompatCacheキーのパーサ
* software.txt - regruns.exeで読み込むリストファイル
* system.txt - regruns.exeで読み込むリストファイル
* usnjrnl.py - UsnJrnlのパーサ

# 使い方

拡張子py、exeのファイルをコマンドプロンプト上で以下の形式で実行します。

`> プログラム -o 出力フォルダ 入力フォルダ`

入力フォルダはcdir-collectorで収集したデータフォルダを指定します。パース結果は、出力フォルダ配下に「プログラム名_output.csv」のファイル名規則で、タブ区切り、UTF-8で結果を出力します。
