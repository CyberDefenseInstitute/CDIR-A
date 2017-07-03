# cdir-analyzer (parser)

## 概要

cdir-analyzer (parser)はcdir-collectorで収集したデータのパーサ群です。

## 内容

* lpslib
  * LPSLibrary_CDI.XML - Log Parser Studio用のライブラリ
  * evtx_イベントID.sql - 特定のイベントIDのログを抽出するクエリ
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

コマンドプロンプト上で以下の形式で実行します。

`> プログラム -o 出力フォルダ 入力ファイルもしくは入力フォルダ`

入力ファイルは解析したいファイル、入力フォルダの場合はcdir-collectorで収集したデータフォルダを指定します。パース結果は、出力フォルダ配下に「プログラム名_output.csv」のファイル名規則で、タブ区切り、UTF-8で結果を出力します。
