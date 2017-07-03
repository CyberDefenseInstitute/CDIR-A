SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 EXTRACT_TOKEN(Strings,4,'|') AS SID,
 EXTRACT_TOKEN(Strings,5,'|') AS ユーザ,
 EXTRACT_TOKEN(Strings,6,'|') AS ドメイン,
 EXTRACT_TOKEN(Strings,7,'|') AS ログオンID,
 EXTRACT_TOKEN(Strings,9,'|') AS ログオンプロセス,
 EXTRACT_TOKEN(Strings,10,'|') AS 認証パッケージ,
 EXTRACT_TOKEN(Strings,11,'|') AS ワークステーション名,
 EXTRACT_TOKEN(Strings,12,'|') AS ログオンGUID,
 EXTRACT_TOKEN(Strings,16,'|') AS プロセスID,
 EXTRACT_TOKEN(Strings,17,'|') AS プロセス名, 
 EXTRACT_TOKEN(Strings,18,'|') AS IPアドレス,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC) 
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 SourceName = 'Microsoft-Windows-Security-Auditing' AND
 EventID = 4624 AND
 EXTRACT_TOKEN(Strings,8,'|') = '10'
