SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 EXTRACT_TOKEN(Strings,0,'|') AS 現SID,
 EXTRACT_TOKEN(Strings,1,'|') AS 現アカウント,
 EXTRACT_TOKEN(Strings,2,'|') AS 現ドメイン,
 EXTRACT_TOKEN(Strings,3,'|') AS 現ログオンID,
 EXTRACT_TOKEN(Strings,5,'|') AS 指定アカウント,
 EXTRACT_TOKEN(Strings,6,'|') AS 指定ドメイン,
 EXTRACT_TOKEN(Strings,7,'|') AS 指定ログオンGUID,
 EXTRACT_TOKEN(Strings,8,'|') AS ターゲット,
 EXTRACT_TOKEN(Strings,10,'|') AS プロセスID,
 EXTRACT_TOKEN(Strings,11,'|') AS プロセス,
 EXTRACT_TOKEN(Strings,12,'|') AS IPアドレス,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC)
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 SourceName = 'Microsoft-Windows-Security-Auditing' AND
 EventID = 4648 AND
 プロセス <> 'C:\Windows\System32\taskhost.exe' AND 
 プロセス <> 'C:\Windows\System32\taskeng.exe' AND NOT
 (ターゲット = 'localhost' AND IPアドレス = '-') AND NOT 
 (ターゲット = 'localhost' AND IPアドレス = '127.0.0.1') AND NOT
 (ターゲット = 'localhost' AND IPアドレス = '::1')
