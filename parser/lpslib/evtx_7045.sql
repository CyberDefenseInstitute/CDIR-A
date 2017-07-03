SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 SID, 
 EXTRACT_TOKEN(Strings,0,'|') AS サービス名,
 EXTRACT_TOKEN(Strings,1,'|') AS サービスファイル名,
 EXTRACT_TOKEN(Strings,2,'|') AS 種類,
 EXTRACT_TOKEN(Strings,3,'|') AS 開始の種類,
 EXTRACT_TOKEN(Strings,4,'|') AS アカウント,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC) 
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 EventID = '7045'
