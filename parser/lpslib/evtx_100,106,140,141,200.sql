SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 SID,
 EXTRACT_TOKEN(Strings,0,'|') AS ジョブ名,
 EXTRACT_TOKEN(Strings,1,'|') AS ユーザ/プログラム,
 CASE EventID
  WHEN 100 THEN '開始(ユーザ)'
  WHEN 106 THEN '登録'
  WHEN 140 THEN '更新'
  WHEN 141 THEN '削除'
  WHEN 200 THEN '開始(プログラム)'
 END AS 理由,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC) 
INTO
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 SourceName='Microsoft-Windows-TaskScheduler' AND 
 (
 EventID='100' OR
 EventID='106' OR
 EventID='140' OR
 EventID='141' OR
 EventID='200' 
 )
