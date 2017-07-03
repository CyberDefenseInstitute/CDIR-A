SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 CASE EventID
  WHEN 104 THEN SID 
  WHEN 1102 THEN EXTRACT_TOKEN(Strings,0,'|') 
 END AS SID,
 CASE EventID
  WHEN 104 THEN EXTRACT_TOKEN(Strings,0,'|') 
  WHEN 1102 THEN EXTRACT_TOKEN(Strings,1,'|') 
 END AS ユーザ,
 CASE EventID
  WHEN 104 THEN EXTRACT_TOKEN(Strings,2,'|') 
  WHEN 1102 THEN 'Security' 
 END AS 消去ログ名,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC) 
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 SourceName='Microsoft-Windows-Eventlog' AND
 (
 EventID='104' OR
 EventID='1102'
 )
