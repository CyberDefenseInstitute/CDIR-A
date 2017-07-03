SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 SID,
 CASE EventID
  WHEN 12 THEN '起動'
  WHEN 13 THEN '停止'
 END AS 理由,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC)
INTO
 %OUTPUT%
FROM
 %INPUT%
WHERE 
 SourceName='Microsoft-Windows-Kernel-General' AND (EventID='12' OR EventID='13')