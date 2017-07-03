SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 SID,
 TO_LOCALTIME(TO_TIMESTAMP(SUBSTR(EXTRACT_TOKEN(Strings,0,'|'), 0, 19), 'yyyy-MM-dd?hh:mm:ss')) AS 変更前(ローカル),
 TO_INT(SUB(TO_TIMESTAMP(SUBSTR(EXTRACT_TOKEN(Strings,0,'|'), 0, 19), 'yyyy-MM-dd?hh:mm:ss'), TO_TIMESTAMP(SUBSTR(EXTRACT_TOKEN(Strings,1,'|'), 0, 19), 'yyyy-MM-dd?hh:mm:ss'))) AS 差分秒,
 EXTRACT_TOKEN(Strings,1,'|') AS 変更前,
 EXTRACT_TOKEN(Strings,0,'|') AS 変更後,
 CASE SourceName
  WHEN 'Microsoft-Windows-Kernel-General' THEN '時刻変更'
  WHEN 'Microsoft-Windows-Power-Troubleshooter' THEN 'スリープ再開'
 END AS 理由,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC)
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 EventID='1'
 AND (SourceName='Microsoft-Windows-Kernel-General' OR SourceName='Microsoft-Windows-Power-Troubleshooter')
 AND 差分秒 <>0
 AND 差分秒 <>-1
 AND 差分秒 <>1
