SELECT 
 TimeGenerated AS 日時,
 ComputerName AS コンピュータ名,
 SID,
 Message AS 内容,
 TO_UTCTIME(TimeGenerated) AS 日時(UTC)
INTO 
 %OUTPUT%
FROM 
 %INPUT%
WHERE
 SourceName = 'EventLog' AND
 EventID = '6008'
