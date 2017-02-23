/* 
* This query will show all scan results within a certain time limit and under a certain certainty 
* The default is set to a certainty of 1 and a date range of 14 days
*/

SELECT dsite.name AS Site, da.ip_address, da.host_name, dos.description AS OS, max(daos.certainty) AS Certainty, date(fa.scan_finished) 
FROM dim_asset AS da 
JOIN dim_operating_system AS dos USING (operating_system_id) 
JOIN dim_asset_operating_system AS daos USING (asset_id) 
JOIN dim_site_asset AS dsa ON da.asset_id = dsa.asset_id 
JOIN dim_site AS dsite ON dsa.site_id = dsite.site_id 
JOIN fact_asset AS fa ON da.asset_id = fa.asset_id 
WHERE certainty <= 1 AND date(fa.scan_finished) > CURRENT_DATE - interval '14 days' 
GROUP BY dsite.name, da.ip_address, da.host_name, dos.description, fa.scan_finished 
ORDER BY dsite.name, da.ip_address ASC
