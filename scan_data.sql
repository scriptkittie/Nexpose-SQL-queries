/* This SQL query displays vulnerability scan data from a specific scan
 * Replace 'xx' with your designated scan identifier */

SELECT dsi.name AS "Site Name", da.asset_id as "AssetID", da.host_name AS "Host Name", da.ip_address AS "IP Address", dos.description AS "Operating System", 
ds.name AS "Service Name", dp.name AS "Protocol Name", dp.description AS "Protocol Description",
das.port AS "Port", dsf.vendor AS "Service Fingerprint Vendor", dsf.family AS "Service Fingerprint Family", dsf.name AS "Service Fingerprint Name", dsf.version AS "Service Fingerprint Version",
das.certainty AS "Certainty",
to_char (fa.scan_finished, 'YYYY-MM-DD') AS "Last Scan"
FROM dim_asset da
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_asset_service das USING (asset_id)
JOIN dim_service ds USING (service_id)
JOIN dim_protocol dp USING (protocol_id)
JOIN dim_service_fingerprint dsf USING (service_fingerprint_id)
JOIN dim_site_asset USING (asset_id)
JOIN dim_site dsi USING (site_id)
JOIN fact_asset fa USING (asset_id)
JOIN dim_asset_scan dsa ON (dsa.asset_id = da.asset_id)
JOIN dim_scan ds2 ON (dsa.scan_id = ds2.scan_id)
WHERE da.sites = '_FID - External Assets - External Scan Engine' AND ds2.scan_id = xx
ORDER BY da.ip_address
