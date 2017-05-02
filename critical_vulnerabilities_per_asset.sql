/* This query displays all Critical level vulnerabilities published within the last 7 days from a specific Asset Group */

SELECT da.ip_address AS "Asset IP", da.host_name AS "Asset Name", fa.critical_vulnerabilities AS "Critical Vulns",
fa.exploits AS "Exploits", fa.malware_kits as "Malware", fa.riskscore AS "Risk Score"
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da ON da.asset_id = favf.asset_id
JOIN fact_asset fa ON fa.asset_id = da.asset_id
WHERE fa.scan_finished >  current_date - interval '7 days'
