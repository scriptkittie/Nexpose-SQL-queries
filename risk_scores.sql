/* This query will show asset and vulnerability information for all vulnerabilities with a certain cvss_score and riskscore */

SELECT dv.title, dv.cvss_score, dv.riskscore, da.asset_id, da.ip_address, da.mac_address,
da.host_name, da.host_type_id, da.sites
FROM dim_vulnerability dv
JOIN fact_asset_scan_vulnerability_instance AS favi ON favi.vulnerability_id = dv.vulnerability_id
JOIN dim_asset da ON da.asset_id = favi.asset_id
WHERE cvss_score = 10 AND riskscore > 950 

/* Replace 10 and 950 with your score designations */
