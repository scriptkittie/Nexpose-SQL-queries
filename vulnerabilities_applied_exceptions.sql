/* This query will show all vulnerabilties with applied exceptions */

WITH
  vuln_title AS(
   SELECT title, severity, vulnerability_id FROM dim_vulnerability
  ),

  host AS(
   SELECT host_name, asset_id, sites FROM dim_asset
  ),

  host_vuln AS(
   SELECT asset_id, vulnerability_id, age_in_days, host_name, severity, title, sites FROM fact_asset_vulnerability_age
   JOIN vuln_title USING (vulnerability_id)
   JOIN host USING (asset_id)
  )

SELECT ds.site_id AS "Site ID", ds.name AS "Site Name", ds.description AS "Site Description",
ds.importance AS "Site Importance", hv.host_name AS "Asset Hostname", hv.title AS "Vulnerability Title",
hv.severity AS "Vulnerability Severity", hv.age_in_days AS "Vulnerability Age"
FROM dim_site ds
JOIN dim_site_asset dsa ON dsa.site_id = ds.site_id
JOIN host_vuln hv ON hv.asset_id = dsa.asset_id
JOIN dim_vulnerability_exception dve ON dve.vulnerability_id = hv.vulnerability_id AND dve.site_id = dsa.site_id
WHERE dve.reason_id = 'U'
