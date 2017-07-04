/*
Display's a report that shows hostname remediations and vulnerabilitites by the application name
*/

WITH remediations AS (
    SELECT DISTINCT fr.solution_id AS ultimate_soln_id, assets as assets_affected, solution_type, vulnerabilities, url, summary, fix, assets, dshs.solution_id AS solution_id
    FROM fact_remediation(20000,'riskscore DESC') fr
    JOIN dim_solution ds USING (solution_id)
    JOIN dim_solution_highest_supercedence dshs ON (fr.solution_id = dshs.superceding_solution_id AND ds.solution_id = dshs.superceding_solution_id)
),
owner_map as (
		SELECT
		dta.asset_id,
		array_to_string(array_agg(dt.tag_name), ', ') AS owner_name
		FROM dim_tag_asset dta
		JOIN dim_tag dt ON dt.tag_id=dta.tag_id
		WHERE dt.tag_type = 'OWNER'
		GROUP BY dta.asset_id
		ORDER BY dta.asset_id ASC
),
app_map as (
        SELECT
        dta.asset_id,
        dt.tag_name as app_name
        FROM dim_tag_asset dta
        JOIN dim_tag dt ON dt.tag_id=dta.tag_id
        WHERE dt.tag_name like 'app_%'
),
assets AS (
    SELECT DISTINCT asset_id, host_name, ip_address, name as os
    FROM dim_asset
    JOIN dim_operating_system USING (operating_system_id)
    GROUP BY asset_id, host_name, ip_address, name
)
 
SELECT DISTINCT
   app_name as "System (Application) Name",
   host_name as "Hostname",
   summary as "Remediation",
   vulnerabilities AS "Vulnerabilities Affected (Count)",
   owner_name as "Owner"
 
FROM remediations r
   JOIN dim_asset_vulnerability_solution dvs USING (solution_id)
   JOIN dim_vulnerability dv USING (vulnerability_id)
   JOIN assets USING (asset_id)
   JOIN owner_map USING (asset_id)
   JOIN app_map USING(asset_id)
WHERE cvss_score >= 7
GROUP BY app_name, host_name, summary, vulnerabilities, owner_name
