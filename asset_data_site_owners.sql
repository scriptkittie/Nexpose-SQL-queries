/*
Display asset data including site owners
*/

/*
Display asset data including site owners
*/

WITH asset_owners AS
(
                SELECT DISTINCT asset_id,
                                Array_to_string(Array_agg(dt.tag_name), ',') AS owners
                FROM            dim_tag_asset dta
                JOIN            dim_tag dt
                using           (tag_id)
                WHERE           tag_type='OWNER'
                GROUP BY        asset_id ), asset_locations AS
(
                SELECT DISTINCT asset_id,
                                Array_to_string(Array_agg(dt.tag_name), ',') AS locations
                FROM            dim_tag_asset dta
                JOIN            dim_tag dt
                using           (tag_id)
                WHERE           tag_type='LOCATION'
                GROUP BY        asset_id ), asset_custom AS
(
                SELECT DISTINCT asset_id,
                                Array_to_string(Array_agg(dt.tag_name), ',') AS custom
                FROM            dim_tag_asset dta
                JOIN            dim_tag dt
                using           (tag_id)
                WHERE           tag_type='CUSTOM'
                GROUP BY        asset_id ), asset_sites AS
(
         SELECT   asset_id,
                  Array_to_string(Array_agg(ds.NAME), ',') AS sites
         FROM     dim_site_asset dsa
         JOIN     dim_site ds
         using   (site_id)
         GROUP BY asset_id ), asset_os AS
(
         SELECT   asset_id,
                  dos.description     AS os,
                  Max(daos.certainty) AS certainty
         FROM     dim_asset_operating_system daos
         JOIN     dim_operating_system dos
         using   (operating_system_id)
         GROUP BY asset_id,
                  description )
SELECT    da.ip_address               AS "Address",
          da.host_name                AS "Name",
          asi.sites                   AS "Site",
          aos.os                      AS "Operating System",
          fa.exploits                 AS "Exploits",
          fa.malware_kits             AS "Malware",
          fa.moderate_vulnerabilities AS "Moderate",
          fa.severe_vulnerabilities   AS "Severe",
          fa.critical_vulnerabilities AS "Critical",
          fa.vulnerabilities          AS "Vulnerabilities",
          al.locations                AS "Tag [Location]",
          ao.owners                   AS "Tag [Owner]",
          CASE
                    WHEN aos.certainty = '1' THEN "PASS"
                    ELSE "FAIL" END AS "Authentication"
                    FROM      fact_asset fa
                    JOIN      dim_asset da
                    using    (asset_id)
                    LEFT JOIN asset_owners ao
                    using    (asset_id)
                    LEFT JOIN asset_locations al
                    using    (asset_id)
                    LEFT JOIN asset_custom ac
                    using    (asset_id)
                    JOIN      asset_sites asi
                    using    (asset_id)
                    JOIN      asset_os aos
using (asset_id) 
