/*
Display's a report that shows hostname remediations and vulnerabilitites by the application name with extra asset information.
*/

WITH assets_vulns
     AS (SELECT fasv.asset_id,
                fasv.vulnerability_id,
                Baselinecomparison (fasv.scan_id, current_scan) AS baseline,
                s.baseline_scan,
                s.current_scan
         FROM   fact_asset_scan_vulnerability_instance fasv
                JOIN (SELECT asset_id,
                             Previousscan (asset_id) AS baseline_scan,
                             Lastscan (asset_id)     AS current_scan
                      FROM   dim_asset da) s
                  ON s.asset_id = fasv.asset_id
                     AND ( fasv.scan_id = s.baseline_scan
                            OR fasv.scan_id = s.current_scan )
         GROUP  BY fasv.asset_id,
                   fasv.vulnerability_id,
                   s.baseline_scan,
                   s.current_scan
         HAVING ( Baselinecomparison (fasv.scan_id, current_scan) = 'Same' )
                 OR ( Baselinecomparison (fasv.scan_id, current_scan) = 'New' )
                 OR ( Baselinecomparison (fasv.scan_id, current_scan) = 'Old' ))
,
     baseline_scan_date
     AS (SELECT av.asset_id,
                finished
         FROM   assets_vulns av
                LEFT JOIN dim_scan ds
                       ON ds.scan_id = av.baseline_scan
         GROUP  BY av.asset_id,
                   finished),
     current_scan_date
     AS (SELECT Max(pass_fail) AS pass_fail,
                finished,
                asset_id
         FROM   (SELECT av.asset_id,
                        finished,
                        CASE
                          WHEN fa.aggregated_credential_status_id > 2
                               AND fa.aggregated_credential_status_id != '-1'
                        THEN
                          'Pass'
                          ELSE 'Fail'
                        END AS pass_fail
                 FROM   assets_vulns av
                        LEFT JOIN dim_scan ds
                               ON ds.scan_id = av.current_scan
                        JOIN fact_asset fa
                          ON fa.last_scan_id = ds.scan_id
                        JOIN dim_aggregated_credential_status dacs
                          ON
dacs.aggregated_credential_status_id = fa.aggregated_credential_status_id
         GROUP  BY av.asset_id,
                   finished,
                   fa.aggregated_credential_status_id) AS temp
 GROUP  BY asset_id,
           finished),
     existing_vulns
     AS (SELECT av.asset_id,
                Count (av.vulnerability_id) AS existing_vulns
         FROM   assets_vulns AS av
         WHERE  av.baseline = 'Same'
         GROUP  BY av.asset_id),
     new_vulns
     AS (SELECT av.asset_id,
                Count (av.vulnerability_id) AS new_vulns
         FROM   assets_vulns AS av
         WHERE  av.baseline = 'New'
         GROUP  BY av.asset_id),
     remediated_vulns
     AS (SELECT av.asset_id,
                Count (av.vulnerability_id) AS remediated_vulns
         FROM   assets_vulns AS av
         WHERE  av.baseline = 'Old'
         GROUP  BY av.asset_id),
     owner_map
     AS (SELECT dta.asset_id,
                Array_to_string(Array_agg(dt.tag_name), ', ') AS owner_name
         FROM   dim_tag_asset dta
                JOIN dim_tag dt
                  ON dt.tag_id = dta.tag_id
         WHERE  dt.tag_type = 'OWNER'
         GROUP  BY dta.asset_id
         ORDER  BY dta.asset_id ASC),
     app_map
     AS (SELECT dta.asset_id,
                dt.tag_name AS app_name
         FROM   dim_tag_asset dta
                JOIN dim_tag dt
                  ON dt.tag_id = dta.tag_id
         WHERE  dt.tag_name LIKE 'app_%'),
     final
     AS (SELECT am.app_name                       AS
                "System (Gilead Application)",
                COALESCE(da.host_name, 'N/A')     AS "Hostname",
                ( COALESCE (ev.existing_vulns, 0)
                  + COALESCE (rv.remediated_vulns, 0)
                  + COALESCE (nv.new_vulns, 0) )  AS
                "Total Vulnerabilities Count",
                COALESCE (ev.existing_vulns, 0)   AS
                "Existing Vulnerabilities Count"
                ,
                COALESCE (nv.new_vulns, 0)        AS
                "New Vulnerabilities Count",
                COALESCE (rv.remediated_vulns, 0) AS
                "Remediated Vulnerabilities Count",
                csd.pass_fail                     AS "Auth Pass / Fail Total",
                om.owner_name                     AS "Owner"
         FROM   existing_vulns AS ev
                FULL JOIN remediated_vulns AS rv
                       ON ev.asset_id = rv.asset_id
                FULL JOIN new_vulns AS nv
                       ON ev.asset_id = nv.asset_id
                JOIN dim_asset AS da
                  ON da.asset_id = ev.asset_id
                JOIN app_map am
                  ON am.asset_id = da.asset_id
                JOIN owner_map AS om
                  ON ev.asset_id = om.asset_id
                JOIN dim_operating_system dos
                  ON da.operating_system_id = dos.operating_system_id
                LEFT JOIN baseline_scan_date bsd
                       ON bsd.asset_id = da.asset_id
                LEFT JOIN current_scan_date csd
                       ON csd.asset_id = da.asset_id)
SELECT *
FROM   final  
