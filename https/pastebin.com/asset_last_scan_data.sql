/*
Display Asset data including tag name and when the asset was last assessed for vulnerabilities.
*/


WITH asset_owners
     AS (SELECT DISTINCT asset_id,
                         Array_to_string(Array_agg(dt.tag_name), ',') AS owners
         FROM   dim_tag_asset dta
                JOIN dim_tag dt using (tag_id)
         WHERE  tag_type = 'OWNER'
         GROUP  BY asset_id),
     asset_locations
     AS (SELECT DISTINCT asset_id,
                         Array_to_string(Array_agg(dt.tag_name), ',') AS
                         locations
         FROM   dim_tag_asset dta
                JOIN dim_tag dt using (tag_id)
         WHERE  tag_type = 'LOCATION'
         GROUP  BY asset_id),
     asset_custom
     AS (SELECT DISTINCT asset_id,
                         Array_to_string(Array_agg(dt.tag_name), ',') AS custom
         FROM   dim_tag_asset dta
                JOIN dim_tag dt using (tag_id)
         WHERE  tag_type = 'CUSTOM'
         GROUP  BY asset_id),
     asset_sites
     AS (SELECT asset_id,
                Array_to_string(Array_agg(ds.NAME), ',') AS sites
         FROM   dim_site_asset dsa
                JOIN dim_site ds using(site_id)
         GROUP  BY asset_id),
     asset_os
     AS (SELECT asset_id,
                dos.description     AS OS,
                Max(daos.certainty) AS certainty
         FROM   dim_asset_operating_system daos
                JOIN dim_operating_system dos using(operating_system_id)
         GROUP  BY asset_id,
                   description)
SELECT ip_address,
       host_name,
       port,
       dp.NAME      AS protocol,
       ds.NAME      AS service,
       dsf.vendor,
       dsf.family,
       dsf.NAME,
       dsf.version,
       al.locations AS "Tag [Location]",
       ao.owners    AS "Tag [Owner]",
       ac.custom    AS "Tag [Custom]",
       asi.sites,
       aos.os,
       Round(Cast(aos.certainty AS NUMERIC), 2),
       To_char(da.last_assessed_for_vulnerabilities, 'dd/mm/yyyy')
FROM   dim_asset da
       JOIN dim_asset_service using (asset_id)
       JOIN dim_service ds using (service_id)
       JOIN dim_protocol dp using (protocol_id)
       JOIN dim_service_fingerprint dsf using (service_fingerprint_id)
       LEFT JOIN asset_owners ao using(asset_id)
       LEFT JOIN asset_locations al using(asset_id)
       LEFT JOIN asset_custom ac using(asset_id)
       JOIN asset_sites asi using(asset_id)
       JOIN asset_os aos using(asset_id)  
