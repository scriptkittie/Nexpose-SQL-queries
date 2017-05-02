/* This query displays all vulnerabilities that have been fixed per asset */

WITH
  site_last_scan AS (

   SELECT site_id,

  (SELECT scan_id AS last_scan

   FROM dim_site_scan

   JOIN dim_scan USING (scan_id)

   WHERE site_id = ds.site_id

   ORDER BY finished DESC

   LIMIT 1) AS last_scan

   FROM dim_site ds

  ),

  site_previous_scan AS (

   SELECT site_id,

  (SELECT scan_id AS last_scan

   FROM dim_site_scan

   JOIN dim_scan USING (scan_id)

   WHERE site_id = ds.site_id AND scan_id NOT IN (SELECT last_scan FROM site_last_scan WHERE site_id = ds.site_id)

   ORDER BY finished DESC

   LIMIT 1) AS previous_scan

   FROM dim_site ds

  ),


  last_asset_count AS (SELECT sls.site_id, count(fas.asset_id) AS last_asset_count

   FROM site_last_scan AS sls

   LEFT OUTER JOIN fact_asset_scan AS fas ON sls.last_scan = fas.scan_id

   GROUP BY sls.site_id),

  

  previous_asset_count AS (SELECT sps.site_id, count(fas.asset_id) AS previous_asset_count

   FROM site_previous_scan AS sps

   LEFT OUTER JOIN fact_asset_scan AS fas ON sps.previous_scan = fas.scan_id

   GROUP BY sps.site_id),


  last_vuln_count AS (SELECT sls.site_id, count(fasv.vulnerability_id) AS last_vuln_count

   FROM site_last_scan AS sls

   LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sls.last_scan = fasv.scan_id

   GROUP BY sls.site_id),


  previous_vuln_count AS (SELECT sps.site_id, count(fasv.vulnerability_id) AS previous_vuln_count

   FROM site_previous_scan AS sps

   LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sps.previous_scan = fasv.scan_id

   GROUP BY sps.site_id),


  asset_count_change AS (SELECT lac.site_id, (lac.last_asset_count - pac.previous_asset_count)  AS asset_count_change,

   CASE WHEN (lac.last_asset_count - pac.previous_asset_count) > 1000 THEN 'MEGA INCREASE'

   WHEN (lac.last_asset_count - pac.previous_asset_count) > 100 THEN 'SLIGHT INCREASE'

   WHEN (lac.last_asset_count - pac.previous_asset_count) > 10 THEN 'TINY INCREASE'

   WHEN (lac.last_asset_count - pac.previous_asset_count) < -1000 THEN 'MEGA DECREASE'

   WHEN (lac.last_asset_count - pac.previous_asset_count) < -100 THEN 'SLIGHT DECREASE'

   WHEN (lac.last_asset_count - pac.previous_asset_count) < -10 THEN 'TINY DECREASE'

   ELSE 'IGNORE'

   END AS asset_status

   FROM last_asset_count AS lac

   JOIN previous_asset_count AS pac ON lac.site_id = pac.site_id),


  vuln_count_change AS (SELECT lac.site_id, (lac.last_vuln_count - pac.previous_vuln_count) AS vuln_count_change,

   CASE WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 1000 THEN 'MEGA INCREASE'

   WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 100 THEN 'SLIGHT INCREASE'

   WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 10 THEN 'TINY INCREASE'

   WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -1000 THEN 'MEGA DECREASE'

   WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -100 THEN 'SLIGHT DECREASE'

   WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -10 THEN 'TINY DECREASE'

   ELSE 'IGNORE'

   END AS vuln_status

   FROM last_vuln_count AS lac

   JOIN previous_vuln_count AS pac ON lac.site_id = pac.site_id)


   SELECT ds.name, lac.last_asset_count, pac.previous_asset_count, lvc.last_vuln_count, pvc.previous_vuln_count, acc.asset_count_change, acc.asset_status, vcc.vuln_count_change, vcc.vuln_status

   FROM last_asset_count AS lac

   JOIN previous_asset_count AS pac ON lac.site_id = pac.site_id

   JOIN last_vuln_count AS lvc ON lac.site_id = lvc.site_id

   JOIN previous_vuln_count AS pvc ON lac.site_id = pvc.site_id

   JOIN asset_count_change AS acc ON lac.site_id = acc.site_id

   JOIN vuln_count_change AS vcc ON lac.site_id = vcc.site_id

   JOIN dim_site AS ds ON lac.site_id = ds.site_id
See the reply in context
No one else had this question
Outcomes

    Helpful(1)

Visibility: Nexpose836 Views
Last modified on Apr 17, 2017 2:03 PM
Tags:nexpose
Content tagged with nexpose
custom reporting
Content tagged with custom reporting

    4 Replies

    brett.deroche
    brett.deroche Apr 17, 2017 4:31 PM

    It seems like you're looking for a query similar to what glytch dome suggested on my post, Remediated SQL Query
    1 person found this helpful
    Like •
    Show 0 Likes
    0
    Actions
    glytch dome
    glytch dome Employee @ brett.deroche on Apr 18, 2017 12:38 PM

    Hello Brett.

     

    Mo,

     

    WITH
      site_last_scan AS (

       SELECT site_id,

      (SELECT scan_id AS last_scan

       FROM dim_site_scan

       JOIN dim_scan USING (scan_id)

       WHERE site_id = ds.site_id

       ORDER BY finished DESC

       LIMIT 1) AS last_scan

       FROM dim_site ds

      ),

      site_previous_scan AS (

       SELECT site_id,

      (SELECT scan_id AS last_scan

       FROM dim_site_scan

       JOIN dim_scan USING (scan_id)

       WHERE site_id = ds.site_id AND scan_id NOT IN (SELECT last_scan FROM site_last_scan WHERE site_id = ds.site_id)

       ORDER BY finished DESC

       LIMIT 1) AS previous_scan

       FROM dim_site ds

      ),


      last_asset_count AS (SELECT sls.site_id, count(fas.asset_id) AS last_asset_count

       FROM site_last_scan AS sls

       LEFT OUTER JOIN fact_asset_scan AS fas ON sls.last_scan = fas.scan_id

       GROUP BY sls.site_id),

      

      previous_asset_count AS (SELECT sps.site_id, count(fas.asset_id) AS previous_asset_count

       FROM site_previous_scan AS sps

       LEFT OUTER JOIN fact_asset_scan AS fas ON sps.previous_scan = fas.scan_id

       GROUP BY sps.site_id),


      last_vuln_count AS (SELECT sls.site_id, count(fasv.vulnerability_id) AS last_vuln_count

       FROM site_last_scan AS sls

       LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sls.last_scan = fasv.scan_id

       GROUP BY sls.site_id),


      previous_vuln_count AS (SELECT sps.site_id, count(fasv.vulnerability_id) AS previous_vuln_count

       FROM site_previous_scan AS sps

       LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sps.previous_scan = fasv.scan_id

       GROUP BY sps.site_id),


      asset_count_change AS (SELECT lac.site_id, (lac.last_asset_count - pac.previous_asset_count)  AS asset_count_change,

       CASE WHEN (lac.last_asset_count - pac.previous_asset_count) > 1000 THEN 'MEGA INCREASE'

       WHEN (lac.last_asset_count - pac.previous_asset_count) > 100 THEN 'SLIGHT INCREASE'

       WHEN (lac.last_asset_count - pac.previous_asset_count) > 10 THEN 'TINY INCREASE'

       WHEN (lac.last_asset_count - pac.previous_asset_count) < -1000 THEN 'MEGA DECREASE'

       WHEN (lac.last_asset_count - pac.previous_asset_count) < -100 THEN 'SLIGHT DECREASE'

       WHEN (lac.last_asset_count - pac.previous_asset_count) < -10 THEN 'TINY DECREASE'

       ELSE 'IGNORE'

       END AS asset_status

       FROM last_asset_count AS lac

       JOIN previous_asset_count AS pac ON lac.site_id = pac.site_id),


      vuln_count_change AS (SELECT lac.site_id, (lac.last_vuln_count - pac.previous_vuln_count) AS vuln_count_change,

       CASE WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 1000 THEN 'MEGA INCREASE'

       WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 100 THEN 'SLIGHT INCREASE'

       WHEN (lac.last_vuln_count - pac.previous_vuln_count) > 10 THEN 'TINY INCREASE'

       WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -1000 THEN 'MEGA DECREASE'

       WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -100 THEN 'SLIGHT DECREASE'

       WHEN (lac.last_vuln_count - pac.previous_vuln_count) < -10 THEN 'TINY DECREASE'

       ELSE 'IGNORE'

       END AS vuln_status

       FROM last_vuln_count AS lac

       JOIN previous_vuln_count AS pac ON lac.site_id = pac.site_id)


       SELECT ds.name, lac.last_asset_count, pac.previous_asset_count, lvc.last_vuln_count, pvc.previous_vuln_count, acc.asset_count_change, acc.asset_status, vcc.vuln_count_change, vcc.vuln_status

       FROM last_asset_count AS lac

       JOIN previous_asset_count AS pac ON lac.site_id = pac.site_id

       JOIN last_vuln_count AS lvc ON lac.site_id = lvc.site_id

       JOIN previous_vuln_count AS pvc ON lac.site_id = pvc.site_id

       JOIN asset_count_change AS acc ON lac.site_id = acc.site_id

       JOIN vuln_count_change AS vcc ON lac.site_id = vcc.site_id

       JOIN dim_site AS ds ON lac.site_id = ds.site_id
