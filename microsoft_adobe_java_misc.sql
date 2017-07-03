/*
A report which shows Microsoft, Java, Adobe, and other software vulnerabilities, and the associated risks. Report also shows old and new vulnerabilities.
*/

 WITH timestamps AS
(
       SELECT Date (ts)                                                                 AS upper_date,
              date (ts               - interval '1 months')                             AS lower_date
       FROM   generate_series (now() - interval '12 months', now(), interval '1 month') AS ts), total_date AS
(
       SELECT ts.lower_date   AS date,
              'Total' :: text AS change
       FROM   timestamps ts), new_date AS
(
       SELECT ts.lower_date AS date,
              'New' :: text AS change
       FROM   timestamps ts), same_date AS
(
       SELECT ts.lower_date  AS date,
              'Same' :: text AS change
       FROM   timestamps ts), old_date AS
(
       SELECT ts.lower_date AS date,
              'Old' :: text AS change
       FROM   timestamps ts), asset_scans AS
(
           SELECT     da.asset_id,
                      ts.lower_date,
                      ts.upper_date,
                      scanasof (da.asset_id, ts.lower_date) AS previous_scan,
                      scanasof (da.asset_id, ts.upper_date) AS current_scan
           FROM       dim_asset                             AS da
           CROSS JOIN timestamps ts
           ORDER BY   asset_id,
                      lower_date), asset_current_vulnerabilities AS
(
       SELECT ac.asset_id,
              upper_date AS date,
              scan_id,
              ac.current_scan,
              vulnerability_id,
              category_name,
              riskscore
       FROM   asset_scans ac
       JOIN   fact_asset_scan_vulnerability_finding fasvf
       ON     fasvf.asset_id = ac.asset_id
       AND    fasvf.scan_id = current_scan
       JOIN   dim_vulnerability dv
       using  (vulnerability_id)
       JOIN   dim_vulnerability_category dvc
       using  (vulnerability_id)
       WHERE  ((
                            extract (year FROM fasvf. date) * 100) + extract (month FROM fasvf. date)) = ((extract (year FROM dv.date_published) * 100) + extract (month FROM dv.date_published))), difference AS
(
         SELECT   asset_id,
                  date,
                  vulnerability_id,
                  baselinecomparison (scan_id, current_scan) AS change,
                  category_name,
                  riskscore
         FROM     asset_current_vulnerabilities
         GROUP BY asset_id,
                  date,
                  vulnerability_id,
                  category_name,
                  riskscore), microsoft_category_risk_total AS
(
         SELECT   date,
                  'Total' :: text AS change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    category_name LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), microsoft_category_risk_new AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'New'
         AND      category_name LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), microsoft_category_risk_old AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Old'
         AND      category_name LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), microsoft_category_risk_same AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Same'
         AND      category_name LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), java_category_risk_total AS
(
         SELECT   date,
                  'Total' :: text AS change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    category_name LIKE '%Java%'
         GROUP BY date,
                  change,
                  category_name), java_category_risk_new AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'New'
         AND      category_name LIKE '%Java%'
         GROUP BY date,
                  change,
                  category_name), java_category_risk_old AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Old'
         AND      category_name LIKE '%Java%'
         GROUP BY date,
                  change,
                  category_name), java_category_risk_same AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Same'
         AND      category_name LIKE '%Java%'
         GROUP BY date,
                  change,
                  category_name), adobe_category_risk_total AS
(
         SELECT   date,
                  'Total' :: text AS change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    category_name LIKE 'Adobe'
         GROUP BY date,
                  change,
                  category_name), adobe_category_risk_new AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'New'
         AND      category_name LIKE 'Adobe'
         GROUP BY date,
                  change,
                  category_name), adobe_category_risk_old AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Old'
         AND      category_name LIKE 'Adobe'
         GROUP BY date,
                  change,
                  category_name), adobe_category_risk_same AS
(
         SELECT   date,
                  change,
                  category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Same'
         AND      category_name LIKE 'Adobe'
         GROUP BY date,
                  change,
                  category_name), other_category_risk_total AS
(
         SELECT   date,
                  'Total' :: text              AS change,
                  'Other' :: text              AS category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    category_name NOT LIKE 'Adobe'
         AND      category_name NOT LIKE '%Java%'
         AND      category_name NOT LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), other_category_risk_new AS
(
         SELECT   date,
                  change,
                  'Other' :: text              AS category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'New'
         AND      category_name NOT LIKE 'Adobe'
         AND      category_name NOT LIKE '%Java%'
         AND      category_name NOT LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), other_category_risk_old AS
(
         SELECT   date,
                  change,
                  'Other' :: text              AS category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Old'
         AND      category_name NOT LIKE 'Adobe'
         AND      category_name NOT LIKE '%Java%'
         AND      category_name NOT LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), other_category_risk_same AS
(
         SELECT   date,
                  change,
                  'Other' :: text              AS category_name,
                  COALESCE (sum(riskscore), 0) AS risk
         FROM     difference
         WHERE    change LIKE 'Same'
         AND      category_name NOT LIKE 'Adobe'
         AND      category_name NOT LIKE '%Java%'
         AND      category_name NOT LIKE 'Microsoft'
         GROUP BY date,
                  change,
                  category_name), microsoft_total AS
(
                SELECT          nd.date,
                                nd.change,
                                'Microsoft' :: text AS category_name,
                                COALESCE(risk,0)    AS risk
                FROM            total_date nd
                LEFT OUTER JOIN microsoft_category_risk_total cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), microsoft_new AS
(
                SELECT          nd.date,
                                nd.change,
                                'Microsoft' :: text AS category_name,
                                COALESCE(risk,0)    AS risk
                FROM            new_date nd
                LEFT OUTER JOIN microsoft_category_risk_new cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), microsoft_old AS
(
                SELECT          nd.date,
                                nd.change,
                                'Microsoft' :: text AS category_name,
                                COALESCE(risk,0)    AS risk
                FROM            old_date nd
                LEFT OUTER JOIN microsoft_category_risk_old cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), microsoft_same AS
(
                SELECT          nd.date,
                                nd.change,
                                'Microsoft' :: text AS category_name,
                                COALESCE(risk,0)    AS risk
                FROM            same_date nd
                LEFT OUTER JOIN microsoft_category_risk_same cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), java_total AS
(
                SELECT          nd.date,
                                nd.change,
                                'Java' :: text   AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            total_date nd
                LEFT OUTER JOIN java_category_risk_total cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), java_new AS
(
                SELECT          nd.date,
                                nd.change,
                                'Java' :: text   AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            new_date nd
                LEFT OUTER JOIN java_category_risk_new cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), java_old AS
(
                SELECT          nd.date,
                                nd.change,
                                'Java' :: text   AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            old_date nd
                LEFT OUTER JOIN java_category_risk_old cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), java_same AS
(
                SELECT          nd.date,
                                nd.change,
                                'Java' :: text   AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            same_date nd
                LEFT OUTER JOIN java_category_risk_same cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), adobe_total AS
(
                SELECT          nd.date,
                                nd.change,
                                'Adobe' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            total_date nd
                LEFT OUTER JOIN adobe_category_risk_total cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), adobe_new AS
(
                SELECT          nd.date,
                                nd.change,
                                'Adobe' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            new_date nd
                LEFT OUTER JOIN adobe_category_risk_new cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), adobe_old AS
(
                SELECT          nd.date,
                                nd.change,
                                'Adobe' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            old_date nd
                LEFT OUTER JOIN adobe_category_risk_old cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), adobe_same AS
(
                SELECT          nd.date,
                                nd.change,
                                'Adobe' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            same_date nd
                LEFT OUTER JOIN adobe_category_risk_same cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), other_total AS
(
                SELECT          nd.date,
                                nd.change,
                                'Other' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            total_date nd
                LEFT OUTER JOIN other_category_risk_total cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), other_new AS
(
                SELECT          nd.date,
                                nd.change,
                                'Other' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            new_date nd
                LEFT OUTER JOIN other_category_risk_new cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), other_old AS
(
                SELECT          nd.date,
                                nd.change,
                                'Other' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            old_date nd
                LEFT OUTER JOIN other_category_risk_old cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change), other_same AS
(
                SELECT          nd.date,
                                nd.change,
                                'Other' :: text  AS category_name,
                                COALESCE(risk,0) AS risk
                FROM            same_date nd
                LEFT OUTER JOIN other_category_risk_same cgn
                ON              nd.date = cgn.date
                AND             nd.change = cgn.change)
SELECT *
FROM   microsoft_new
UNION
SELECT *
FROM   microsoft_old
UNION
SELECT *
FROM   microsoft_new
UNION
SELECT *
FROM   microsoft_same
UNION
SELECT *
FROM   java_old
UNION
SELECT *
FROM   java_new
UNION
SELECT *
FROM   java_same
UNION
SELECT *
FROM   adobe_old
UNION
SELECT *
FROM   adobe_new
UNION
SELECT *
FROM   adobe_same
UNION
SELECT *
FROM   other_old
UNION
SELECT *
FROM   other_new
UNION
SELECT *
FROM   other_same
UNION
SELECT *
FROM   microsoft_total
UNION
SELECT *
FROM   java_total
UNION
SELECT *
FROM   adobe_total
UNION
SELECT   *
FROM     other_total
ORDER BY date ASC,
         category_name,
         change 
