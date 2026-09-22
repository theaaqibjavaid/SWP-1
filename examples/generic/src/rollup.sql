-- Rollup of settled invoices per region, kept as SQL because a `.sql` file has
-- no SWP-1 adapter either: nothing in this build reads literals in it at all.
-- See ../README.md.

CREATE VIEW region_rollup AS
SELECT i.region AS region,
       COUNT(*) AS settled_count,
       SUM(i.total_cents) AS settled_cents,
       MAX(i.total_cents) AS largest_cents
FROM invoice AS i
WHERE i.state = 'settled'
  AND i.total_cents > 1500
GROUP BY i.region
HAVING COUNT(*) >= 3;

CREATE INDEX invoice_region_state ON invoice (region, state);
