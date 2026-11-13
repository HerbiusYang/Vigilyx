-- Run against disposable tables with the two login trigger functions from
-- infra/migrate.rs installed. Never run this fixture on the application DB.
-- Runner: scripts/test-login-hourly-trigger.py --image <local PostgreSQL 17 image>
SET TIME ZONE 'Asia/Shanghai';
CREATE FUNCTION assert_login_rollup() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        (SELECT hour_start, protocol, login_count, success_count, failed_count FROM external_login_hourly
         EXCEPT
         SELECT date_trunc('hour', started_at_ts), upper(protocol), count(*),
                count(*) FILTER (WHERE auth_info->>'auth_success' = 'true'),
                count(*) FILTER (WHERE auth_info->>'auth_success' = 'false')
         FROM sessions WHERE started_at_ts IS NOT NULL AND
           ((upper(protocol) IN ('SMTP', 'HTTP') AND auth_info IS NOT NULL)
             OR upper(protocol) IN ('POP3', 'IMAP')) GROUP BY 1, 2)
        UNION ALL
        (SELECT date_trunc('hour', started_at_ts), upper(protocol), count(*),
                count(*) FILTER (WHERE auth_info->>'auth_success' = 'true'),
                count(*) FILTER (WHERE auth_info->>'auth_success' = 'false')
         FROM sessions WHERE started_at_ts IS NOT NULL AND
           ((upper(protocol) IN ('SMTP', 'HTTP') AND auth_info IS NOT NULL)
             OR upper(protocol) IN ('POP3', 'IMAP')) GROUP BY 1, 2
         EXCEPT SELECT hour_start, protocol, login_count, success_count, failed_count FROM external_login_hourly)
    ) THEN RAISE EXCEPTION 'hourly totals differ from authoritative sessions'; END IF;
    IF EXISTS (
        (SELECT hour_start, client_ip FROM external_login_hourly_sources EXCEPT
         SELECT DISTINCT date_trunc('hour', started_at_ts), client_ip FROM sessions
         WHERE started_at_ts IS NOT NULL AND ((upper(protocol) IN ('SMTP','HTTP') AND auth_info IS NOT NULL)
           OR upper(protocol) IN ('POP3','IMAP')))
        UNION ALL
        (SELECT DISTINCT date_trunc('hour', started_at_ts), client_ip FROM sessions
         WHERE started_at_ts IS NOT NULL AND ((upper(protocol) IN ('SMTP','HTTP') AND auth_info IS NOT NULL)
           OR upper(protocol) IN ('POP3','IMAP'))
         EXCEPT SELECT hour_start, client_ip FROM external_login_hourly_sources)
    ) THEN RAISE EXCEPTION 'source IP rollup differs from authoritative sessions'; END IF;
END $$;
INSERT INTO sessions VALUES
 ('a','2026-11-13 08:00:00+08','SMTP','{"auth_success":true}','192.0.2.1'),
 ('b','2026-11-13 08:59:59.999999+08','HTTP','{"auth_success":false}','192.0.2.1'),
 ('c','2026-11-13 09:00:00+08','IMAP',NULL,'192.0.2.1'),
 ('d','2026-11-13 08:30:00+08','POP3',NULL,'192.0.2.2'),
 ('e','2026-11-13 08:30:00+08','HTTP',NULL,'192.0.2.3'),
 ('f',NULL,'SMTP','{"auth_success":true}','192.0.2.4');
SELECT assert_login_rollup();
CREATE TEMP TABLE old_hourly AS SELECT hour_start, protocol, ctid::text AS tuple_id FROM external_login_hourly;
CREATE TEMP TABLE old_sources AS SELECT hour_start, client_ip, ctid::text AS tuple_id FROM external_login_hourly_sources;
UPDATE sessions SET started_at_ts=COALESCE(started_at_ts, started_at_ts),
 protocol=protocol, auth_info=auth_info, client_ip=client_ip;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM old_hourly o JOIN external_login_hourly h USING(hour_start,protocol) WHERE o.tuple_id<>h.ctid::text)
 OR EXISTS (SELECT 1 FROM old_sources o JOIN external_login_hourly_sources s USING(hour_start,client_ip) WHERE o.tuple_id<>s.ctid::text)
 THEN RAISE EXCEPTION 'no-op replay rewrote aggregate rows'; END IF;
END $$;
SELECT assert_login_rollup();
UPDATE sessions SET auth_info='{"auth_success":false}' WHERE id='a';
SELECT assert_login_rollup();
UPDATE sessions SET client_ip='192.0.2.9', started_at_ts='2026-11-13 09:00:00+08' WHERE id='a';
SELECT assert_login_rollup();
DELETE FROM sessions WHERE id='b'; -- the adjacent hour must not retain this source
SELECT assert_login_rollup();
UPDATE sessions SET protocol='HTTP' WHERE id='d'; -- eligibility removed
UPDATE sessions SET auth_info='{"auth_success":true}' WHERE id='e'; -- eligibility added
UPDATE sessions SET started_at_ts='2026-11-13 10:00:00+08' WHERE id='f'; -- legacy null timestamp
SELECT assert_login_rollup();
UPDATE sessions SET protocol='IMAP' WHERE id='a'; -- protocol changes within a source/hour
SELECT assert_login_rollup();
DELETE FROM sessions;
SELECT assert_login_rollup();
