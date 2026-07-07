BEGIN;

ALTER TABLE runs ADD COLUMN IF NOT EXISTS customer_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS tenant_id varchar(128) NOT NULL DEFAULT 'unknown';

ALTER TABLE events ADD COLUMN IF NOT EXISTS customer_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id varchar(128) NOT NULL DEFAULT 'unknown';

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS customer_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS primary_event_id varchar(128);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS customer_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id varchar(128) NOT NULL DEFAULT 'unknown';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS primary_alert_id varchar(128);

CREATE TABLE IF NOT EXISTS alert_events (
    run_id varchar(64) NOT NULL,
    alert_id varchar(128) NOT NULL,
    event_id varchar(128) NOT NULL,
    CONSTRAINT pk_alert_events PRIMARY KEY (run_id, alert_id, event_id),
    CONSTRAINT fk_alert_events_alert FOREIGN KEY (run_id, alert_id) REFERENCES alerts (run_id, alert_id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_events_event FOREIGN KEY (run_id, event_id) REFERENCES events (run_id, event_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    run_id varchar(64) NOT NULL,
    incident_id varchar(128) NOT NULL,
    alert_id varchar(128) NOT NULL,
    CONSTRAINT pk_incident_alerts PRIMARY KEY (run_id, incident_id, alert_id),
    CONSTRAINT fk_incident_alerts_incident FOREIGN KEY (run_id, incident_id) REFERENCES incidents (run_id, incident_id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_alerts_alert FOREIGN KEY (run_id, alert_id) REFERENCES alerts (run_id, alert_id) ON DELETE CASCADE
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_events_run') THEN
        ALTER TABLE events ADD CONSTRAINT fk_events_run FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_alerts_run') THEN
        ALTER TABLE alerts ADD CONSTRAINT fk_alerts_run FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_alerts_primary_event') THEN
        ALTER TABLE alerts ADD CONSTRAINT fk_alerts_primary_event FOREIGN KEY (run_id, primary_event_id) REFERENCES events (run_id, event_id) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_incidents_run') THEN
        ALTER TABLE incidents ADD CONSTRAINT fk_incidents_run FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_incidents_primary_alert') THEN
        ALTER TABLE incidents ADD CONSTRAINT fk_incidents_primary_alert FOREIGN KEY (run_id, primary_alert_id) REFERENCES alerts (run_id, alert_id) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_dlq_events_run') THEN
        ALTER TABLE dlq_events ADD CONSTRAINT fk_dlq_events_run FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_alert_events_alert') THEN
        ALTER TABLE alert_events ADD CONSTRAINT fk_alert_events_alert FOREIGN KEY (run_id, alert_id) REFERENCES alerts (run_id, alert_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_alert_events_event') THEN
        ALTER TABLE alert_events ADD CONSTRAINT fk_alert_events_event FOREIGN KEY (run_id, event_id) REFERENCES events (run_id, event_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_incident_alerts_incident') THEN
        ALTER TABLE incident_alerts ADD CONSTRAINT fk_incident_alerts_incident FOREIGN KEY (run_id, incident_id) REFERENCES incidents (run_id, incident_id) ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_incident_alerts_alert') THEN
        ALTER TABLE incident_alerts ADD CONSTRAINT fk_incident_alerts_alert FOREIGN KEY (run_id, alert_id) REFERENCES alerts (run_id, alert_id) ON DELETE CASCADE NOT VALID;
    END IF;
END $$;

ALTER TABLE events VALIDATE CONSTRAINT fk_events_run;
ALTER TABLE alerts VALIDATE CONSTRAINT fk_alerts_run;
ALTER TABLE alerts VALIDATE CONSTRAINT fk_alerts_primary_event;
ALTER TABLE incidents VALIDATE CONSTRAINT fk_incidents_run;
ALTER TABLE incidents VALIDATE CONSTRAINT fk_incidents_primary_alert;
ALTER TABLE dlq_events VALIDATE CONSTRAINT fk_dlq_events_run;
ALTER TABLE alert_events VALIDATE CONSTRAINT fk_alert_events_alert;
ALTER TABLE alert_events VALIDATE CONSTRAINT fk_alert_events_event;
ALTER TABLE incident_alerts VALIDATE CONSTRAINT fk_incident_alerts_incident;
ALTER TABLE incident_alerts VALIDATE CONSTRAINT fk_incident_alerts_alert;

CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events (run_id, event_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts (run_id, alert_id);

COMMIT;
