BEGIN;

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id varchar(64) PRIMARY KEY,
    celery_task_id varchar(64) NOT NULL UNIQUE,
    status varchar(40) NOT NULL,
    created_at varchar(40) NOT NULL,
    updated_at varchar(40) NOT NULL,
    started_at varchar(40),
    completed_at varchar(40),
    run_id varchar(64),
    customer_id varchar(128) NOT NULL DEFAULT 'unknown',
    tenant_id varchar(128) NOT NULL DEFAULT 'unknown',
    agent_version varchar(80) NOT NULL DEFAULT 'unknown',
    payload_version varchar(80) NOT NULL DEFAULT 'unknown',
    input_meta text NOT NULL,
    result text,
    error text
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_analysis_jobs_run') THEN
        ALTER TABLE analysis_jobs ADD CONSTRAINT fk_analysis_jobs_run FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE SET NULL NOT VALID;
    END IF;
END $$;

ALTER TABLE analysis_jobs VALIDATE CONSTRAINT fk_analysis_jobs_run;

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs (status);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_celery_task_id ON analysis_jobs (celery_task_id);

COMMIT;
