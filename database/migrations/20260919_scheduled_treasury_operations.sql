-- BEGIN SYNCED MIGRATION: 20260919_scheduled_treasury_operations.sql
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_frequency TEXT NOT NULL DEFAULT 'DAILY' CHECK(sweep_frequency IN ('DAILY','WEEKLY','MONTHLY'));
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_timezone TEXT NOT NULL DEFAULT 'Africa/Dar_es_Salaam';
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_next_run_at TIMESTAMPTZ;
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_window_minutes INTEGER NOT NULL DEFAULT 60 CHECK(sweep_window_minutes BETWEEN 5 AND 1440);
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_schedule_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS public.treasury_schedule_change_requests(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,goal_id UUID NOT NULL REFERENCES public.goals(id) ON DELETE CASCADE,
 requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
 enabled BOOLEAN NOT NULL,threshold NUMERIC NOT NULL CHECK(threshold>=0),frequency TEXT NOT NULL CHECK(frequency IN ('DAILY','WEEKLY','MONTHLY')),timezone TEXT NOT NULL,next_run_at TIMESTAMPTZ NOT NULL,window_minutes INTEGER NOT NULL CHECK(window_minutes BETWEEN 5 AND 1440),reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED')),review_reason TEXT,expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_schedule_change_open ON public.treasury_schedule_change_requests(goal_id) WHERE status='PENDING';
CREATE TABLE IF NOT EXISTS public.treasury_schedule_executions(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,goal_id UUID NOT NULL REFERENCES public.goals(id) ON DELETE CASCADE,schedule_version INTEGER NOT NULL,scheduled_for TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL DEFAULT 'CLAIMED' CHECK(status IN ('CLAIMED','COMPLETED','SKIPPED','FAILED')),worker_id TEXT NOT NULL,lease_until TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL DEFAULT 1,last_error TEXT,transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),finished_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(goal_id,schedule_version,scheduled_for)
);
ALTER TABLE public.treasury_schedule_change_requests ENABLE ROW LEVEL SECURITY;ALTER TABLE public.treasury_schedule_executions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS treasury_schedule_change_service ON public.treasury_schedule_change_requests;
DROP POLICY IF EXISTS treasury_schedule_execution_service ON public.treasury_schedule_executions;
CREATE POLICY treasury_schedule_change_service ON public.treasury_schedule_change_requests FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
CREATE POLICY treasury_schedule_execution_service ON public.treasury_schedule_executions FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON TABLE public.treasury_schedule_change_requests,public.treasury_schedule_executions FROM anon,authenticated;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.treasury_schedule_change_requests,public.treasury_schedule_executions TO service_role;

CREATE OR REPLACE FUNCTION public.request_treasury_schedule_change_v1(p_actor_id UUID,p_goal_id UUID,p_enabled BOOLEAN,p_threshold NUMERIC,p_frequency TEXT,p_timezone TEXT,p_next_run_at TIMESTAMPTZ,p_window_minutes INTEGER,p_reason TEXT)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_goal public.goals%ROWTYPE;v_actor public.users%ROWTYPE;v_id UUID;v_tz TEXT:=BTRIM(COALESCE(p_timezone,''));v_frequency TEXT:=UPPER(BTRIM(COALESCE(p_frequency,'')));
BEGIN
 SELECT * INTO v_goal FROM public.goals WHERE id=p_goal_id FOR UPDATE;SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
 IF v_goal.id IS NULL OR v_goal.organization_id IS NULL OR v_goal.is_corporate<>TRUE THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_CORPORATE_GOAL_REQUIRED';END IF;
 IF v_actor.organization_id IS DISTINCT FROM v_goal.organization_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_actor.org_role,'')) NOT IN ('ADMIN','SIGNATORY') THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REQUESTER_DENIED';END IF;
 IF p_threshold<0 OR v_frequency NOT IN ('DAILY','WEEKLY','MONTHLY') OR p_next_run_at<=NOW() OR p_window_minutes NOT BETWEEN 5 AND 1440 OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 OR NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_tz) THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_INVALID';END IF;
 UPDATE public.treasury_schedule_change_requests SET status='EXPIRED',updated_at=NOW() WHERE goal_id=p_goal_id AND status='PENDING' AND expires_at<=NOW();
 INSERT INTO public.treasury_schedule_change_requests(organization_id,goal_id,requested_by,enabled,threshold,frequency,timezone,next_run_at,window_minutes,reason) VALUES(v_goal.organization_id,p_goal_id,p_actor_id,p_enabled,p_threshold,v_frequency,v_tz,p_next_run_at,p_window_minutes,BTRIM(p_reason)) RETURNING id INTO v_id;RETURN v_id;
END$$;

CREATE OR REPLACE FUNCTION public.respond_treasury_schedule_change_v1(p_reviewer_id UUID,p_request_id UUID,p_decision TEXT,p_reason TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_r public.treasury_schedule_change_requests%ROWTYPE;v_u public.users%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
 SELECT * INTO v_r FROM public.treasury_schedule_change_requests WHERE id=p_request_id FOR UPDATE;IF NOT FOUND OR v_r.status<>'PENDING' THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REQUEST_NOT_OPEN';END IF;
 IF v_r.expires_at<=NOW() THEN UPDATE public.treasury_schedule_change_requests SET status='EXPIRED',updated_at=NOW() WHERE id=p_request_id;RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED');END IF;
 SELECT * INTO v_u FROM public.users WHERE id=p_reviewer_id;IF v_u.organization_id IS DISTINCT FROM v_r.organization_id OR UPPER(COALESCE(v_u.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_u.org_role,'')) NOT IN ('ADMIN','SIGNATORY') OR p_reviewer_id=v_r.requested_by THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_MAKER_CHECKER_REQUIRED';END IF;
 IF v_decision NOT IN ('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REVIEW_INVALID';END IF;
 IF v_decision='APPROVE' THEN UPDATE public.goals SET auto_sweep_enabled=v_r.enabled,sweep_threshold=v_r.threshold,sweep_frequency=v_r.frequency,sweep_timezone=v_r.timezone,sweep_next_run_at=v_r.next_run_at,sweep_window_minutes=v_r.window_minutes,sweep_schedule_version=sweep_schedule_version+1,updated_at=NOW() WHERE id=v_r.goal_id;END IF;
 UPDATE public.treasury_schedule_change_requests SET status=CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
 RETURN jsonb_build_object('request_id',p_request_id,'status',CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,'goal_id',v_r.goal_id,'organization_id',v_r.organization_id);
END$$;

CREATE OR REPLACE FUNCTION public.claim_due_treasury_sweeps_v1(p_worker_id TEXT,p_limit INTEGER DEFAULT 25,p_lease_seconds INTEGER DEFAULT 120)
RETURNS SETOF public.treasury_schedule_executions LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_goal public.goals%ROWTYPE;v_run TIMESTAMPTZ;v_exec public.treasury_schedule_executions%ROWTYPE;
BEGIN
 IF LENGTH(BTRIM(COALESCE(p_worker_id,'')))<3 OR p_limit NOT BETWEEN 1 AND 100 OR p_lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_WORKER_INVALID';END IF;
 FOR v_goal IN SELECT * FROM public.goals WHERE is_corporate=TRUE AND status='ACTIVE' AND auto_sweep_enabled=TRUE AND sweep_next_run_at<=NOW() ORDER BY sweep_next_run_at FOR UPDATE SKIP LOCKED LIMIT p_limit LOOP
  v_run:=v_goal.sweep_next_run_at;
  INSERT INTO public.treasury_schedule_executions(organization_id,goal_id,schedule_version,scheduled_for,status,worker_id,lease_until,finished_at,last_error) VALUES(v_goal.organization_id,v_goal.id,v_goal.sweep_schedule_version,v_run,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN 'SKIPPED' ELSE 'CLAIMED' END,BTRIM(p_worker_id),NOW()+(p_lease_seconds||' seconds')::INTERVAL,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN NOW() ELSE NULL END,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN 'MISSED_EXECUTION_WINDOW' ELSE NULL END) ON CONFLICT(goal_id,schedule_version,scheduled_for) DO NOTHING RETURNING * INTO v_exec;
  UPDATE public.goals SET sweep_next_run_at=(CASE v_goal.sweep_frequency WHEN 'DAILY' THEN (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '1 day' WHEN 'WEEKLY' THEN (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '7 days' ELSE (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '1 month' END) AT TIME ZONE v_goal.sweep_timezone,updated_at=NOW() WHERE id=v_goal.id;
  IF v_exec.id IS NOT NULL AND v_exec.status='CLAIMED' THEN RETURN NEXT v_exec;END IF;
 END LOOP;RETURN;
END$$;

CREATE OR REPLACE FUNCTION public.reclaim_treasury_schedule_executions_v1(p_worker_id TEXT,p_limit INTEGER DEFAULT 25,p_lease_seconds INTEGER DEFAULT 120)
RETURNS SETOF public.treasury_schedule_executions LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF LENGTH(BTRIM(COALESCE(p_worker_id,'')))<3 OR p_limit NOT BETWEEN 1 AND 100 OR p_lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_WORKER_INVALID';END IF;
 RETURN QUERY WITH candidates AS (SELECT id FROM public.treasury_schedule_executions WHERE status='CLAIMED' AND lease_until<=NOW() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT p_limit)
 UPDATE public.treasury_schedule_executions e SET worker_id=BTRIM(p_worker_id),lease_until=NOW()+(p_lease_seconds||' seconds')::INTERVAL,attempts=e.attempts+1,updated_at=NOW() FROM candidates c WHERE e.id=c.id RETURNING e.*;
END$$;

CREATE OR REPLACE FUNCTION public.finish_treasury_schedule_execution_v1(p_execution_id UUID,p_worker_id TEXT,p_status TEXT,p_transaction_id UUID DEFAULT NULL,p_error TEXT DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF UPPER(p_status) NOT IN ('COMPLETED','SKIPPED','FAILED') THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_FINISH_INVALID';END IF;
 UPDATE public.treasury_schedule_executions SET status=UPPER(p_status),transaction_id=p_transaction_id,last_error=LEFT(p_error,1000),finished_at=NOW(),updated_at=NOW() WHERE id=p_execution_id AND worker_id=p_worker_id AND status='CLAIMED';IF NOT FOUND THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_CLAIM_REQUIRED';END IF;
END$$;

REVOKE ALL ON FUNCTION public.request_treasury_schedule_change_v1(UUID,UUID,BOOLEAN,NUMERIC,TEXT,TEXT,TIMESTAMPTZ,INTEGER,TEXT) FROM PUBLIC;REVOKE ALL ON FUNCTION public.respond_treasury_schedule_change_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;REVOKE ALL ON FUNCTION public.claim_due_treasury_sweeps_v1(TEXT,INTEGER,INTEGER) FROM PUBLIC;REVOKE ALL ON FUNCTION public.reclaim_treasury_schedule_executions_v1(TEXT,INTEGER,INTEGER) FROM PUBLIC;REVOKE ALL ON FUNCTION public.finish_treasury_schedule_execution_v1(UUID,TEXT,TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_treasury_schedule_change_v1(UUID,UUID,BOOLEAN,NUMERIC,TEXT,TEXT,TIMESTAMPTZ,INTEGER,TEXT) TO service_role;GRANT EXECUTE ON FUNCTION public.respond_treasury_schedule_change_v1(UUID,UUID,TEXT,TEXT) TO service_role;GRANT EXECUTE ON FUNCTION public.claim_due_treasury_sweeps_v1(TEXT,INTEGER,INTEGER) TO service_role;GRANT EXECUTE ON FUNCTION public.reclaim_treasury_schedule_executions_v1(TEXT,INTEGER,INTEGER) TO service_role;GRANT EXECUTE ON FUNCTION public.finish_treasury_schedule_execution_v1(UUID,TEXT,TEXT,UUID,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260919_scheduled_treasury_operations.sql
