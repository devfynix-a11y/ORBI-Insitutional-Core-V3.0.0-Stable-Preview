-- BEGIN SYNCED MIGRATION: 20260916_notification_delivery_idempotency.sql
CREATE TABLE IF NOT EXISTS public.notification_delivery_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_key TEXT NOT NULL,
    recipient_user_id UUID NOT NULL,
    message_id UUID NOT NULL,
    event_code TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DISPATCHED', 'FAILED')),
    attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts > 0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched_at TIMESTAMPTZ,
    UNIQUE (event_key, recipient_user_id)
);

CREATE INDEX IF NOT EXISTS idx_notification_delivery_events_status
    ON public.notification_delivery_events(status, updated_at);

ALTER TABLE public.notification_delivery_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_delivery_events_service_role ON public.notification_delivery_events;
CREATE POLICY notification_delivery_events_service_role
    ON public.notification_delivery_events FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON public.notification_delivery_events FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.notification_delivery_events TO service_role;

CREATE OR REPLACE FUNCTION public.claim_notification_delivery_v1(
    p_event_key TEXT,
    p_recipient_user_id UUID,
    p_message_id UUID,
    p_event_code TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_row public.notification_delivery_events%ROWTYPE; v_acquired BOOLEAN := FALSE;
BEGIN
    IF NULLIF(BTRIM(p_event_key), '') IS NULL OR NULLIF(BTRIM(p_event_code), '') IS NULL THEN
        RAISE EXCEPTION 'NOTIFICATION_EVENT_REQUIRED';
    END IF;
    INSERT INTO public.notification_delivery_events(event_key, recipient_user_id, message_id, event_code)
    VALUES (BTRIM(p_event_key), p_recipient_user_id, p_message_id, UPPER(BTRIM(p_event_code)))
    ON CONFLICT (event_key, recipient_user_id) DO NOTHING
    RETURNING * INTO v_row;
    IF FOUND THEN
        v_acquired := TRUE;
    ELSE
        SELECT * INTO v_row FROM public.notification_delivery_events
        WHERE event_key=BTRIM(p_event_key) AND recipient_user_id=p_recipient_user_id FOR UPDATE;
        IF v_row.status='FAILED' OR (v_row.status='PENDING' AND v_row.updated_at < NOW() - INTERVAL '15 minutes') THEN
            UPDATE public.notification_delivery_events SET status='PENDING', attempts=attempts+1,
                last_error=NULL, updated_at=NOW() WHERE id=v_row.id RETURNING * INTO v_row;
            v_acquired := TRUE;
        END IF;
    END IF;
    RETURN jsonb_build_object('acquired',v_acquired,'message_id',v_row.message_id,'status',v_row.status);
END $$;

CREATE OR REPLACE FUNCTION public.finish_notification_delivery_v1(
    p_event_key TEXT, p_recipient_user_id UUID, p_status TEXT, p_error TEXT DEFAULT NULL
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF UPPER(p_status) NOT IN ('DISPATCHED','FAILED') THEN RAISE EXCEPTION 'INVALID_NOTIFICATION_STATUS'; END IF;
    UPDATE public.notification_delivery_events SET status=UPPER(p_status), last_error=LEFT(p_error,1000),
        updated_at=NOW(), dispatched_at=CASE WHEN UPPER(p_status)='DISPATCHED' THEN NOW() ELSE dispatched_at END
    WHERE event_key=BTRIM(p_event_key) AND recipient_user_id=p_recipient_user_id;
END $$;
REVOKE ALL ON FUNCTION public.claim_notification_delivery_v1(TEXT,UUID,UUID,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.finish_notification_delivery_v1(TEXT,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.claim_notification_delivery_v1(TEXT,UUID,UUID,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.finish_notification_delivery_v1(TEXT,UUID,TEXT,TEXT) TO service_role;
-- END SYNCED MIGRATION: 20260916_notification_delivery_idempotency.sql
