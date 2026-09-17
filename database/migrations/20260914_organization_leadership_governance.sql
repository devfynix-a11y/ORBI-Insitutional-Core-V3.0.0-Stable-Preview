-- BEGIN SYNCED MIGRATION: 20260914_organization_leadership_governance.sql
CREATE TABLE IF NOT EXISTS public.organization_role_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    from_role TEXT,
    to_role TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    required_approvals INTEGER NOT NULL DEFAULT 1,
    approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

ALTER TABLE public.organization_role_change_requests
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    ADD COLUMN IF NOT EXISTS review_reason TEXT;

UPDATE public.organization_role_change_requests
SET status='CANCELLED', updated_at=NOW(),
    metadata=COALESCE(metadata,'{}'::jsonb)||jsonb_build_object('migration_reason','replaced_by_sql_authoritative_governance')
WHERE status='PENDING';

DO $$
BEGIN
    ALTER TABLE public.organization_role_change_requests DROP CONSTRAINT IF EXISTS organization_role_change_requests_action_check;
    ALTER TABLE public.organization_role_change_requests ADD CONSTRAINT organization_role_change_requests_action_check
        CHECK(action IN ('ADD_ADMIN','REMOVE_ADMIN','TRANSFER_PRIMARY_ADMIN'));
    ALTER TABLE public.organization_role_change_requests DROP CONSTRAINT IF EXISTS organization_role_change_requests_required_approvals_check;
    ALTER TABLE public.organization_role_change_requests ADD CONSTRAINT organization_role_change_requests_required_approvals_check
        CHECK(required_approvals BETWEEN 1 AND 2);
    ALTER TABLE public.organization_role_change_requests DROP CONSTRAINT IF EXISTS organization_role_change_requests_status_check;
    ALTER TABLE public.organization_role_change_requests ADD CONSTRAINT organization_role_change_requests_status_check
        CHECK(status IN ('PENDING','APPROVED','REJECTED','EXECUTED','CANCELLED','EXPIRED'));
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_leadership_change_pending
    ON public.organization_role_change_requests(organization_id,target_user_id) WHERE status='PENDING';

CREATE OR REPLACE FUNCTION public.request_organization_leadership_change_v1(
    p_actor_id UUID, p_organization_id UUID, p_target_user_id UUID,
    p_action TEXT, p_to_role TEXT, p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE
    v_actor public.users%ROWTYPE; v_target public.users%ROWTYPE; v_org public.organizations%ROWTYPE;
    v_action TEXT:=UPPER(BTRIM(COALESCE(p_action,''))); v_to_role TEXT:=UPPER(BTRIM(COALESCE(p_to_role,'MANAGER')));
    v_reviewers INTEGER; v_id UUID;
BEGIN
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE'
       OR v_actor.organization_id IS DISTINCT FROM p_organization_id
       OR UPPER(COALESCE(v_actor.org_role,''))<>'ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_ADMIN_REQUIRED'; END IF;
    SELECT * INTO v_target FROM public.users WHERE id=p_target_user_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_target.account_status,''))<>'ACTIVE'
       OR v_target.organization_id IS DISTINCT FROM p_organization_id THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_NOT_FOUND'; END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id=p_organization_id FOR UPDATE;
    IF v_action NOT IN ('ADD_ADMIN','REMOVE_ADMIN','TRANSFER_PRIMARY_ADMIN') THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_ACTION_INVALID'; END IF;
    IF p_actor_id=p_target_user_id THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_SELF_REQUEST_DENIED'; END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,'')))<5 THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_REASON_REQUIRED'; END IF;
    IF v_action='ADD_ADMIN' AND UPPER(COALESCE(v_target.org_role,''))='ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_ALREADY_ADMIN'; END IF;
    IF v_action='REMOVE_ADMIN' THEN
        IF UPPER(COALESCE(v_target.org_role,''))<>'ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_NOT_ADMIN'; END IF;
        IF v_org.primary_admin_user_id=p_target_user_id THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_PRIMARY_TRANSFER_REQUIRED'; END IF;
        IF v_to_role NOT IN ('MEMBER','MANAGER','ACCOUNTANT') THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_ROLE_INVALID'; END IF;
        IF EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=p_organization_id AND user_id=p_target_user_id AND status='ACTIVE') THEN
            RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TREASURY_REMOVAL_REQUIRED';
        END IF;
    END IF;
    IF v_action='TRANSFER_PRIMARY_ADMIN' AND UPPER(COALESCE(v_target.org_role,''))<>'ADMIN' THEN
        RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_NOT_ADMIN';
    END IF;
    SELECT COUNT(*) INTO v_reviewers FROM public.users
     WHERE organization_id=p_organization_id AND UPPER(COALESCE(account_status,''))='ACTIVE'
       AND UPPER(COALESCE(org_role,'')) IN ('ADMIN','SIGNATORY') AND id NOT IN (p_actor_id,p_target_user_id);
    IF v_reviewers<1 THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_REVIEWER_UNAVAILABLE'; END IF;
    UPDATE public.organization_role_change_requests SET status='EXPIRED',updated_at=NOW()
     WHERE organization_id=p_organization_id AND target_user_id=p_target_user_id AND status='PENDING' AND expires_at<=NOW();
    INSERT INTO public.organization_role_change_requests(
        organization_id,target_user_id,requested_by,action,from_role,to_role,required_approvals,reason,metadata
    ) VALUES(
        p_organization_id,p_target_user_id,p_actor_id,v_action,UPPER(v_target.org_role),
        CASE WHEN v_action='REMOVE_ADMIN' THEN v_to_role ELSE 'ADMIN' END,LEAST(2,v_reviewers),BTRIM(p_reason),
        jsonb_build_object('governance_version',1,'eligible_reviewers',v_reviewers)
    ) RETURNING id INTO v_id;
    RETURN jsonb_build_object('request_id',v_id,'required_reviews',LEAST(2,v_reviewers),'expires_in_hours',24);
END; $$;

CREATE OR REPLACE FUNCTION public.respond_organization_leadership_change_v1(
    p_reviewer_id UUID, p_request_id UUID, p_decision TEXT, p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE
    v_request public.organization_role_change_requests%ROWTYPE; v_reviewer public.users%ROWTYPE;
    v_target public.users%ROWTYPE; v_org public.organizations%ROWTYPE; v_approvals JSONB; v_count INTEGER;
    v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
    SELECT * INTO v_request FROM public.organization_role_change_requests WHERE id=p_request_id FOR UPDATE;
    IF NOT FOUND OR v_request.status<>'PENDING' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_REQUEST_NOT_PENDING'; END IF;
    IF v_request.expires_at<=NOW() THEN
        UPDATE public.organization_role_change_requests SET status='EXPIRED',decided_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
        RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED');
    END IF;
    SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_reviewer.account_status,''))<>'ACTIVE'
       OR v_reviewer.organization_id IS DISTINCT FROM v_request.organization_id
       OR UPPER(COALESCE(v_reviewer.org_role,'')) NOT IN ('ADMIN','SIGNATORY')
       OR p_reviewer_id IN (v_request.requested_by,v_request.target_user_id) THEN
        RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_REVIEWER_REQUIRED';
    END IF;
    IF v_decision NOT IN ('APPROVE','REJECT') THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_DECISION_INVALID'; END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,'')))<5 THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_REVIEW_REASON_REQUIRED'; END IF;
    v_approvals:=COALESCE(v_request.approvals,'[]'::jsonb);
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(v_approvals) item WHERE item->>'user_id'=p_reviewer_id::TEXT) THEN
        RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_ALREADY_REVIEWED';
    END IF;
    v_approvals:=v_approvals||jsonb_build_object('user_id',p_reviewer_id,'decision',v_decision,'reason',BTRIM(p_reason),'at',NOW());
    IF v_decision='REJECT' THEN
        UPDATE public.organization_role_change_requests SET approvals=v_approvals,status='REJECTED',review_reason=BTRIM(p_reason),decided_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
        RETURN jsonb_build_object('request_id',p_request_id,'status','REJECTED');
    END IF;
    SELECT COUNT(*) INTO v_count FROM jsonb_array_elements(v_approvals) item WHERE item->>'decision'='APPROVE';
    IF v_count<v_request.required_approvals THEN
        UPDATE public.organization_role_change_requests SET approvals=v_approvals,updated_at=NOW() WHERE id=p_request_id;
        RETURN jsonb_build_object('request_id',p_request_id,'status','PENDING','reviews_received',v_count,'reviews_required',v_request.required_approvals);
    END IF;
    SELECT * INTO v_target FROM public.users WHERE id=v_request.target_user_id FOR UPDATE;
    SELECT * INTO v_org FROM public.organizations WHERE id=v_request.organization_id FOR UPDATE;
    IF v_target.organization_id IS DISTINCT FROM v_request.organization_id OR UPPER(COALESCE(v_target.account_status,''))<>'ACTIVE' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_NOT_FOUND'; END IF;
    IF v_request.action='REMOVE_ADMIN' THEN
        IF v_org.primary_admin_user_id=v_target.id THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_PRIMARY_TRANSFER_REQUIRED'; END IF;
        IF EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=v_request.organization_id AND user_id=v_target.id AND status='ACTIVE') THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TREASURY_REMOVAL_REQUIRED'; END IF;
        IF (SELECT COUNT(*) FROM public.users WHERE organization_id=v_request.organization_id AND UPPER(COALESCE(account_status,''))='ACTIVE' AND UPPER(COALESCE(org_role,''))='ADMIN')<=1 THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_LOCKOUT_DENIED'; END IF;
        UPDATE public.users SET org_role=v_request.to_role WHERE id=v_target.id;
    ELSIF v_request.action='ADD_ADMIN' THEN
        UPDATE public.users SET org_role='ADMIN' WHERE id=v_target.id;
    ELSE
        IF UPPER(COALESCE(v_target.org_role,''))<>'ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_LEADERSHIP_TARGET_NOT_ADMIN'; END IF;
        UPDATE public.organizations SET primary_admin_user_id=v_target.id,updated_at=NOW() WHERE id=v_request.organization_id;
    END IF;
    UPDATE public.organization_role_change_requests SET approvals=v_approvals,status='EXECUTED',review_reason=BTRIM(p_reason),decided_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
    RETURN jsonb_build_object('request_id',p_request_id,'status','EXECUTED','action',v_request.action);
END; $$;

REVOKE ALL ON FUNCTION public.request_organization_leadership_change_v1(UUID,UUID,UUID,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_leadership_change_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_organization_leadership_change_v1(UUID,UUID,UUID,TEXT,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_leadership_change_v1(UUID,UUID,TEXT,TEXT) TO service_role;
NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260914_organization_leadership_governance.sql
