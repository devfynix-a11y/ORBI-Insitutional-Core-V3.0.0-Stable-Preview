-- BEGIN SYNCED MIGRATION: 20260917_organization_recovery_contact_reactivation.sql
ALTER TABLE public.organization_recovery_contacts
    ADD COLUMN IF NOT EXISTS contact_user_id UUID REFERENCES public.users(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS requested_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS request_reason TEXT,
    ADD COLUMN IF NOT EXISTS revocation_requested_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS revocation_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS review_reason TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_recovery_contact_active_user
    ON public.organization_recovery_contacts(organization_id,contact_user_id)
    WHERE status IN ('PENDING','VERIFIED') AND contact_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.organization_reactivation_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    recovery_case_id UUID NOT NULL REFERENCES public.organization_recovery_cases(id) ON DELETE RESTRICT,
    target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'COOLING' CHECK(status IN ('COOLING','REJECTED','EXECUTED','EXPIRED','CANCELLED')),
    reason TEXT NOT NULL,
    evidence JSONB NOT NULL,
    cooling_until TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '72 hours'),
    review_reason TEXT,
    reviewed_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_reactivation_open
    ON public.organization_reactivation_cases(target_user_id) WHERE status='COOLING';
ALTER TABLE public.organization_reactivation_cases ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_reactivation_cases_service_role ON public.organization_reactivation_cases;
CREATE POLICY organization_reactivation_cases_service_role ON public.organization_reactivation_cases
    FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON public.organization_reactivation_cases FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.organization_reactivation_cases TO service_role;

CREATE OR REPLACE FUNCTION public.request_organization_recovery_contact_v1(
    p_actor_id UUID,p_organization_id UUID,p_contact_user_id UUID,p_contact_type TEXT,p_reason TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_actor public.users%ROWTYPE;v_contact public.users%ROWTYPE;v_org public.organizations%ROWTYPE;v_type TEXT:=UPPER(BTRIM(COALESCE(p_contact_type,'')));v_value TEXT;v_id UUID;
BEGIN
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id FOR UPDATE;
    SELECT * INTO v_org FROM public.organizations WHERE id=p_organization_id FOR UPDATE;
    IF v_org.id IS NULL OR v_org.primary_admin_user_id IS DISTINCT FROM p_actor_id OR v_actor.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' THEN RAISE EXCEPTION 'RECOVERY_CONTACT_PRIMARY_ADMIN_REQUIRED';END IF;
    SELECT * INTO v_contact FROM public.users WHERE id=p_contact_user_id FOR UPDATE;
    IF v_contact.id IS NULL OR UPPER(COALESCE(v_contact.account_status,''))<>'ACTIVE' OR v_contact.organization_id IS NOT DISTINCT FROM p_organization_id OR p_contact_user_id=p_actor_id THEN RAISE EXCEPTION 'RECOVERY_CONTACT_EXTERNAL_ACTIVE_USER_REQUIRED';END IF;
    IF v_type='EMAIL' THEN v_value:=LOWER(BTRIM(COALESCE(v_contact.email,''))); ELSIF v_type='PHONE' THEN v_value:=regexp_replace(COALESCE(v_contact.phone,''),'[^0-9+]','','g'); ELSIF v_type='LEGAL_REPRESENTATIVE' THEN v_value:=p_contact_user_id::TEXT; ELSE RAISE EXCEPTION 'RECOVERY_CONTACT_TYPE_INVALID';END IF;
    IF LENGTH(v_value)<5 OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'RECOVERY_CONTACT_EVIDENCE_REQUIRED';END IF;
    INSERT INTO public.organization_recovery_contacts(organization_id,contact_type,contact_hash,contact_user_id,status,requested_by,request_reason)
    VALUES(p_organization_id,v_type,encode(digest(v_value,'sha256'),'hex'),p_contact_user_id,'PENDING',p_actor_id,BTRIM(p_reason)) RETURNING id INTO v_id;
    RETURN v_id;
END;$$;

CREATE OR REPLACE FUNCTION public.request_organization_recovery_contact_revocation_v1(
    p_actor_id UUID,p_contact_id UUID,p_reason TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_contact public.organization_recovery_contacts%ROWTYPE;v_org public.organizations%ROWTYPE;v_actor public.users%ROWTYPE;
BEGIN
    SELECT * INTO v_contact FROM public.organization_recovery_contacts WHERE id=p_contact_id FOR UPDATE;
    IF NOT FOUND OR v_contact.status<>'VERIFIED' THEN RAISE EXCEPTION 'RECOVERY_CONTACT_VERIFIED_REQUIRED';END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id=v_contact.organization_id FOR UPDATE;
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
    IF v_org.primary_admin_user_id IS DISTINCT FROM p_actor_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' THEN RAISE EXCEPTION 'RECOVERY_CONTACT_PRIMARY_ADMIN_REQUIRED';END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'RECOVERY_CONTACT_REASON_REQUIRED';END IF;
    UPDATE public.organization_recovery_contacts SET revocation_requested_by=p_actor_id,revocation_requested_at=NOW(),request_reason=BTRIM(p_reason),updated_at=NOW() WHERE id=p_contact_id;
    RETURN p_contact_id;
END;$$;

CREATE OR REPLACE FUNCTION public.respond_organization_recovery_contact_v1(
    p_reviewer_id UUID,p_contact_id UUID,p_decision TEXT,p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_contact public.organization_recovery_contacts%ROWTYPE;v_reviewer public.users%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));v_status TEXT;
BEGIN
    SELECT * INTO v_contact FROM public.organization_recovery_contacts WHERE id=p_contact_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_CONTACT_NOT_FOUND';END IF;
    SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id;
    IF v_reviewer.id IS NULL OR UPPER(COALESCE(v_reviewer.role,''))<>'SUPER_ADMIN' OR UPPER(COALESCE(v_reviewer.account_status,''))<>'ACTIVE' OR p_reviewer_id IN (v_contact.requested_by,v_contact.contact_user_id,v_contact.revocation_requested_by) THEN RAISE EXCEPTION 'RECOVERY_CONTACT_EXTERNAL_REVIEWER_REQUIRED';END IF;
    IF v_decision NOT IN ('VERIFY','REJECT','REVOKE') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'RECOVERY_CONTACT_REVIEW_INVALID';END IF;
    IF v_decision IN ('VERIFY','REJECT') AND v_contact.status<>'PENDING' THEN RAISE EXCEPTION 'RECOVERY_CONTACT_PENDING_REQUIRED';END IF;
    IF v_decision='REVOKE' AND (v_contact.status<>'VERIFIED' OR v_contact.revocation_requested_at IS NULL) THEN RAISE EXCEPTION 'RECOVERY_CONTACT_REVOCATION_REQUEST_REQUIRED';END IF;
    v_status:=CASE WHEN v_decision='VERIFY' THEN 'VERIFIED' ELSE 'REVOKED' END;
    UPDATE public.organization_recovery_contacts SET status=v_status,verified_by=CASE WHEN v_decision='VERIFY' THEN p_reviewer_id ELSE verified_by END,verified_at=CASE WHEN v_decision='VERIFY' THEN NOW() ELSE verified_at END,review_reason=BTRIM(p_reason),updated_at=NOW() WHERE id=p_contact_id;
    RETURN jsonb_build_object('contact_id',p_contact_id,'status',v_status,'organization_id',v_contact.organization_id,'contact_user_id',v_contact.contact_user_id,'requested_by',v_contact.requested_by,'revocation_requested_by',v_contact.revocation_requested_by);
END;$$;

CREATE OR REPLACE FUNCTION public.request_organization_reactivation_v1(
    p_actor_id UUID,p_organization_id UUID,p_target_user_id UUID,p_reason TEXT,p_evidence JSONB
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_org public.organizations%ROWTYPE;v_actor public.users%ROWTYPE;v_target public.users%ROWTYPE;v_recovery public.organization_recovery_cases%ROWTYPE;v_id UUID;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id=p_organization_id FOR UPDATE;
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
    SELECT * INTO v_target FROM public.users WHERE id=p_target_user_id FOR UPDATE;
    IF v_org.id IS NULL OR v_org.primary_admin_user_id IS DISTINCT FROM p_actor_id OR v_actor.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_PRIMARY_REQUIRED';END IF;
    IF v_target.id IS NULL OR v_target.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_target.account_status,''))<>'SUSPENDED' OR COALESCE(v_target.status_reason_code,'')<>'ORG_RECOVERY_HOLD' THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_TARGET_INVALID';END IF;
    SELECT * INTO v_recovery FROM public.organization_recovery_cases WHERE organization_id=p_organization_id AND current_primary_user_id=p_target_user_id AND status='EXECUTED' ORDER BY executed_at DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_RECOVERY_REQUIRED';END IF;
    IF COALESCE((p_evidence->>'identityReverified')::BOOLEAN,FALSE)<>TRUE OR COALESCE((p_evidence->>'credentialResetConfirmed')::BOOLEAN,FALSE)<>TRUE OR COALESCE((p_evidence->>'incidentClosed')::BOOLEAN,FALSE)<>TRUE OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_REMEDIATION_REQUIRED';END IF;
    UPDATE public.organization_reactivation_cases SET status='EXPIRED',updated_at=NOW() WHERE target_user_id=p_target_user_id AND status='COOLING' AND expires_at<=NOW();
    INSERT INTO public.organization_reactivation_cases(organization_id,recovery_case_id,target_user_id,requested_by,reason,evidence)
    VALUES(p_organization_id,v_recovery.id,p_target_user_id,p_actor_id,BTRIM(p_reason),p_evidence) RETURNING id INTO v_id;
    RETURN v_id;
END;$$;

CREATE OR REPLACE FUNCTION public.respond_organization_reactivation_v1(
    p_reviewer_id UUID,p_case_id UUID,p_decision TEXT,p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_case public.organization_reactivation_cases%ROWTYPE;v_reviewer public.users%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
    SELECT * INTO v_case FROM public.organization_reactivation_cases WHERE id=p_case_id FOR UPDATE;
    IF NOT FOUND OR v_case.status<>'COOLING' THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_NOT_OPEN';END IF;
    IF v_case.expires_at<=NOW() THEN UPDATE public.organization_reactivation_cases SET status='EXPIRED',updated_at=NOW() WHERE id=p_case_id;RETURN jsonb_build_object('case_id',p_case_id,'status','EXPIRED');END IF;
    SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id;
    IF v_reviewer.id IS NULL OR UPPER(COALESCE(v_reviewer.role,''))<>'SUPER_ADMIN' OR UPPER(COALESCE(v_reviewer.account_status,''))<>'ACTIVE' OR p_reviewer_id IN (v_case.requested_by,v_case.target_user_id) THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_EXTERNAL_REVIEWER_REQUIRED';END IF;
    IF v_decision NOT IN ('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_REVIEW_INVALID';END IF;
    IF v_decision='REJECT' THEN UPDATE public.organization_reactivation_cases SET status='REJECTED',reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_case_id;RETURN jsonb_build_object('case_id',p_case_id,'status','REJECTED');END IF;
    IF v_case.cooling_until>NOW() THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_COOLING_ACTIVE';END IF;
    IF NOT EXISTS(SELECT 1 FROM public.organizations WHERE id=v_case.organization_id AND primary_admin_user_id=v_case.requested_by) THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_PRIMARY_CHANGED';END IF;
    UPDATE public.user_sessions SET is_revoked=TRUE WHERE user_id=v_case.target_user_id AND is_revoked=FALSE;
    UPDATE public.users SET account_status='ACTIVE',org_role='MEMBER',status_reason='Recovery remediation independently approved',status_reason_code='ORG_RECOVERY_REACTIVATED',status_changed_at=NOW(),status_changed_by=p_reviewer_id::TEXT WHERE id=v_case.target_user_id AND account_status='SUSPENDED' AND status_reason_code='ORG_RECOVERY_HOLD';
    IF NOT FOUND THEN RAISE EXCEPTION 'ORGANIZATION_REACTIVATION_TARGET_CHANGED';END IF;
    UPDATE public.organization_reactivation_cases SET status='EXECUTED',reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),executed_at=NOW(),updated_at=NOW() WHERE id=p_case_id;
    RETURN jsonb_build_object('case_id',p_case_id,'status','EXECUTED','target_user_id',v_case.target_user_id,'restored_role','MEMBER','sessions_revoked',TRUE);
END;$$;

CREATE OR REPLACE FUNCTION public.request_organization_recovery_v1(
 p_actor_id UUID,p_organization_id UUID,p_beneficiary_id UUID,p_incident_reference TEXT,p_reason TEXT,p_evidence JSONB
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_actor public.users%ROWTYPE;v_target public.users%ROWTYPE;v_org public.organizations%ROWTYPE;v_contacts INTEGER;v_id UUID;
BEGIN
 SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id FOR UPDATE;
 SELECT * INTO v_org FROM public.organizations WHERE id=p_organization_id FOR UPDATE;
 IF v_org.id IS NULL OR v_org.primary_admin_user_id IS NULL THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_PRIMARY_REQUIRED';END IF;
 IF v_actor.id IS NULL OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' OR v_actor.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_actor.org_role,'')) NOT IN ('ADMIN','SIGNATORY') THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_REQUESTER_REQUIRED';END IF;
 SELECT * INTO v_target FROM public.users WHERE id=p_beneficiary_id FOR UPDATE;
 IF v_target.id IS NULL OR UPPER(COALESCE(v_target.account_status,''))<>'ACTIVE' OR v_target.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_target.org_role,''))<>'ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_BENEFICIARY_REQUIRED';END IF;
 IF p_actor_id IN (v_org.primary_admin_user_id,p_beneficiary_id) THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_SEPARATION_REQUIRED';END IF;
 IF LENGTH(BTRIM(COALESCE(p_incident_reference,'')))<8 OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_EVIDENCE_REQUIRED';END IF;
 SELECT COUNT(DISTINCT contact_user_id) INTO v_contacts FROM public.organization_recovery_contacts WHERE organization_id=p_organization_id AND status='VERIFIED' AND contact_user_id IS NOT NULL;
 IF v_contacts<2 THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_CONTACTS_UNVERIFIED';END IF;
 UPDATE public.organization_recovery_cases SET status='EXPIRED',updated_at=NOW() WHERE organization_id=p_organization_id AND status IN ('COOLING','APPROVED') AND expires_at<=NOW();
 INSERT INTO public.organization_recovery_cases(organization_id,current_primary_user_id,beneficiary_user_id,requested_by,incident_reference,reason,evidence)
 VALUES(p_organization_id,v_org.primary_admin_user_id,p_beneficiary_id,p_actor_id,BTRIM(p_incident_reference),BTRIM(p_reason),COALESCE(p_evidence,'{}'::jsonb)) RETURNING id INTO v_id;
 RETURN v_id;
END;$$;

REVOKE ALL ON FUNCTION public.request_organization_recovery_contact_v1(UUID,UUID,UUID,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.request_organization_recovery_contact_revocation_v1(UUID,UUID,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_recovery_contact_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.request_organization_reactivation_v1(UUID,UUID,UUID,TEXT,JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_reactivation_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_organization_recovery_contact_v1(UUID,UUID,UUID,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.request_organization_recovery_contact_revocation_v1(UUID,UUID,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_recovery_contact_v1(UUID,UUID,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.request_organization_reactivation_v1(UUID,UUID,UUID,TEXT,JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_reactivation_v1(UUID,UUID,TEXT,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260917_organization_recovery_contact_reactivation.sql
