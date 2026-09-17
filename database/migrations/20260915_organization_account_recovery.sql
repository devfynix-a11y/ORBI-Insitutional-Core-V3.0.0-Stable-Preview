-- BEGIN SYNCED MIGRATION: 20260915_organization_account_recovery.sql
CREATE TABLE IF NOT EXISTS public.organization_recovery_contacts (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 contact_type TEXT NOT NULL CHECK(contact_type IN ('EMAIL','PHONE','LEGAL_REPRESENTATIVE')), contact_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','VERIFIED','REVOKED')),
 verified_by UUID REFERENCES public.users(id) ON DELETE SET NULL, verified_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(organization_id,contact_type,contact_hash)
);
CREATE TABLE IF NOT EXISTS public.organization_recovery_cases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 current_primary_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 beneficiary_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
 status TEXT NOT NULL DEFAULT 'COOLING' CHECK(status IN ('COOLING','APPROVED','REJECTED','EXECUTED','EXPIRED','CANCELLED')),
 incident_reference TEXT NOT NULL, reason TEXT NOT NULL, evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
 cooling_until TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'), expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '72 hours'),
 review_reason TEXT, reviewed_at TIMESTAMPTZ, executed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_recovery_open ON public.organization_recovery_cases(organization_id) WHERE status IN ('COOLING','APPROVED');
ALTER TABLE public.organization_recovery_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_recovery_cases ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_recovery_contacts_service_role ON public.organization_recovery_contacts;
CREATE POLICY organization_recovery_contacts_service_role ON public.organization_recovery_contacts FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
DROP POLICY IF EXISTS organization_recovery_cases_service_role ON public.organization_recovery_cases;
CREATE POLICY organization_recovery_cases_service_role ON public.organization_recovery_cases FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
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
 SELECT COUNT(*) INTO v_contacts FROM public.organization_recovery_contacts WHERE organization_id=p_organization_id AND status='VERIFIED';
 IF v_contacts<2 THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_CONTACTS_UNVERIFIED';END IF;
 UPDATE public.organization_recovery_cases SET status='EXPIRED',updated_at=NOW() WHERE organization_id=p_organization_id AND status IN ('COOLING','APPROVED') AND expires_at<=NOW();
 INSERT INTO public.organization_recovery_cases(organization_id,current_primary_user_id,beneficiary_user_id,requested_by,incident_reference,reason,evidence)
 VALUES(p_organization_id,v_org.primary_admin_user_id,p_beneficiary_id,p_actor_id,BTRIM(p_incident_reference),BTRIM(p_reason),COALESCE(p_evidence,'{}'::jsonb)) RETURNING id INTO v_id;
 RETURN v_id;
END;$$;

CREATE OR REPLACE FUNCTION public.respond_organization_recovery_v1(
 p_reviewer_id UUID,p_case_id UUID,p_decision TEXT,p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_case public.organization_recovery_cases%ROWTYPE;v_reviewer public.users%ROWTYPE;v_org public.organizations%ROWTYPE;v_required INTEGER;v_remaining INTEGER;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
 SELECT * INTO v_case FROM public.organization_recovery_cases WHERE id=p_case_id FOR UPDATE;
 IF NOT FOUND OR v_case.status NOT IN ('COOLING','APPROVED') THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_NOT_OPEN';END IF;
 IF v_case.expires_at<=NOW() THEN UPDATE public.organization_recovery_cases SET status='EXPIRED',updated_at=NOW() WHERE id=p_case_id;RETURN jsonb_build_object('case_id',p_case_id,'status','EXPIRED');END IF;
 SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id FOR UPDATE;
 IF NOT FOUND OR UPPER(COALESCE(v_reviewer.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_reviewer.role,''))<>'SUPER_ADMIN' OR p_reviewer_id IN (v_case.requested_by,v_case.beneficiary_user_id,v_case.current_primary_user_id) THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_EXTERNAL_REVIEWER_REQUIRED';END IF;
 IF v_decision NOT IN ('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_REVIEW_INVALID';END IF;
 IF v_decision='REJECT' THEN UPDATE public.organization_recovery_cases SET status='REJECTED',reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_case_id;RETURN jsonb_build_object('case_id',p_case_id,'status','REJECTED');END IF;
 IF v_case.cooling_until>NOW() THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_COOLING_ACTIVE';END IF;
 SELECT * INTO v_org FROM public.organizations WHERE id=v_case.organization_id FOR UPDATE;
 IF v_org.primary_admin_user_id IS DISTINCT FROM v_case.current_primary_user_id THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_PRIMARY_CHANGED';END IF;
 SELECT COALESCE(MAX(min_approvals),2) INTO v_required FROM public.treasury_policies WHERE organization_id=v_case.organization_id AND is_active=TRUE;
 SELECT COUNT(*) INTO v_remaining FROM public.treasury_approvers ta JOIN public.users u ON u.id=ta.user_id WHERE ta.organization_id=v_case.organization_id AND ta.status='ACTIVE' AND ta.user_id<>v_case.current_primary_user_id AND UPPER(COALESCE(u.account_status,''))='ACTIVE';
 IF EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=v_case.organization_id AND user_id=v_case.current_primary_user_id AND status='ACTIVE') AND v_remaining<v_required THEN RAISE EXCEPTION 'ORGANIZATION_RECOVERY_TREASURY_QUORUM_REQUIRED';END IF;
 UPDATE public.user_sessions SET is_revoked=TRUE WHERE user_id=v_case.current_primary_user_id AND is_revoked=FALSE;
 UPDATE public.users SET account_status='SUSPENDED',status_reason='Organization recovery hold',status_reason_code='ORG_RECOVERY_HOLD',status_changed_at=NOW(),status_changed_by=p_reviewer_id::TEXT WHERE id=v_case.current_primary_user_id;
 UPDATE public.organizations SET primary_admin_user_id=v_case.beneficiary_user_id,updated_at=NOW() WHERE id=v_case.organization_id;
 UPDATE public.organization_recovery_cases SET status='EXECUTED',reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),executed_at=NOW(),updated_at=NOW() WHERE id=p_case_id;
 RETURN jsonb_build_object('case_id',p_case_id,'status','EXECUTED','sessions_revoked',TRUE,'new_primary_user_id',v_case.beneficiary_user_id);
END;$$;

REVOKE ALL ON FUNCTION public.request_organization_recovery_v1(UUID,UUID,UUID,TEXT,TEXT,JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_recovery_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_organization_recovery_v1(UUID,UUID,UUID,TEXT,TEXT,JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_recovery_v1(UUID,UUID,TEXT,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260915_organization_account_recovery.sql