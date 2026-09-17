-- BEGIN SYNCED MIGRATION: 20260918_shared_budget_governance_certification.sql
ALTER TABLE public.shared_budgets ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE public.shared_budget_invitations ADD COLUMN IF NOT EXISTS response_idempotency_key TEXT;
ALTER TABLE public.shared_budget_approvals ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE public.shared_budget_approvals ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ;
ALTER TABLE public.shared_budget_approvals ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE public.shared_budget_approvals DROP CONSTRAINT IF EXISTS shared_budget_approvals_status_check;
ALTER TABLE public.shared_budget_approvals ADD CONSTRAINT shared_budget_approvals_status_check CHECK(status IN ('PENDING','PROCESSING','APPROVED','REJECTED','FAILED','CANCELLED'));
CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_budget_owner_idempotency ON public.shared_budgets(owner_user_id,idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_budget_approval_idempotency ON public.shared_budget_approvals(requester_user_id,idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE OR REPLACE FUNCTION public.create_shared_budget_v1(p_actor_id UUID,p_name TEXT,p_purpose TEXT,p_currency TEXT,p_budget_limit NUMERIC,p_period_type TEXT,p_approval_mode TEXT,p_idempotency_key TEXT,p_metadata JSONB DEFAULT '{}'::jsonb)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_budget public.shared_budgets%ROWTYPE;v_key TEXT:=NULLIF(BTRIM(COALESCE(p_idempotency_key,'')),'');v_currency TEXT:=UPPER(BTRIM(COALESCE(p_currency,'TZS')));v_period TEXT:=UPPER(BTRIM(COALESCE(p_period_type,'MONTHLY')));v_mode TEXT:=UPPER(BTRIM(COALESCE(p_approval_mode,'AUTO')));
BEGIN
 IF auth.uid() IS NOT NULL AND auth.uid()<>p_actor_id THEN RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_INVALID';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.users WHERE id=p_actor_id AND UPPER(COALESCE(account_status,''))='ACTIVE') THEN RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_NOT_ACTIVE';END IF;
 IF v_key IS NULL THEN RAISE EXCEPTION 'SHARED_BUDGET_IDEMPOTENCY_REQUIRED';END IF;
 IF LENGTH(BTRIM(COALESCE(p_name,'')))<2 OR p_budget_limit IS NULL OR p_budget_limit<=0 OR v_period NOT IN ('WEEKLY','MONTHLY','CUSTOM') OR v_mode NOT IN ('AUTO','REVIEW') THEN RAISE EXCEPTION 'SHARED_BUDGET_CREATE_INVALID';END IF;
 SELECT * INTO v_budget FROM public.shared_budgets WHERE owner_user_id=p_actor_id AND idempotency_key=v_key FOR UPDATE;
 IF FOUND THEN
  IF v_budget.name<>BTRIM(p_name) OR UPPER(v_budget.currency)<>v_currency OR v_budget.budget_limit<>p_budget_limit OR v_budget.approval_mode<>v_mode THEN RAISE EXCEPTION 'SHARED_BUDGET_CREATE_REPLAY_MISMATCH';END IF;
  RETURN jsonb_build_object('budget',to_jsonb(v_budget),'idempotent',TRUE);
 END IF;
 INSERT INTO public.shared_budgets(owner_user_id,name,purpose,currency,budget_limit,funded_amount,spent_amount,period_type,approval_mode,status,idempotency_key,metadata)
 VALUES(p_actor_id,BTRIM(p_name),NULLIF(BTRIM(COALESCE(p_purpose,'')),''),v_currency,p_budget_limit,0,0,v_period,v_mode,'ACTIVE',v_key,COALESCE(p_metadata,'{}'::jsonb)||jsonb_build_object('created_atomically',TRUE)) RETURNING * INTO v_budget;
 INSERT INTO public.shared_budget_members(budget_id,user_id,role,status,spent_amount,metadata) VALUES(v_budget.id,p_actor_id,'OWNER','ACTIVE',0,jsonb_build_object('owner_membership',TRUE,'created_atomically',TRUE));
 RETURN jsonb_build_object('budget',to_jsonb(v_budget),'idempotent',FALSE);
END$$;

CREATE OR REPLACE FUNCTION public.respond_shared_budget_invitation_v1(p_actor_id UUID,p_invitation_id UUID,p_action TEXT,p_idempotency_key TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_inv public.shared_budget_invitations%ROWTYPE;v_member public.shared_budget_members%ROWTYPE;v_action TEXT:=UPPER(BTRIM(COALESCE(p_action,'')));v_key TEXT:=NULLIF(BTRIM(COALESCE(p_idempotency_key,'')),'');
BEGIN
 IF auth.uid() IS NOT NULL AND auth.uid()<>p_actor_id THEN RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_INVALID';END IF;
 IF v_key IS NULL OR v_action NOT IN ('ACCEPT','REJECT') THEN RAISE EXCEPTION 'SHARED_BUDGET_INVITE_RESPONSE_INVALID';END IF;
 SELECT * INTO v_inv FROM public.shared_budget_invitations WHERE id=p_invitation_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_BUDGET_INVITE_NOT_FOUND';END IF;
 IF v_inv.invitee_user_id<>p_actor_id THEN RAISE EXCEPTION 'SHARED_BUDGET_INVITE_ACCESS_DENIED';END IF;
 IF v_inv.status IN ('ACCEPTED','REJECTED') AND v_inv.response_idempotency_key=v_key THEN RETURN jsonb_build_object('invitation',to_jsonb(v_inv),'idempotent',TRUE);END IF;
 IF v_inv.status<>'PENDING' THEN RAISE EXCEPTION 'SHARED_BUDGET_INVITE_NOT_PENDING';END IF;
 IF v_inv.expires_at IS NOT NULL AND v_inv.expires_at<=NOW() THEN UPDATE public.shared_budget_invitations SET status='EXPIRED',updated_at=NOW() WHERE id=v_inv.id;RAISE EXCEPTION 'SHARED_BUDGET_INVITE_EXPIRED';END IF;
 IF v_action='ACCEPT' THEN INSERT INTO public.shared_budget_members(budget_id,user_id,role,status,member_limit,spent_amount,metadata) VALUES(v_inv.budget_id,p_actor_id,v_inv.role,'ACTIVE',v_inv.member_limit,0,jsonb_build_object('joined_via_invitation',v_inv.id)) ON CONFLICT(budget_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='ACTIVE',member_limit=EXCLUDED.member_limit,updated_at=NOW() RETURNING * INTO v_member;END IF;
 UPDATE public.shared_budget_invitations SET status=CASE WHEN v_action='ACCEPT' THEN 'ACCEPTED' ELSE 'REJECTED' END,response_idempotency_key=v_key,responded_at=NOW(),updated_at=NOW() WHERE id=v_inv.id RETURNING * INTO v_inv;
 RETURN jsonb_build_object('invitation',to_jsonb(v_inv),'member',CASE WHEN v_member.id IS NULL THEN NULL ELSE to_jsonb(v_member) END,'idempotent',FALSE);
END$$;

CREATE OR REPLACE FUNCTION public.request_shared_budget_approval_v1(p_actor_id UUID,p_budget_id UUID,p_amount NUMERIC,p_currency TEXT,p_provider TEXT,p_bill_category TEXT,p_reference TEXT,p_note TEXT,p_idempotency_key TEXT,p_metadata JSONB)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_budget public.shared_budgets%ROWTYPE;v_member public.shared_budget_members%ROWTYPE;v_existing public.shared_budget_approvals%ROWTYPE;v_pending NUMERIC;v_member_pending NUMERIC;v_key TEXT:=NULLIF(BTRIM(COALESCE(p_idempotency_key,'')),'');
BEGIN
 IF auth.uid() IS NOT NULL AND auth.uid()<>p_actor_id THEN RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_INVALID';END IF;
 IF v_key IS NULL OR p_amount IS NULL OR p_amount<=0 THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_INVALID';END IF;
 SELECT * INTO v_budget FROM public.shared_budgets WHERE id=p_budget_id FOR UPDATE;
 IF NOT FOUND OR v_budget.status<>'ACTIVE' OR v_budget.approval_mode<>'REVIEW' THEN RAISE EXCEPTION 'SHARED_BUDGET_REVIEW_REQUIRED';END IF;
 SELECT * INTO v_member FROM public.shared_budget_members WHERE budget_id=p_budget_id AND user_id=p_actor_id AND status='ACTIVE' FOR UPDATE;
 IF NOT FOUND OR v_member.role NOT IN ('OWNER','MANAGER','SPENDER') THEN RAISE EXCEPTION 'SHARED_BUDGET_SPEND_DENIED';END IF;
 SELECT * INTO v_existing FROM public.shared_budget_approvals WHERE requester_user_id=p_actor_id AND idempotency_key=v_key FOR UPDATE;
 IF FOUND THEN IF v_existing.shared_budget_id<>p_budget_id OR v_existing.amount<>p_amount OR UPPER(v_existing.currency)<>UPPER(p_currency) THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_REPLAY_MISMATCH';END IF;RETURN jsonb_build_object('approval',to_jsonb(v_existing),'idempotent',TRUE);END IF;
 SELECT COALESCE(SUM(amount),0) INTO v_pending FROM public.shared_budget_approvals WHERE shared_budget_id=p_budget_id AND status IN ('PENDING','PROCESSING');
 SELECT COALESCE(SUM(amount),0) INTO v_member_pending FROM public.shared_budget_approvals WHERE shared_budget_id=p_budget_id AND requester_user_id=p_actor_id AND status IN ('PENDING','PROCESSING');
 IF COALESCE(v_budget.funded_amount,0)-COALESCE(v_budget.spent_amount,0)-v_pending<p_amount THEN RAISE EXCEPTION 'SHARED_BUDGET_FUNDS_RESERVED';END IF;
 IF v_member.member_limit IS NOT NULL AND COALESCE(v_member.spent_amount,0)+v_member_pending+p_amount>v_member.member_limit THEN RAISE EXCEPTION 'SHARED_BUDGET_MEMBER_LIMIT_RESERVED';END IF;
 INSERT INTO public.shared_budget_approvals(shared_budget_id,requester_user_id,amount,currency,provider,bill_category,reference,note,status,idempotency_key,metadata) VALUES(p_budget_id,p_actor_id,p_amount,UPPER(p_currency),p_provider,p_bill_category,p_reference,p_note,'PENDING',v_key,COALESCE(p_metadata,'{}'::jsonb)) RETURNING * INTO v_existing;
 RETURN jsonb_build_object('approval',to_jsonb(v_existing),'idempotent',FALSE);
END$$;

CREATE OR REPLACE FUNCTION public.claim_shared_budget_approval_v1(p_reviewer_id UUID,p_approval_id UUID,p_action TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_a public.shared_budget_approvals%ROWTYPE;v_m public.shared_budget_members%ROWTYPE;v_action TEXT:=UPPER(BTRIM(COALESCE(p_action,'')));
BEGIN
 SELECT * INTO v_a FROM public.shared_budget_approvals WHERE id=p_approval_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_NOT_FOUND';END IF;
 IF p_reviewer_id=v_a.requester_user_id THEN RAISE EXCEPTION 'SHARED_BUDGET_MAKER_CHECKER_REQUIRED';END IF;
 SELECT * INTO v_m FROM public.shared_budget_members WHERE budget_id=v_a.shared_budget_id AND user_id=p_reviewer_id AND status='ACTIVE' FOR UPDATE;
 IF NOT FOUND OR v_m.role NOT IN ('OWNER','MANAGER') THEN RAISE EXCEPTION 'SHARED_BUDGET_REVIEW_DENIED';END IF;
 IF v_action='REJECT' AND v_a.status='PENDING' THEN UPDATE public.shared_budget_approvals SET status='REJECTED',reviewer_user_id=p_reviewer_id,responded_at=NOW(),updated_at=NOW() WHERE id=p_approval_id RETURNING * INTO v_a;RETURN jsonb_build_object('approval',to_jsonb(v_a),'execute',FALSE);END IF;
 IF v_action<>'APPROVE' THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_ACTION_INVALID';END IF;
 IF v_a.status='PROCESSING' AND v_a.processing_started_at>NOW()-INTERVAL '15 minutes' THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_IN_PROGRESS';END IF;
 IF v_a.status NOT IN ('PENDING','PROCESSING','FAILED') THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_NOT_OPEN';END IF;
 UPDATE public.shared_budget_approvals SET status='PROCESSING',reviewer_user_id=p_reviewer_id,processing_started_at=NOW(),last_error=NULL,updated_at=NOW() WHERE id=p_approval_id RETURNING * INTO v_a;
 RETURN jsonb_build_object('approval',to_jsonb(v_a),'execute',TRUE);
END$$;

CREATE OR REPLACE FUNCTION public.finish_shared_budget_approval_v1(p_reviewer_id UUID,p_approval_id UUID,p_status TEXT,p_transaction_id UUID,p_error TEXT DEFAULT NULL)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_a public.shared_budget_approvals%ROWTYPE;v_status TEXT:=UPPER(BTRIM(COALESCE(p_status,'')));
BEGIN
 SELECT * INTO v_a FROM public.shared_budget_approvals WHERE id=p_approval_id FOR UPDATE;
 IF NOT FOUND OR v_a.status<>'PROCESSING' OR v_a.reviewer_user_id<>p_reviewer_id THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_CLAIM_REQUIRED';END IF;
 IF v_status NOT IN ('APPROVED','FAILED') THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_FINISH_INVALID';END IF;
 IF v_status='APPROVED' AND p_transaction_id IS NULL THEN RAISE EXCEPTION 'SHARED_BUDGET_APPROVAL_TRANSACTION_REQUIRED';END IF;
 UPDATE public.shared_budget_approvals SET status=v_status,responded_at=CASE WHEN v_status='APPROVED' THEN NOW() ELSE responded_at END,last_error=LEFT(p_error,1000),metadata=COALESCE(metadata,'{}'::jsonb)||CASE WHEN p_transaction_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('approved_transaction_id',p_transaction_id) END,updated_at=NOW() WHERE id=p_approval_id RETURNING * INTO v_a;
 RETURN to_jsonb(v_a);
END$$;

REVOKE ALL ON FUNCTION public.create_shared_budget_v1(UUID,TEXT,TEXT,TEXT,NUMERIC,TEXT,TEXT,TEXT,JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_shared_budget_invitation_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.request_shared_budget_approval_v1(UUID,UUID,NUMERIC,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.claim_shared_budget_approval_v1(UUID,UUID,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.finish_shared_budget_approval_v1(UUID,UUID,TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_shared_budget_v1(UUID,TEXT,TEXT,TEXT,NUMERIC,TEXT,TEXT,TEXT,JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_shared_budget_invitation_v1(UUID,UUID,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.request_shared_budget_approval_v1(UUID,UUID,NUMERIC,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_shared_budget_approval_v1(UUID,UUID,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.finish_shared_budget_approval_v1(UUID,UUID,TEXT,UUID,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260918_shared_budget_governance_certification.sql
