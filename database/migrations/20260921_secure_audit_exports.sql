-- BEGIN SYNCED MIGRATION: 20260921_secure_audit_exports.sql
CREATE TABLE IF NOT EXISTS public.audit_export_requests(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),requested_by TEXT NOT NULL,reviewed_by TEXT,period_start TIMESTAMPTZ NOT NULL,period_end TIMESTAMPTZ NOT NULL,
 event_types TEXT[] NOT NULL DEFAULT '{}',action_prefix TEXT,format TEXT NOT NULL CHECK(format IN('JSON','CSV')),purpose TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','APPROVED','REJECTED','EXPIRED')),review_reason TEXT,idempotency_key TEXT NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(requested_by,idempotency_key)
);
CREATE TABLE IF NOT EXISTS public.audit_export_packages(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),request_id UUID NOT NULL UNIQUE REFERENCES public.audit_export_requests(id) ON DELETE RESTRICT,
 format TEXT NOT NULL CHECK(format IN('JSON','CSV')),entry_count INTEGER NOT NULL,manifest JSONB NOT NULL,content_hash TEXT NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '7 days'),download_count INTEGER NOT NULL DEFAULT 0,download_limit INTEGER NOT NULL DEFAULT 3,last_downloaded_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public.audit_export_entries(
 package_id UUID NOT NULL REFERENCES public.audit_export_packages(id) ON DELETE RESTRICT,sequence_number INTEGER NOT NULL,audit_id UUID NOT NULL REFERENCES public.audit_trail(id) ON DELETE RESTRICT,
 timestamp TIMESTAMPTZ NOT NULL,event_type TEXT NOT NULL,actor_id TEXT,transaction_id TEXT,action TEXT NOT NULL,metadata JSONB,hash TEXT NOT NULL,signature TEXT,
 PRIMARY KEY(package_id,sequence_number),UNIQUE(package_id,audit_id)
);
CREATE TABLE IF NOT EXISTS public.audit_export_downloads(package_id UUID NOT NULL REFERENCES public.audit_export_packages(id) ON DELETE RESTRICT,actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,download_number INTEGER NOT NULL,downloaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(package_id,actor_id,idempotency_key));
CREATE INDEX IF NOT EXISTS idx_audit_export_requests_status ON public.audit_export_requests(status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_export_entries_package ON public.audit_export_entries(package_id,sequence_number);
ALTER TABLE public.audit_export_requests ENABLE ROW LEVEL SECURITY;ALTER TABLE public.audit_export_packages ENABLE ROW LEVEL SECURITY;ALTER TABLE public.audit_export_entries ENABLE ROW LEVEL SECURITY;ALTER TABLE public.audit_export_downloads ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_export_requests_service ON public.audit_export_requests;DROP POLICY IF EXISTS audit_export_packages_service ON public.audit_export_packages;DROP POLICY IF EXISTS audit_export_entries_service ON public.audit_export_entries;
CREATE POLICY audit_export_requests_service ON public.audit_export_requests FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);CREATE POLICY audit_export_packages_service ON public.audit_export_packages FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);CREATE POLICY audit_export_entries_service ON public.audit_export_entries FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
DROP POLICY IF EXISTS audit_export_downloads_service ON public.audit_export_downloads;CREATE POLICY audit_export_downloads_service ON public.audit_export_downloads FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON TABLE public.audit_export_requests,public.audit_export_packages,public.audit_export_entries,public.audit_export_downloads FROM anon,authenticated;
GRANT SELECT,INSERT ON public.audit_export_requests,public.audit_export_packages,public.audit_export_entries,public.audit_export_downloads TO service_role;

CREATE OR REPLACE FUNCTION public.audit_export_officer_v1(p_actor_id TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path=public AS $$
 SELECT CASE WHEN p_actor_id!~*'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN FALSE ELSE EXISTS(SELECT 1 FROM public.staff WHERE id=p_actor_id::UUID AND UPPER(COALESCE(account_status,''))='ACTIVE' AND UPPER(COALESCE(role,'')) IN('SUPER_ADMIN','ADMIN','AUDIT','RISK_OFFICER')) OR EXISTS(SELECT 1 FROM public.users WHERE id=p_actor_id::UUID AND UPPER(COALESCE(account_status,''))='ACTIVE' AND UPPER(COALESCE(role,'')) IN('SUPER_ADMIN','ADMIN','AUDIT','RISK_OFFICER')) END
$$;
CREATE OR REPLACE FUNCTION public.request_audit_export_v1(p_actor_id TEXT,p_period_start TIMESTAMPTZ,p_period_end TIMESTAMPTZ,p_event_types TEXT[],p_action_prefix TEXT,p_format TEXT,p_purpose TEXT,p_idempotency_key TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_id UUID;v_format TEXT:=UPPER(BTRIM(COALESCE(p_format,'')));
BEGIN
 IF NOT public.audit_export_officer_v1(p_actor_id) THEN RAISE EXCEPTION 'AUDIT_EXPORT_ACCESS_DENIED';END IF;
 IF p_period_start>=p_period_end OR p_period_end>NOW() OR p_period_end-p_period_start>INTERVAL '90 days' OR v_format NOT IN('JSON','CSV') OR LENGTH(BTRIM(COALESCE(p_purpose,'')))<10 OR LENGTH(BTRIM(COALESCE(p_idempotency_key,'')))<8 OR COALESCE(cardinality(p_event_types),0)>20 THEN RAISE EXCEPTION 'AUDIT_EXPORT_REQUEST_INVALID';END IF;
 SELECT id INTO v_id FROM public.audit_export_requests WHERE requested_by=p_actor_id AND idempotency_key=BTRIM(p_idempotency_key);IF v_id IS NOT NULL THEN RETURN jsonb_build_object('request_id',v_id,'replayed',TRUE);END IF;
 UPDATE public.audit_export_requests SET status='EXPIRED',updated_at=NOW() WHERE status='PENDING' AND expires_at<=NOW();
 INSERT INTO public.audit_export_requests(requested_by,period_start,period_end,event_types,action_prefix,format,purpose,idempotency_key) VALUES(p_actor_id,p_period_start,p_period_end,COALESCE(p_event_types,'{}'),NULLIF(BTRIM(COALESCE(p_action_prefix,'')),''),v_format,BTRIM(p_purpose),BTRIM(p_idempotency_key)) ON CONFLICT(requested_by,idempotency_key) DO NOTHING RETURNING id INTO v_id;
 IF v_id IS NULL THEN SELECT id INTO v_id FROM public.audit_export_requests WHERE requested_by=p_actor_id AND idempotency_key=BTRIM(p_idempotency_key);RETURN jsonb_build_object('request_id',v_id,'replayed',TRUE);END IF;RETURN jsonb_build_object('request_id',v_id,'replayed',FALSE);
END$$;
CREATE OR REPLACE FUNCTION public.respond_audit_export_v1(p_reviewer_id TEXT,p_request_id UUID,p_decision TEXT,p_reason TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_r public.audit_export_requests%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));v_count INTEGER;v_package UUID;v_hash TEXT;v_manifest JSONB;
BEGIN
 SELECT * INTO v_r FROM public.audit_export_requests WHERE id=p_request_id FOR UPDATE;IF NOT FOUND OR v_r.status<>'PENDING' THEN RAISE EXCEPTION 'AUDIT_EXPORT_REQUEST_NOT_OPEN';END IF;
 IF v_r.expires_at<=NOW() THEN UPDATE public.audit_export_requests SET status='EXPIRED',updated_at=NOW() WHERE id=p_request_id;RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED');END IF;
 IF NOT public.audit_export_officer_v1(p_reviewer_id) OR p_reviewer_id=v_r.requested_by THEN RAISE EXCEPTION 'AUDIT_EXPORT_MAKER_CHECKER_REQUIRED';END IF;
 IF v_decision NOT IN('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'AUDIT_EXPORT_REVIEW_INVALID';END IF;
 IF v_decision='APPROVE' THEN
  SELECT COUNT(*) INTO v_count FROM public.audit_trail a WHERE a.timestamp>=v_r.period_start AND a.timestamp<v_r.period_end AND (cardinality(v_r.event_types)=0 OR a.event_type=ANY(v_r.event_types)) AND (v_r.action_prefix IS NULL OR a.action LIKE v_r.action_prefix||'%');
  IF v_count>25000 THEN RAISE EXCEPTION 'AUDIT_EXPORT_SCOPE_TOO_LARGE';END IF;
  v_manifest:=jsonb_build_object('requestId',v_r.id,'periodStart',v_r.period_start,'periodEnd',v_r.period_end,'eventTypes',v_r.event_types,'actionPrefix',v_r.action_prefix,'format',v_r.format,'entryCount',v_count,'generatedAt',NOW());
  INSERT INTO public.audit_export_packages(request_id,format,entry_count,manifest,content_hash) VALUES(v_r.id,v_r.format,v_count,v_manifest,repeat('0',64)) RETURNING id INTO v_package;
  INSERT INTO public.audit_export_entries SELECT v_package,ROW_NUMBER() OVER(ORDER BY a.timestamp,a.id),a.id,a.timestamp,a.event_type,a.actor_id,a.transaction_id,a.action,a.metadata,a.hash,a.signature FROM public.audit_trail a WHERE a.timestamp>=v_r.period_start AND a.timestamp<v_r.period_end AND (cardinality(v_r.event_types)=0 OR a.event_type=ANY(v_r.event_types)) AND (v_r.action_prefix IS NULL OR a.action LIKE v_r.action_prefix||'%') ORDER BY a.timestamp,a.id;
  SELECT encode(digest(convert_to(v_manifest::TEXT||'|'||COALESCE(string_agg(concat_ws('|',sequence_number,audit_id,timestamp,event_type,actor_id,transaction_id,action,hash,signature),E'\n' ORDER BY sequence_number),''),'UTF8'),'sha256'),'hex') INTO v_hash FROM public.audit_export_entries WHERE package_id=v_package;
  UPDATE public.audit_export_packages SET content_hash=v_hash WHERE id=v_package;
 END IF;
 UPDATE public.audit_export_requests SET status=CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
 RETURN jsonb_build_object('request_id',p_request_id,'status',CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,'package_id',v_package,'content_hash',v_hash,'entry_count',v_count);
END$$;
CREATE OR REPLACE FUNCTION public.claim_audit_export_download_v1(p_actor_id TEXT,p_package_id UUID,p_idempotency_key TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_p public.audit_export_packages%ROWTYPE;v_r public.audit_export_requests%ROWTYPE;v_existing INTEGER;
BEGIN SELECT * INTO v_p FROM public.audit_export_packages WHERE id=p_package_id FOR UPDATE;IF NOT FOUND THEN RAISE EXCEPTION 'AUDIT_EXPORT_NOT_FOUND';END IF;SELECT * INTO v_r FROM public.audit_export_requests WHERE id=v_p.request_id;
 IF NOT public.audit_export_officer_v1(p_actor_id) OR (p_actor_id<>v_r.requested_by AND p_actor_id<>v_r.reviewed_by) THEN RAISE EXCEPTION 'AUDIT_EXPORT_DOWNLOAD_DENIED';END IF;
 IF LENGTH(BTRIM(COALESCE(p_idempotency_key,'')))<8 THEN RAISE EXCEPTION 'AUDIT_EXPORT_DOWNLOAD_KEY_INVALID';END IF;
 SELECT download_number INTO v_existing FROM public.audit_export_downloads WHERE package_id=p_package_id AND actor_id=p_actor_id AND idempotency_key=BTRIM(p_idempotency_key);IF v_existing IS NOT NULL THEN RETURN jsonb_build_object('package_id',v_p.id,'format',v_p.format,'entry_count',v_p.entry_count,'manifest',v_p.manifest,'content_hash',v_p.content_hash,'download_number',v_existing,'replayed',TRUE);END IF;
 IF v_p.expires_at<=NOW() THEN RAISE EXCEPTION 'AUDIT_EXPORT_EXPIRED';END IF;IF v_p.download_count>=v_p.download_limit THEN RAISE EXCEPTION 'AUDIT_EXPORT_DOWNLOAD_LIMIT';END IF;
 UPDATE public.audit_export_packages SET download_count=download_count+1,last_downloaded_at=NOW() WHERE id=p_package_id;
 INSERT INTO public.audit_export_downloads(package_id,actor_id,idempotency_key,download_number) VALUES(p_package_id,p_actor_id,BTRIM(p_idempotency_key),v_p.download_count+1);
 RETURN jsonb_build_object('package_id',v_p.id,'format',v_p.format,'entry_count',v_p.entry_count,'manifest',v_p.manifest,'content_hash',v_p.content_hash,'download_number',v_p.download_count+1,'replayed',FALSE);
END$$;
REVOKE ALL ON FUNCTION public.audit_export_officer_v1(TEXT),public.request_audit_export_v1(TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT[],TEXT,TEXT,TEXT,TEXT),public.respond_audit_export_v1(TEXT,UUID,TEXT,TEXT),public.claim_audit_export_download_v1(TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_audit_export_v1(TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT[],TEXT,TEXT,TEXT,TEXT),public.respond_audit_export_v1(TEXT,UUID,TEXT,TEXT),public.claim_audit_export_download_v1(TEXT,UUID,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260921_secure_audit_exports.sql
