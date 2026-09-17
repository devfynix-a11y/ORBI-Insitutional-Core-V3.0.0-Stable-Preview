-- External API credentials and authorization guard.
-- Raw credentials are returned once by the application and never persisted.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.api_keys
  ADD COLUMN IF NOT EXISTS secret_hash TEXT,
  ADD COLUMN IF NOT EXISTS secret_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'live',
  ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT 'orbi-core',
  ADD COLUMN IF NOT EXISTS service_code TEXT,
  ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS issued_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

UPDATE public.api_keys
SET secret_hash = encode(digest(secret_key, 'sha256'), 'hex'),
    secret_fingerprint = left(encode(digest(secret_key, 'sha256'), 'hex'), 16),
    environment = CASE WHEN secret_key LIKE 'sk_test_%' THEN 'sandbox' ELSE 'live' END,
    scopes = CASE WHEN cardinality(scopes) = 0 THEN ARRAY['wallets:read']::TEXT[] ELSE scopes END
WHERE secret_key IS NOT NULL AND secret_hash IS NULL;

INSERT INTO public.pay_gateway_developer_services(service_code,display_name,status,environments,scopes_granted,metadata)
SELECT DISTINCT 'tenant:'||k.tenant_id::TEXT, 'Tenant '||k.tenant_id::TEXT, 'active',
       ARRAY[k.environment]::TEXT[], k.scopes, jsonb_build_object('migratedLegacyCredential',true)
FROM public.api_keys k
ON CONFLICT(service_code) DO UPDATE SET
  environments=(SELECT ARRAY(SELECT DISTINCT unnest(public.pay_gateway_developer_services.environments||EXCLUDED.environments))),
  scopes_granted=(SELECT ARRAY(SELECT DISTINCT unnest(public.pay_gateway_developer_services.scopes_granted||EXCLUDED.scopes_granted)));
UPDATE public.api_keys SET service_code='tenant:'||tenant_id::TEXT WHERE service_code IS NULL;
ALTER TABLE public.api_keys ALTER COLUMN service_code SET NOT NULL;

ALTER TABLE public.api_keys ALTER COLUMN secret_key DROP NOT NULL;
UPDATE public.api_keys SET secret_key = NULL WHERE secret_key IS NOT NULL;

DO $$ BEGIN
  ALTER TABLE public.api_keys ADD CONSTRAINT api_keys_environment_check CHECK (environment IN ('sandbox','live'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_secret_hash ON public.api_keys(secret_hash) WHERE secret_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_runtime_guard ON public.api_keys(status, environment, audience, secret_hash);

CREATE OR REPLACE FUNCTION public.authorize_external_api_request_v1(
  p_secret_hash TEXT,
  p_environment TEXT,
  p_audience TEXT,
  p_required_scopes TEXT[],
  p_subject_user_id UUID DEFAULT NULL,
  p_purpose TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_key public.api_keys%ROWTYPE; v_profile public.payment_profiles%ROWTYPE;
BEGIN
  IF coalesce(trim(p_secret_hash),'') = '' OR p_environment NOT IN ('sandbox','live')
     OR coalesce(trim(p_audience),'') = '' OR cardinality(p_required_scopes) = 0 THEN
    RAISE EXCEPTION 'EXTERNAL_API_CONTEXT_INVALID';
  END IF;
  SELECT * INTO v_key FROM public.api_keys
   WHERE secret_hash=p_secret_hash AND status='ACTIVE'
     AND environment=p_environment AND audience=p_audience
     AND (expires_at IS NULL OR expires_at>NOW()) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'EXTERNAL_API_CREDENTIAL_DENIED'; END IF;
  IF NOT v_key.scopes @> p_required_scopes THEN RAISE EXCEPTION 'EXTERNAL_API_SCOPE_DENIED'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.pay_gateway_developer_services s WHERE s.service_code=v_key.service_code AND s.status='active' AND p_environment=ANY(s.environments) AND s.scopes_granted @> p_required_scopes)
  THEN RAISE EXCEPTION 'EXTERNAL_API_SERVICE_DENIED'; END IF;
  IF p_subject_user_id IS NOT NULL THEN
    IF coalesce(trim(p_purpose),'')='' OR v_key.service_code IS NULL THEN RAISE EXCEPTION 'EXTERNAL_API_CONSENT_CONTEXT_REQUIRED'; END IF;
    SELECT * INTO v_profile FROM public.payment_profiles p
     WHERE p.service_code=v_key.service_code AND p.user_id=p_subject_user_id
       AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>NOW())
       AND p.scopes @> p_required_scopes
       AND coalesce(p.consent_payload->>'purpose','')=p_purpose
     ORDER BY p.updated_at DESC LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'EXTERNAL_API_CONSENT_DENIED'; END IF;
  END IF;
  UPDATE public.api_keys SET last_used_at=NOW(),updated_at=NOW() WHERE id=v_key.id;
  RETURN jsonb_build_object('keyId',v_key.id,'tenantId',v_key.tenant_id,'serviceCode',v_key.service_code,'environment',v_key.environment,'audience',v_key.audience,'scopes',v_key.scopes,'subjectUserId',p_subject_user_id);
END $$;

REVOKE ALL ON FUNCTION public.authorize_external_api_request_v1(TEXT,TEXT,TEXT,TEXT[],UUID,TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.authorize_external_api_request_v1(TEXT,TEXT,TEXT,TEXT[],UUID,TEXT) TO service_role;
NOTIFY pgrst, 'reload schema';
