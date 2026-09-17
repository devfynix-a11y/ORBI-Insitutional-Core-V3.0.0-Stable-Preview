-- Isolated, deterministic developer sandbox. No financial or customer tables are referenced.
CREATE TABLE IF NOT EXISTS public.sandbox_payment_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service_code TEXT NOT NULL REFERENCES public.pay_gateway_developer_services(service_code) ON DELETE CASCADE,
  intent_id TEXT NOT NULL,
  reference TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN('collection','payout','refund','paysafe')),
  scenario TEXT NOT NULL CHECK(scenario IN('success','decline','timeout','requires_action')),
  request_hash TEXT NOT NULL,
  amount NUMERIC(20,2) NOT NULL CHECK(amount>=0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN('completed','failed','pending','requires_action')),
  response_payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(service_code,intent_id)
);
ALTER TABLE public.sandbox_payment_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sandbox_payment_runs_service ON public.sandbox_payment_runs;
CREATE POLICY sandbox_payment_runs_service ON public.sandbox_payment_runs FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON public.sandbox_payment_runs FROM anon,authenticated;
GRANT SELECT,INSERT,UPDATE ON public.sandbox_payment_runs TO service_role;

CREATE OR REPLACE FUNCTION public.simulate_sandbox_payment_v1(
 p_service_code TEXT,p_intent_id TEXT,p_reference TEXT,p_operation TEXT,p_scenario TEXT,
 p_request_hash TEXT,p_amount NUMERIC,p_currency TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_run public.sandbox_payment_runs%ROWTYPE;v_status TEXT;v_response JSONB;v_challenge TEXT;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.pay_gateway_developer_services s WHERE s.service_code=p_service_code AND s.status='active' AND 'sandbox'=ANY(s.environments)) THEN RAISE EXCEPTION 'SANDBOX_SERVICE_DENIED';END IF;
 IF BTRIM(COALESCE(p_intent_id,''))='' OR BTRIM(COALESCE(p_reference,''))='' OR LOWER(p_operation) NOT IN('collection','payout','refund','paysafe') OR LOWER(p_scenario) NOT IN('success','decline','timeout','requires_action') OR BTRIM(COALESCE(p_request_hash,''))='' OR p_amount<0 OR BTRIM(COALESCE(p_currency,''))='' THEN RAISE EXCEPTION 'SANDBOX_REQUEST_INVALID';END IF;
 SELECT * INTO v_run FROM public.sandbox_payment_runs WHERE service_code=p_service_code AND intent_id=p_intent_id FOR UPDATE;
 IF FOUND THEN
   IF v_run.request_hash<>p_request_hash THEN RAISE EXCEPTION 'SANDBOX_REPLAY_MISMATCH';END IF;
   RETURN v_run.response_payload||jsonb_build_object('replayed',TRUE);
 END IF;
 v_status:=CASE LOWER(p_scenario) WHEN 'success' THEN 'completed' WHEN 'decline' THEN 'failed' WHEN 'timeout' THEN 'pending' ELSE 'requires_action' END;
 v_challenge:='sim_ch_'||LEFT(encode(digest(p_service_code||':'||p_intent_id,'sha256'),'hex'),24);
 v_response:=jsonb_build_object('intentId',p_intent_id,'serviceCode',p_service_code,'environment','sandbox','scenario',LOWER(p_scenario),'status',v_status,'reference',p_reference,'operation',LOWER(p_operation),'amount',ROUND(p_amount,2),'currency',UPPER(p_currency),'replayed',FALSE,'simulation',TRUE,
   'message',CASE LOWER(p_scenario) WHEN 'success' THEN 'Sandbox payment completed.' WHEN 'decline' THEN 'Sandbox payment declined.' WHEN 'timeout' THEN 'Sandbox payment remains pending for timeout testing.' ELSE 'Sandbox authorization is required.' END);
 IF LOWER(p_scenario)='requires_action' THEN v_response:=v_response||jsonb_build_object('challenge',jsonb_build_object('type','OTP','challengeId',v_challenge,'prompt','Use sandbox code 000000.','delivery',jsonb_build_object('channel','in_app','destinationHint','sandbox only')));END IF;
 INSERT INTO public.sandbox_payment_runs(service_code,intent_id,reference,operation,scenario,request_hash,amount,currency,status,response_payload) VALUES(p_service_code,p_intent_id,p_reference,LOWER(p_operation),LOWER(p_scenario),p_request_hash,ROUND(p_amount,2),UPPER(p_currency),v_status,v_response);
 RETURN v_response;
END$$;
REVOKE ALL ON FUNCTION public.simulate_sandbox_payment_v1(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,NUMERIC,TEXT) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.simulate_sandbox_payment_v1(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,NUMERIC,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
