-- BEGIN SYNCED MIGRATION: 20260920_organization_statements.sql
CREATE TABLE IF NOT EXISTS public.organization_statements(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE RESTRICT,
 period_start TIMESTAMPTZ NOT NULL, period_end TIMESTAMPTZ NOT NULL, timezone TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'FINAL' CHECK(status IN ('FINAL','SUPERSEDED')),
 generated_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT, generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 line_count INTEGER NOT NULL DEFAULT 0, currency_totals JSONB NOT NULL DEFAULT '{}'::JSONB, content_hash TEXT NOT NULL,
 supersedes_statement_id UUID REFERENCES public.organization_statements(id) ON DELETE RESTRICT, reason TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(organization_id,period_start,period_end)
);
CREATE TABLE IF NOT EXISTS public.organization_statement_lines(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), statement_id UUID NOT NULL REFERENCES public.organization_statements(id) ON DELETE RESTRICT,
 sequence_number INTEGER NOT NULL, ledger_entry_id UUID NOT NULL REFERENCES public.financial_ledger(id) ON DELETE RESTRICT,
 transaction_id UUID REFERENCES public.transactions(id) ON DELETE RESTRICT, occurred_at TIMESTAMPTZ NOT NULL,
 reference_id TEXT, currency TEXT NOT NULL, entry_side TEXT NOT NULL CHECK(entry_side IN ('DEBIT','CREDIT')),
 amount NUMERIC NOT NULL CHECK(amount>=0), description TEXT, balance_after NUMERIC, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(statement_id,sequence_number),UNIQUE(statement_id,ledger_entry_id)
);
CREATE INDEX IF NOT EXISTS idx_org_statements_period ON public.organization_statements(organization_id,period_start DESC);
CREATE INDEX IF NOT EXISTS idx_org_statement_lines_order ON public.organization_statement_lines(statement_id,sequence_number);
ALTER TABLE public.organization_statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_statement_lines ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_statements_service ON public.organization_statements;
DROP POLICY IF EXISTS organization_statement_lines_service ON public.organization_statement_lines;
CREATE POLICY organization_statements_service ON public.organization_statements FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
CREATE POLICY organization_statement_lines_service ON public.organization_statement_lines FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON TABLE public.organization_statements,public.organization_statement_lines FROM anon,authenticated;
GRANT SELECT,INSERT ON TABLE public.organization_statements,public.organization_statement_lines TO service_role;
CREATE OR REPLACE FUNCTION public.guard_organization_statement_immutability() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=public AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_IMMUTABLE';END IF;
 IF TG_TABLE_NAME='organization_statement_lines' THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_LINE_IMMUTABLE';END IF;
 IF OLD.content_hash<>repeat('0',64) OR NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.period_start IS DISTINCT FROM OLD.period_start OR NEW.period_end IS DISTINCT FROM OLD.period_end OR NEW.generated_by IS DISTINCT FROM OLD.generated_by THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_IMMUTABLE';END IF;
 RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS trg_organization_statement_immutable ON public.organization_statements;
DROP TRIGGER IF EXISTS trg_organization_statement_line_immutable ON public.organization_statement_lines;
CREATE TRIGGER trg_organization_statement_immutable BEFORE UPDATE OR DELETE ON public.organization_statements FOR EACH ROW EXECUTE FUNCTION public.guard_organization_statement_immutability();
CREATE TRIGGER trg_organization_statement_line_immutable BEFORE UPDATE OR DELETE ON public.organization_statement_lines FOR EACH ROW EXECUTE FUNCTION public.guard_organization_statement_immutability();

CREATE OR REPLACE FUNCTION public.generate_organization_statement_v1(p_actor_id UUID,p_organization_id UUID,p_period_start TIMESTAMPTZ,p_period_end TIMESTAMPTZ,p_timezone TEXT,p_reason TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_actor public.users%ROWTYPE;v_id UUID;v_hash TEXT;v_count INTEGER;v_totals JSONB;v_tz TEXT:=BTRIM(COALESCE(p_timezone,''));
BEGIN
 SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
 IF NOT FOUND OR v_actor.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_actor.org_role,'')) NOT IN ('ADMIN','FINANCE','ACCOUNTANT','SIGNATORY') THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_ACCESS_DENIED';END IF;
 IF p_period_start>=p_period_end OR p_period_end>NOW() OR p_period_end-p_period_start>INTERVAL '1 year' OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 OR NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_tz) THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_PERIOD_INVALID';END IF;
 IF EXISTS(SELECT 1 FROM public.financial_ledger fl JOIN public.users u ON u.id=fl.user_id WHERE u.organization_id=p_organization_id AND fl.created_at>=p_period_start AND fl.created_at<p_period_end AND (fl.amount!~'^-?[0-9]+(\.[0-9]+)?$' OR UPPER(COALESCE(fl.entry_side,fl.entry_type,'')) NOT IN ('DEBIT','CREDIT'))) THEN RAISE EXCEPTION 'ORGANIZATION_STATEMENT_LEDGER_INVALID';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_organization_id::TEXT||p_period_start::TEXT||p_period_end::TEXT,0));
 SELECT id,content_hash,line_count,currency_totals INTO v_id,v_hash,v_count,v_totals FROM public.organization_statements WHERE organization_id=p_organization_id AND period_start=p_period_start AND period_end=p_period_end;
 IF v_id IS NOT NULL THEN RETURN jsonb_build_object('statement_id',v_id,'content_hash',v_hash,'line_count',v_count,'currency_totals',v_totals,'replayed',TRUE);END IF;
 INSERT INTO public.organization_statements(organization_id,period_start,period_end,timezone,generated_by,content_hash,reason) VALUES(p_organization_id,p_period_start,p_period_end,v_tz,p_actor_id,repeat('0',64),BTRIM(p_reason)) RETURNING id INTO v_id;
 INSERT INTO public.organization_statement_lines(statement_id,sequence_number,ledger_entry_id,transaction_id,occurred_at,reference_id,currency,entry_side,amount,description,balance_after)
 SELECT v_id,ROW_NUMBER() OVER(ORDER BY fl.created_at,fl.id),fl.id,fl.transaction_id,fl.created_at,t.reference_id,UPPER(COALESCE(t.currency,o.base_currency,'TZS')),
  CASE WHEN UPPER(COALESCE(fl.entry_side,fl.entry_type,''))='DEBIT' THEN 'DEBIT' ELSE 'CREDIT' END,
  CASE WHEN fl.amount~'^-?[0-9]+(\.[0-9]+)?$' THEN ABS(fl.amount::NUMERIC) ELSE 0 END,fl.description,
  CASE WHEN fl.balance_after~'^-?[0-9]+(\.[0-9]+)?$' THEN fl.balance_after::NUMERIC ELSE NULL END
 FROM public.financial_ledger fl JOIN public.users u ON u.id=fl.user_id JOIN public.organizations o ON o.id=p_organization_id
 LEFT JOIN public.transactions t ON t.id=fl.transaction_id
 WHERE u.organization_id=p_organization_id AND fl.created_at>=p_period_start AND fl.created_at<p_period_end ORDER BY fl.created_at,fl.id;
 SELECT COUNT(*) INTO v_count FROM public.organization_statement_lines WHERE statement_id=v_id;
 SELECT COALESCE(jsonb_object_agg(currency,jsonb_build_object('debits',debits,'credits',credits,'net',credits-debits)),'{}'::JSONB) INTO v_totals FROM (SELECT currency,COALESCE(SUM(amount) FILTER(WHERE entry_side='DEBIT'),0) debits,COALESCE(SUM(amount) FILTER(WHERE entry_side='CREDIT'),0) credits FROM public.organization_statement_lines WHERE statement_id=v_id GROUP BY currency) q;
 SELECT encode(digest(convert_to(COALESCE(string_agg(concat_ws('|',sequence_number,ledger_entry_id,transaction_id,occurred_at,reference_id,currency,entry_side,amount,description,balance_after),E'\n' ORDER BY sequence_number),'')||'|'||p_organization_id||'|'||p_period_start||'|'||p_period_end,'UTF8'),'sha256'),'hex') INTO v_hash FROM public.organization_statement_lines WHERE statement_id=v_id;
 UPDATE public.organization_statements SET line_count=v_count,currency_totals=v_totals,content_hash=v_hash WHERE id=v_id;
 RETURN jsonb_build_object('statement_id',v_id,'content_hash',v_hash,'line_count',v_count,'currency_totals',v_totals,'replayed',FALSE);
END$$;
REVOKE ALL ON FUNCTION public.generate_organization_statement_v1(UUID,UUID,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.generate_organization_statement_v1(UUID,UUID,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260920_organization_statements.sql
