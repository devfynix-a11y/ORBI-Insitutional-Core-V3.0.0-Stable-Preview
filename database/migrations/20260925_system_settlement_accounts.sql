-- Company accounts are segregated by purpose and currency. This migration creates
-- zero-balance internal vaults; treasury must fund FX clearing before conversions settle.
CREATE TABLE IF NOT EXISTS public.system_settlement_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role TEXT NOT NULL CHECK (role IN ('SERVICE_REVENUE', 'TAX_RESERVE', 'FX_CLEARING', 'FX_SPREAD_REVENUE', 'FX_RISK_RESERVE', 'COMMISSION_RESERVE')),
  currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  vault_id UUID NOT NULL UNIQUE REFERENCES public.platform_vaults(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DISABLED')),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (role, currency)
);

ALTER TABLE public.system_settlement_accounts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Service role company settlement accounts" ON public.system_settlement_accounts;
CREATE POLICY "Service role company settlement accounts" ON public.system_settlement_accounts
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DO $$
DECLARE
  code TEXT;
  purpose TEXT;
  new_vault_id UUID;
BEGIN
  FOR code IN
    SELECT DISTINCT currency_code FROM (
      SELECT 'TZS' AS currency_code UNION SELECT 'USD'
      UNION SELECT from_currency FROM public.fx_corridors
      UNION SELECT to_currency FROM public.fx_corridors
      UNION SELECT currency FROM public.platform_fee_configs WHERE currency ~ '^[A-Z]{3}$'
    ) available WHERE currency_code ~ '^[A-Z]{3}$'
  LOOP
    FOREACH purpose IN ARRAY ARRAY['SERVICE_REVENUE', 'TAX_RESERVE', 'FX_CLEARING', 'FX_SPREAD_REVENUE', 'FX_RISK_RESERVE', 'COMMISSION_RESERVE']
    LOOP
      IF NOT EXISTS (SELECT 1 FROM public.system_settlement_accounts WHERE role = purpose AND currency = code) THEN
        new_vault_id := gen_random_uuid();
        INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, currency, status, metadata)
        VALUES (new_vault_id, NULL, purpose, 'ORBI ' || purpose || ' ' || code, 0, code, 'active',
          jsonb_build_object('owner', 'ORBI', 'account_role', purpose, 'currency', code, 'provisioning', '20260925_system_settlement_accounts'));
        INSERT INTO public.system_settlement_accounts (role, currency, vault_id)
        VALUES (purpose, code, new_vault_id);
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- Legacy fee aliases remain for old reports, but their TZS mappings now point
-- to the correctly denominated company accounts.
UPDATE public.fee_collector_wallets fcw
SET vault_id = ssa.vault_id, currency = 'TZS', updated_at = NOW()
FROM public.system_settlement_accounts ssa
WHERE fcw.fee_type = 'SERVICE_FEE' AND ssa.role = 'SERVICE_REVENUE' AND ssa.currency = 'TZS';

UPDATE public.fee_collector_wallets fcw
SET vault_id = ssa.vault_id, currency = 'TZS', updated_at = NOW()
FROM public.system_settlement_accounts ssa
WHERE fcw.fee_type = 'GOV_TAX' AND ssa.role = 'TAX_RESERVE' AND ssa.currency = 'TZS';
