-- ORBI SOVEREIGN MASTER SCHEMA V93.0 (IDEMPOTENT MASTER KEY)
-- This script is designed to be run multiple times without data loss.
-- It adds missing columns, tables, and updates functions to the latest version.
-- V93.0: Added append_ledger_entries_v1 for atomic ledger updates and enhanced reconciliation support.
DROP FUNCTION IF EXISTS public.card_settle_v1(TEXT, UUID, UUID, NUMERIC) CASCADE;
DROP FUNCTION IF EXISTS public.bill_reserve_adjust_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB, NUMERIC) CASCADE;

-- 1. CORE EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Supabase-compatible auth namespace for self-hosted/fresh Postgres installs.
-- Existing managed auth schemas are left untouched.
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS orbi_auth;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN NOINHERIT; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN NOINHERIT; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; END IF;
END
$$;
CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID,
    aud TEXT DEFAULT 'authenticated',
    role TEXT DEFAULT 'authenticated',
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    encrypted_password TEXT NOT NULL,
    email_confirmed_at TIMESTAMPTZ,
    phone_confirmed_at TIMESTAMPTZ,
    confirmation_sent_at TIMESTAMPTZ,
    recovery_sent_at TIMESTAMPTZ,
    last_sign_in_at TIMESTAMPTZ,
    raw_app_meta_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_user_meta_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION auth.uid()
RETURNS UUID
LANGUAGE SQL
STABLE
AS $$
  SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
CREATE OR REPLACE FUNCTION auth.role()
RETURNS TEXT
LANGUAGE SQL
STABLE
AS $$
  SELECT COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), 'service_role')
$$;
CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS JSONB
LANGUAGE SQL
STABLE
AS $$
  SELECT COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
$$;

-- 2. TABLES DEFINITION (IDEMPOTENT)
                                                                                                                                                                                                                                                                                                                                       
CREATE TABLE IF NOT EXISTS public.secrets (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.schema_migrations (
    version TEXT PRIMARY KEY,
    description TEXT,
    checksum TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.wal_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL,
    meta JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
COMMENT ON TABLE public.audit_logs IS 'LEGACY / NON-AUTHORITATIVE. Do not use for production-critical financial, settlement, webhook, or privileged repair auditing. Use audit_trail, transaction_events, financial_events, provider_webhook_events, and settlement_lifecycle instead.';

CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    email TEXT UNIQUE,
    customer_id TEXT UNIQUE NOT NULL, 
    phone TEXT,
    nationality TEXT DEFAULT 'Tanzania',
    address TEXT,
    avatar_url TEXT,
    currency TEXT DEFAULT 'TZS',
    preferred_currency TEXT DEFAULT 'TZS',
    country_code TEXT,
    country_name TEXT,
    dial_code TEXT,
    account_status TEXT DEFAULT 'pending_confirmation',
    status_reason TEXT,
    status_reason_code TEXT,
    status_changed_at TIMESTAMP WITH TIME ZONE,
    status_changed_by TEXT,
    auth_confirmed_at TIMESTAMP WITH TIME ZONE,
    activation_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '24 hours'),
    activation_method TEXT,
    registry_type TEXT DEFAULT 'CONSUMER',
    role TEXT DEFAULT 'USER',
    app_origin TEXT DEFAULT 'OBI_INSTITUTIONAL_CORE_V25',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    kyc_level INTEGER DEFAULT 0,
    kyc_status TEXT DEFAULT 'unverified',
    id_type TEXT,
    id_number TEXT,
    language TEXT DEFAULT 'en',
    -- Channel-level notification preferences consumed by mobile settings/profile sync.
    notif_push BOOLEAN DEFAULT TRUE,
    notif_email BOOLEAN DEFAULT TRUE,
    notif_security BOOLEAN DEFAULT TRUE,
    notif_financial BOOLEAN DEFAULT TRUE,
    notif_budget BOOLEAN DEFAULT TRUE,
    notif_marketing BOOLEAN DEFAULT FALSE,
    fcm_token TEXT,
    security_tx_pin_hash TEXT,
    security_tx_pin_enabled BOOLEAN DEFAULT FALSE,
    security_biometric_enabled BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb
);
COMMENT ON COLUMN public.users.metadata IS 'User profile metadata. clientTimeContext stores the explicit registration/request timezone or UTC offset used only for user-facing display resolution; canonical financial audit timestamps remain stored in UTC columns.';

-- Enforce unique phone numbers among users (NULL allowed multiple times)
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique
ON public.users (phone)
WHERE phone IS NOT NULL;

DO $$
BEGIN
    ALTER TABLE public.users ALTER COLUMN email DROP NOT NULL;
    ALTER TABLE public.users ALTER COLUMN account_status SET DEFAULT 'pending_confirmation';
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='auth_confirmed_at'
    ) THEN
        ALTER TABLE public.users ADD COLUMN auth_confirmed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='activation_expires_at'
    ) THEN
        ALTER TABLE public.users ADD COLUMN activation_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '24 hours');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='activation_method'
    ) THEN
        ALTER TABLE public.users ADD COLUMN activation_method TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='status_reason') THEN
        ALTER TABLE public.users ADD COLUMN status_reason TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='status_reason_code') THEN
        ALTER TABLE public.users ADD COLUMN status_reason_code TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='status_changed_at') THEN
        ALTER TABLE public.users ADD COLUMN status_changed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='status_changed_by') THEN
        ALTER TABLE public.users ADD COLUMN status_changed_by TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_pending_activation_expiry
ON public.users (activation_expires_at)
WHERE account_status IN ('pending_confirmation', 'unconfirmed', 'inactive');

CREATE INDEX IF NOT EXISTS idx_users_account_status_reason
ON public.users(account_status, status_reason_code, status_changed_at DESC);

-- Compatibility View for user_profiles
CREATE OR REPLACE VIEW public.user_profiles AS SELECT * FROM public.users;

CREATE TABLE IF NOT EXISTS public.staff (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    account_status TEXT DEFAULT 'pending_confirmation',
    status_reason TEXT,
    status_reason_code TEXT,
    status_changed_at TIMESTAMP WITH TIME ZONE,
    status_changed_by TEXT,
    auth_confirmed_at TIMESTAMP WITH TIME ZONE,
    activation_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '24 hours'),
    activation_method TEXT,
    customer_id TEXT UNIQUE NOT NULL,
    phone TEXT,
    avatar_url TEXT,
    address TEXT,
    nationality TEXT DEFAULT 'Tanzania',
    language TEXT DEFAULT 'en',
    -- Channel-level notification preferences consumed by staff/admin messaging flows.
    notif_push BOOLEAN DEFAULT TRUE,
    notif_email BOOLEAN DEFAULT TRUE,
    notif_security BOOLEAN DEFAULT TRUE,
    notif_financial BOOLEAN DEFAULT TRUE,
    notif_budget BOOLEAN DEFAULT TRUE,
    notif_marketing BOOLEAN DEFAULT FALSE,
    fcm_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='staff' AND column_name='address'
    ) THEN
        ALTER TABLE public.staff ADD COLUMN address TEXT;
    END IF;
END $$;

-- Enforce unique phone numbers among staff (NULL allowed multiple times)
DO $$
BEGIN
    ALTER TABLE public.staff ALTER COLUMN account_status SET DEFAULT 'pending_confirmation';
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='staff' AND column_name='auth_confirmed_at'
    ) THEN
        ALTER TABLE public.staff ADD COLUMN auth_confirmed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='staff' AND column_name='activation_expires_at'
    ) THEN
        ALTER TABLE public.staff ADD COLUMN activation_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '24 hours');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='staff' AND column_name='activation_method'
    ) THEN
        ALTER TABLE public.staff ADD COLUMN activation_method TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='staff' AND column_name='status_reason') THEN
        ALTER TABLE public.staff ADD COLUMN status_reason TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='staff' AND column_name='status_reason_code') THEN
        ALTER TABLE public.staff ADD COLUMN status_reason_code TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='staff' AND column_name='status_changed_at') THEN
        ALTER TABLE public.staff ADD COLUMN status_changed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='staff' AND column_name='status_changed_by') THEN
        ALTER TABLE public.staff ADD COLUMN status_changed_by TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_staff_pending_activation_expiry
ON public.staff (activation_expires_at)
WHERE account_status IN ('pending_confirmation', 'unconfirmed', 'inactive');

CREATE INDEX IF NOT EXISTS idx_staff_account_status_reason
ON public.staff(account_status, status_reason_code, status_changed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS staff_phone_unique
ON public.staff (phone)
WHERE phone IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'individual' CHECK (type IN ('individual', 'merchant', 'marketplace', 'partner', 'enterprise')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'PENDING', 'CLOSED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.tenant_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'operator', 'member', 'viewer')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'INVITED', 'REMOVED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT tenant_users_unique_user_per_tenant UNIQUE (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL UNIQUE,
    secret_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    permissions TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.tenant_settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES public.tenants(id) ON DELETE CASCADE,
    destination_type TEXT DEFAULT 'bank',
    account_name TEXT,
    account_number TEXT,
    bank_code TEXT,
    phone TEXT,
    currency TEXT NOT NULL DEFAULT 'TZS',
    schedule TEXT DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DISABLED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.settlement_payouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    fee_deducted NUMERIC(20, 6) NOT NULL DEFAULT 0,
    net_amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'TZS',
    status TEXT NOT NULL DEFAULT 'PROCESSING' CHECK (status IN ('PROCESSING', 'PENDING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    destination_snapshot JSONB DEFAULT '{}'::jsonb,
    reference TEXT UNIQUE,
    provider_ref TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.behavior_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
    typing_cadence JSONB DEFAULT '{}'::jsonb,
    device_motion JSONB DEFAULT '{}'::jsonb,
    navigation_pattern JSONB DEFAULT '{}'::jsonb,
    risk_score NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    tenant_id UUID REFERENCES public.tenants(id) ON DELETE SET NULL,
    owner_type TEXT DEFAULT 'user',
    name TEXT NOT NULL, 
    balance NUMERIC DEFAULT 0, 
    currency TEXT DEFAULT 'TZS', 
    color TEXT, 
    icon TEXT, 
    management_tier TEXT DEFAULT 'linked', 
    type TEXT DEFAULT 'operating', 
    is_primary BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'active',
    is_locked BOOLEAN DEFAULT FALSE,
    locked_at TIMESTAMP WITH TIME ZONE,
    lock_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.platform_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    vault_role TEXT, 
    name TEXT,
    balance NUMERIC DEFAULT 0, 
    encrypted_balance TEXT, 
    currency TEXT DEFAULT 'TZS', 
    color TEXT, 
    icon TEXT,
    status TEXT DEFAULT 'active',
    is_locked BOOLEAN DEFAULT FALSE,
    locked_at TIMESTAMP WITH TIME ZONE,
    lock_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='wallets' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN tenant_id UUID REFERENCES public.tenants(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='wallets' AND column_name='owner_type'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN owner_type TEXT DEFAULT 'user';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='is_locked'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN is_locked BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='locked_at'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN locked_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='wallets' AND column_name='lock_reason'
    ) THEN
        ALTER TABLE public.wallets ADD COLUMN lock_reason TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='status'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN status TEXT DEFAULT 'active';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='is_locked'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN is_locked BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='locked_at'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN locked_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='platform_vaults' AND column_name='lock_reason'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN lock_reason TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='platform_vaults' AND column_name='metadata'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN metadata JSONB DEFAULT '{}'::jsonb;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='platform_vaults' AND column_name='updated_at'
    ) THEN
        ALTER TABLE public.platform_vaults ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.ent_system_vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_purpose VARCHAR(50) UNIQUE NOT NULL,
    wallet_id UUID UNIQUE NOT NULL REFERENCES public.wallets(id) ON DELETE RESTRICT,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON COLUMN public.platform_vaults.metadata IS
  'JSON metadata. External reconciliation reads provider_id, providerId, provider_code, providerCode, partner_id, partnerId, partner_code, or partnerCode from this object.';

CREATE INDEX IF NOT EXISTS idx_platform_vaults_metadata_provider_id
  ON public.platform_vaults ((metadata->>'provider_id'));

CREATE INDEX IF NOT EXISTS idx_platform_vaults_metadata_provider_code
  ON public.platform_vaults ((metadata->>'provider_code'));

CREATE INDEX IF NOT EXISTS idx_platform_vaults_user_role_currency_status
  ON public.platform_vaults(user_id, vault_role, currency, status);

CREATE OR REPLACE FUNCTION public.set_platform_vault_partner_mapping(
  p_vault_id UUID,
  p_provider_id UUID DEFAULT NULL,
  p_provider_code TEXT DEFAULT NULL
)
RETURNS public.platform_vaults
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_partner RECORD;
  v_vault public.platform_vaults%ROWTYPE;
  v_provider_code TEXT;
BEGIN
  IF p_provider_id IS NULL AND BTRIM(COALESCE(p_provider_code, '')) = '' THEN
    RAISE EXCEPTION 'PROVIDER_MAPPING_REQUIRED';
  END IF;

  IF p_provider_id IS NOT NULL THEN
    SELECT * INTO v_partner FROM public.financial_partners WHERE id = p_provider_id LIMIT 1;
  ELSE
    SELECT *
      INTO v_partner
      FROM public.financial_partners
     WHERE BTRIM(LOWER(provider_metadata->>'provider_code')) = BTRIM(LOWER(p_provider_code))
     LIMIT 1;
  END IF;

  IF v_partner.id IS NULL THEN
    RAISE EXCEPTION 'FINANCIAL_PARTNER_NOT_FOUND';
  END IF;

  v_provider_code := BTRIM(COALESCE(v_partner.provider_metadata->>'provider_code', p_provider_code, v_partner.name));

  UPDATE public.platform_vaults
     SET metadata = COALESCE(metadata, '{}'::jsonb)
       || jsonb_build_object(
            'provider_id', v_partner.id,
            'provider_code', v_provider_code,
            'partner_id', v_partner.id,
            'partner_code', v_provider_code,
            'provider_mapping_updated_at', NOW()
          ),
         updated_at = NOW()
   WHERE id = p_vault_id
   RETURNING * INTO v_vault;

  IF v_vault.id IS NULL THEN
    RAISE EXCEPTION 'PLATFORM_VAULT_NOT_FOUND';
  END IF;

  RETURN v_vault;
END;
$$;

CREATE OR REPLACE VIEW public.platform_vault_provider_mapping_gaps AS
SELECT
  pv.id,
  pv.name,
  pv.vault_role,
  pv.currency,
  pv.status,
  pv.metadata,
  pv.created_at,
  pv.updated_at
FROM public.platform_vaults pv
WHERE COALESCE(pv.status, 'active') = 'active'
  AND (
    NULLIF(BTRIM(COALESCE(pv.metadata->>'provider_id', pv.metadata->>'providerId', pv.metadata->>'partner_id', pv.metadata->>'partnerId')), '') IS NULL
    AND NULLIF(BTRIM(COALESCE(pv.metadata->>'provider_code', pv.metadata->>'providerCode', pv.metadata->>'partner_code', pv.metadata->>'partnerCode')), '') IS NULL
  );

CREATE TABLE IF NOT EXISTS public.transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_id TEXT UNIQUE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES public.tenants(id) ON DELETE SET NULL,
    wallet_id UUID,
    to_wallet_id UUID,
    amount TEXT NOT NULL,
    currency TEXT DEFAULT 'TZS',
    description TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('created', 'pending', 'authorized', 'processing', 'settled', 'completed', 'failed', 'cancelled', 'held_for_review', 'awaiting_receiver_acceptance', 'paysafe_confirmed', 'return_requested', 'reversed', 'refunded')),
    status_notes TEXT,
    date DATE DEFAULT CURRENT_DATE,
    settlement_id UUID,
    settlement_status TEXT DEFAULT 'PENDING',
    merchant_name TEXT,
    category TEXT,
    provider TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.transaction_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    old_state TEXT,
    new_state TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure category_id exists in transactions
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='category_id') THEN
        ALTER TABLE public.transactions ADD COLUMN category_id UUID;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='reference_id') THEN
        ALTER TABLE public.transactions ADD COLUMN reference_id TEXT UNIQUE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='currency') THEN
        ALTER TABLE public.transactions ADD COLUMN currency TEXT DEFAULT 'TZS';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='tenant_id') THEN
        ALTER TABLE public.transactions ADD COLUMN tenant_id UUID REFERENCES public.tenants(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='settlement_id') THEN
        ALTER TABLE public.transactions ADD COLUMN settlement_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='settlement_status') THEN
        ALTER TABLE public.transactions ADD COLUMN settlement_status TEXT DEFAULT 'PENDING';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='merchant_name') THEN
        ALTER TABLE public.transactions ADD COLUMN merchant_name TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='category') THEN
        ALTER TABLE public.transactions ADD COLUMN category TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transactions' AND column_name='provider') THEN
        ALTER TABLE public.transactions ADD COLUMN provider TEXT;
    END IF;

    -- Add User Setting Columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='language') THEN
        ALTER TABLE public.users ADD COLUMN language TEXT DEFAULT 'en';
    END IF;
    -- Keep live databases aligned with the app/backend notification preference contract.
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_push') THEN
        ALTER TABLE public.users ADD COLUMN notif_push BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_email') THEN
        ALTER TABLE public.users ADD COLUMN notif_email BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_security') THEN
        ALTER TABLE public.users ADD COLUMN notif_security BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_financial') THEN
        ALTER TABLE public.users ADD COLUMN notif_financial BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_budget') THEN
        ALTER TABLE public.users ADD COLUMN notif_budget BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='notif_marketing') THEN
        ALTER TABLE public.users ADD COLUMN notif_marketing BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='fcm_token') THEN
        ALTER TABLE public.users ADD COLUMN fcm_token TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_tx_pin_hash') THEN
        ALTER TABLE public.users ADD COLUMN security_tx_pin_hash TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_tx_pin_enabled') THEN
        ALTER TABLE public.users ADD COLUMN security_tx_pin_enabled BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='security_biometric_enabled') THEN
        ALTER TABLE public.users ADD COLUMN security_biometric_enabled BOOLEAN DEFAULT FALSE;
    END IF;

    -- Add language and notification preferences to staff
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='language') THEN
        ALTER TABLE public.staff ADD COLUMN language TEXT DEFAULT 'en';
    END IF;
    -- Keep live databases aligned with the staff messaging preference contract.
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_push') THEN
        ALTER TABLE public.staff ADD COLUMN notif_push BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_email') THEN
        ALTER TABLE public.staff ADD COLUMN notif_email BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_security') THEN
        ALTER TABLE public.staff ADD COLUMN notif_security BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_financial') THEN
        ALTER TABLE public.staff ADD COLUMN notif_financial BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_budget') THEN
        ALTER TABLE public.staff ADD COLUMN notif_budget BOOLEAN DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='notif_marketing') THEN
        ALTER TABLE public.staff ADD COLUMN notif_marketing BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='staff' AND column_name='fcm_token') THEN
        ALTER TABLE public.staff ADD COLUMN fcm_token TEXT;
    END IF;
END $$;

DO $$
DECLARE
    tx_constraint RECORD;
BEGIN
    FOR tx_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'transactions'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) LIKE '%status%'
          AND pg_get_constraintdef(c.oid) NOT LIKE '%settled%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.transactions DROP CONSTRAINT %I',
            tx_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'transactions'
          AND c.conname = 'transactions_status_check_v2'
    ) THEN
        ALTER TABLE public.transactions
            ADD CONSTRAINT transactions_status_check_v2
            CHECK (
                status IN (
                    'created',
                    'pending',
                    'authorized',
                    'processing',
                    'settled',
                    'completed',
                    'failed',
                    'cancelled',
                    'held_for_review',
                    'awaiting_receiver_acceptance',
                    'paysafe_confirmed',
                    'return_requested',
                    'reversed',
                    'refunded'
                )
            );
    END IF;
END $$;

UPDATE public.transactions
SET
    merchant_name = COALESCE(
        NULLIF(BTRIM(merchant_name), ''),
        NULLIF(BTRIM(metadata->>'merchant_name'), ''),
        NULLIF(BTRIM(metadata->>'merchantName'), ''),
        NULLIF(BTRIM(metadata->>'business_name'), ''),
        NULLIF(BTRIM(metadata->>'businessName'), '')
    ),
    category = COALESCE(
        NULLIF(BTRIM(category), ''),
        NULLIF(BTRIM(metadata->>'category'), ''),
        NULLIF(BTRIM(metadata->>'category_name'), ''),
        NULLIF(BTRIM(metadata->>'categoryName'), ''),
        NULLIF(BTRIM(metadata->>'category_code'), ''),
        NULLIF(BTRIM(metadata->>'categoryCode'), '')
    ),
    provider = COALESCE(
        NULLIF(BTRIM(provider), ''),
        NULLIF(BTRIM(metadata->>'provider'), ''),
        NULLIF(BTRIM(metadata->>'provider_name'), ''),
        NULLIF(BTRIM(metadata->>'providerName'), ''),
        NULLIF(BTRIM(metadata->>'provider_code'), ''),
        NULLIF(BTRIM(metadata->>'providerCode'), '')
    )
WHERE merchant_name IS NULL
   OR category IS NULL
   OR provider IS NULL;

CREATE INDEX IF NOT EXISTS idx_transactions_user_merchant_recent
    ON public.transactions (user_id, merchant_name, created_at DESC)
    WHERE merchant_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_transactions_user_category_recent
    ON public.transactions (user_id, category, created_at DESC)
    WHERE category IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.transaction_quotes (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    payload_hash TEXT NOT NULL,
    quote_signature TEXT,
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    quote_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    currency TEXT,
    transaction_type TEXT,
    source_wallet_id UUID,
    target_wallet_id UUID,
    total_debit NUMERIC(20, 6) NOT NULL DEFAULT 0,
    total_fee NUMERIC(20, 6) NOT NULL DEFAULT 0,
    provider_code TEXT,
    fee_config_id TEXT,
    can_submit BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'QUOTED',
    idempotency_key TEXT,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    settlement_result JSONB,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    settled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT transaction_quotes_status_check CHECK (
        status IN ('QUOTED', 'READY', 'BLOCKED', 'CONFIRMED', 'SETTLING', 'SETTLED', 'FAILED', 'EXPIRED', 'CANCELLED')
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_quotes_user_status
    ON public.transaction_quotes(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transaction_quotes_expires
    ON public.transaction_quotes(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_transaction_quotes_idempotency
    ON public.transaction_quotes(user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.fx_margin_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_currency TEXT NOT NULL,
    to_currency TEXT NOT NULL,
    base_rate_source TEXT NOT NULL DEFAULT 'ORBI_RATE_ENGINE',
    spread_mode TEXT NOT NULL DEFAULT 'BPS' CHECK (spread_mode IN ('BPS', 'PIPS', 'FIXED_UNIT')),
    fixed_pips NUMERIC(20, 8) NOT NULL DEFAULT 0 CHECK (fixed_pips >= 0),
    margin_bps INTEGER NOT NULL DEFAULT 75 CHECK (margin_bps >= 0 AND margin_bps <= 2500),
    risk_buffer_bps INTEGER NOT NULL DEFAULT 25 CHECK (risk_buffer_bps >= 0 AND risk_buffer_bps <= 2500),
    quote_lock_seconds INTEGER NOT NULL DEFAULT 45 CHECK (quote_lock_seconds >= 15 AND quote_lock_seconds <= 900),
    min_amount NUMERIC(20, 6),
    max_amount NUMERIC(20, 6),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DISABLED')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fx_margin_policies_pair_check CHECK (from_currency <> to_currency),
    CONSTRAINT fx_margin_policies_currency_check CHECK (
        from_currency ~ '^[A-Z]{3}$' AND to_currency ~ '^[A-Z]{3}$'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fx_margin_policies_pair
    ON public.fx_margin_policies(from_currency, to_currency);
CREATE INDEX IF NOT EXISTS idx_fx_margin_policies_status
    ON public.fx_margin_policies(status, from_currency, to_currency);

INSERT INTO public.fx_margin_policies (
    from_currency, to_currency, spread_mode, fixed_pips, margin_bps, risk_buffer_bps, quote_lock_seconds, min_amount, max_amount, metadata
) VALUES
    ('TZS', 'USD', 'BPS', 0, 75, 25, 45, 1000, 500000000, '{"class":"international_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'TZS', 'BPS', 0, 75, 25, 45, 1, 250000, '{"class":"international_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('TZS', 'KES', 'BPS', 0, 90, 35, 45, 1000, 500000000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('KES', 'TZS', 'BPS', 0, 90, 35, 45, 100, 25000000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'KES', 'BPS', 0, 90, 35, 45, 1, 250000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('KES', 'USD', 'BPS', 0, 90, 35, 45, 100, 25000000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'UGX', 'BPS', 0, 100, 50, 45, 1, 250000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('UGX', 'USD', 'BPS', 0, 100, 50, 45, 1000, 500000000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'RWF', 'BPS', 0, 100, 50, 45, 1, 250000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('RWF', 'USD', 'BPS', 0, 100, 50, 45, 1000, 500000000, '{"class":"regional_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'EUR', 'BPS', 0, 70, 25, 45, 1, 250000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('EUR', 'USD', 'BPS', 0, 70, 25, 45, 1, 250000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('EUR', 'TZS', 'BPS', 0, 85, 30, 45, 1, 250000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('TZS', 'EUR', 'BPS', 0, 85, 30, 45, 1000, 500000000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('USD', 'GBP', 'BPS', 0, 70, 25, 45, 1, 250000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb),
    ('GBP', 'USD', 'BPS', 0, 70, 25, 45, 1, 250000, '{"class":"global_fx","pricing":"bid_ask_spread_no_fee"}'::jsonb)
ON CONFLICT (from_currency, to_currency) DO UPDATE SET
    spread_mode = EXCLUDED.spread_mode,
    fixed_pips = EXCLUDED.fixed_pips,
    margin_bps = EXCLUDED.margin_bps,
    risk_buffer_bps = EXCLUDED.risk_buffer_bps,
    quote_lock_seconds = EXCLUDED.quote_lock_seconds,
    min_amount = EXCLUDED.min_amount,
    max_amount = EXCLUDED.max_amount,
    status = 'ACTIVE',
    metadata = public.fx_margin_policies.metadata || EXCLUDED.metadata,
    updated_at = NOW();

CREATE TABLE IF NOT EXISTS public.fx_corridors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_currency TEXT NOT NULL,
    to_currency TEXT NOT NULL,
    corridor_code TEXT GENERATED ALWAYS AS (from_currency || '_' || to_currency) STORED,
    rate_provider_code TEXT NOT NULL DEFAULT 'OPEN_ER_API',
    settlement_provider_id UUID,
    settlement_mode TEXT NOT NULL DEFAULT 'INTERNAL_LEDGER' CHECK (settlement_mode IN ('INTERNAL_LEDGER', 'EXTERNAL_LP', 'HYBRID')),
    priority INTEGER NOT NULL DEFAULT 100,
    min_amount NUMERIC(20, 6),
    max_amount NUMERIC(20, 6),
    supported_countries TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DISABLED')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fx_corridors_pair_check CHECK (from_currency <> to_currency),
    CONSTRAINT fx_corridors_currency_check CHECK (
        from_currency ~ '^[A-Z]{3}$' AND to_currency ~ '^[A-Z]{3}$'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fx_corridors_pair_provider
    ON public.fx_corridors(from_currency, to_currency, rate_provider_code);
CREATE INDEX IF NOT EXISTS idx_fx_corridors_lookup
    ON public.fx_corridors(from_currency, to_currency, status, priority);
CREATE INDEX IF NOT EXISTS idx_fx_corridors_provider
    ON public.fx_corridors(rate_provider_code, status);

CREATE TABLE IF NOT EXISTS public.fx_provider_health (
    provider_code TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEGRADED', 'PAUSED', 'DISABLED')),
    last_checked_at TIMESTAMP WITH TIME ZONE,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_failure_at TIMESTAMP WITH TIME ZONE,
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    latency_ms INTEGER,
    message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fx_provider_health_status
    ON public.fx_provider_health(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS public.fx_treasury_exposure_limits (
    currency TEXT PRIMARY KEY,
    max_net_exposure_usd NUMERIC(20, 6) NOT NULL DEFAULT 0 CHECK (max_net_exposure_usd >= 0),
    max_daily_volume_usd NUMERIC(20, 6) NOT NULL DEFAULT 0 CHECK (max_daily_volume_usd >= 0),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'DISABLED')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT fx_treasury_exposure_limits_currency_check CHECK (currency ~ '^[A-Z]{3}$')
);

CREATE INDEX IF NOT EXISTS idx_fx_treasury_exposure_limits_status
    ON public.fx_treasury_exposure_limits(status, currency);

CREATE TABLE IF NOT EXISTS public.fx_reconciliation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quote_id TEXT,
    transaction_id UUID,
    user_id UUID,
    from_currency TEXT NOT NULL,
    to_currency TEXT NOT NULL,
    source_amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    target_amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    customer_rate NUMERIC(20, 8),
    market_rate NUMERIC(20, 8),
    spread_amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    spread_currency TEXT,
    provider_code TEXT,
    settlement_mode TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'MATCHED', 'MISMATCHED', 'FAILED', 'REVERSED')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fx_reconciliation_events_status_created
    ON public.fx_reconciliation_events(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fx_reconciliation_events_quote
    ON public.fx_reconciliation_events(quote_id);
CREATE INDEX IF NOT EXISTS idx_fx_reconciliation_events_user_created
    ON public.fx_reconciliation_events(user_id, created_at DESC);

INSERT INTO public.fx_corridors (
    from_currency, to_currency, rate_provider_code, settlement_mode, priority, min_amount, max_amount, supported_countries, metadata
) VALUES
    ('TZS', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 10, 1000, 500000000, ARRAY['TZ'], '{"class":"international_fx","note":"Starter international corridor; switch settlement_provider_id when bank/LP contract is live."}'::jsonb),
    ('USD', 'TZS', 'OPEN_ER_API', 'INTERNAL_LEDGER', 10, 1, 250000, ARRAY['TZ'], '{"class":"international_fx","note":"Starter international corridor; switch settlement_provider_id when bank/LP contract is live."}'::jsonb),
    ('TZS', 'KES', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1000, 500000000, ARRAY['TZ','KE'], '{"class":"regional_fx"}'::jsonb),
    ('KES', 'TZS', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 100, 25000000, ARRAY['KE','TZ'], '{"class":"regional_fx"}'::jsonb),
    ('USD', 'KES', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1, 250000, ARRAY['US','KE'], '{"class":"regional_fx"}'::jsonb),
    ('KES', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 100, 25000000, ARRAY['KE','US'], '{"class":"regional_fx"}'::jsonb),
    ('USD', 'UGX', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1, 250000, ARRAY['US','UG'], '{"class":"regional_fx"}'::jsonb),
    ('UGX', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1000, 500000000, ARRAY['UG','US'], '{"class":"regional_fx"}'::jsonb),
    ('USD', 'RWF', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1, 250000, ARRAY['US','RW'], '{"class":"regional_fx"}'::jsonb),
    ('RWF', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 20, 1000, 500000000, ARRAY['RW','US'], '{"class":"regional_fx"}'::jsonb),
    ('USD', 'EUR', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1, 250000, ARRAY[]::TEXT[], '{"class":"global_fx"}'::jsonb),
    ('EUR', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1, 250000, ARRAY[]::TEXT[], '{"class":"global_fx"}'::jsonb),
    ('EUR', 'TZS', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1, 250000, ARRAY['EU','TZ'], '{"class":"global_fx"}'::jsonb),
    ('TZS', 'EUR', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1000, 500000000, ARRAY['TZ','EU'], '{"class":"global_fx"}'::jsonb),
    ('USD', 'GBP', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1, 250000, ARRAY[]::TEXT[], '{"class":"global_fx"}'::jsonb),
    ('GBP', 'USD', 'OPEN_ER_API', 'INTERNAL_LEDGER', 30, 1, 250000, ARRAY[]::TEXT[], '{"class":"global_fx"}'::jsonb)
ON CONFLICT (from_currency, to_currency, rate_provider_code) DO UPDATE SET
    settlement_mode = EXCLUDED.settlement_mode,
    priority = EXCLUDED.priority,
    min_amount = EXCLUDED.min_amount,
    max_amount = EXCLUDED.max_amount,
    supported_countries = EXCLUDED.supported_countries,
    status = 'ACTIVE',
    metadata = public.fx_corridors.metadata || EXCLUDED.metadata,
    updated_at = NOW();

CREATE TABLE IF NOT EXISTS public.financial_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    wallet_id UUID,
    shared_pot_id UUID,
    bill_reserve_id UUID,
    bucket_type TEXT,
    entry_side TEXT,
    entry_type TEXT NOT NULL,
    amount TEXT NOT NULL,
    balance_after TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure balance_after_encrypted exists in financial_ledger
ALTER TABLE public.financial_ledger ADD COLUMN IF NOT EXISTS currency TEXT;
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='balance_after_encrypted') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN balance_after_encrypted TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='shared_pot_id') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN shared_pot_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='bill_reserve_id') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN bill_reserve_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='bucket_type') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN bucket_type TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_ledger' AND column_name='entry_side') THEN
        ALTER TABLE public.financial_ledger ADD COLUMN entry_side TEXT;
    END IF;
END $$;

-- Ledger audit owner guard:
-- financial_ledger.user_id must represent the owner of wallet_id. The actor
-- remains on transactions.user_id and audit_trail. This prevents a sender's
-- ID from appearing on recipient-owned ledger legs in audit/report views.
CREATE OR REPLACE FUNCTION public.resolve_financial_ledger_wallet_owner(
    p_wallet_id UUID,
    p_fallback_user_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_owner UUID;
BEGIN
    IF p_wallet_id IS NULL THEN
        RETURN p_fallback_user_id;
    END IF;

    SELECT COALESCE(w.user_id, pv.user_id, g.user_id, p_fallback_user_id)
      INTO v_owner
      FROM (SELECT p_wallet_id AS id) x
      LEFT JOIN public.wallets w ON w.id = x.id
      LEFT JOIN public.platform_vaults pv ON pv.id = x.id
      LEFT JOIN public.goals g ON g.id = x.id;

    RETURN COALESCE(v_owner, p_fallback_user_id);
END;
$$ LANGUAGE plpgsql STABLE SET search_path = public;

COMMENT ON FUNCTION public.resolve_financial_ledger_wallet_owner(UUID, UUID)
IS 'Resolves the owner of a financial ledger wallet/vault/goal. Used for audit ownership only; balances remain wallet_id based.';

CREATE OR REPLACE FUNCTION public.set_financial_ledger_wallet_owner()
RETURNS trigger AS $$
BEGIN
    NEW.user_id := public.resolve_financial_ledger_wallet_owner(NEW.wallet_id, NEW.user_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

DROP TRIGGER IF EXISTS trg_financial_ledger_wallet_owner ON public.financial_ledger;
CREATE TRIGGER trg_financial_ledger_wallet_owner
BEFORE INSERT OR UPDATE OF wallet_id, user_id ON public.financial_ledger
FOR EACH ROW
EXECUTE FUNCTION public.set_financial_ledger_wallet_owner();

UPDATE public.financial_ledger fl
   SET user_id = public.resolve_financial_ledger_wallet_owner(fl.wallet_id, fl.user_id)
 WHERE fl.wallet_id IS NOT NULL
   AND fl.user_id IS DISTINCT FROM public.resolve_financial_ledger_wallet_owner(fl.wallet_id, fl.user_id);


CREATE TABLE IF NOT EXISTS public.ledger_append_markers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES public.transactions(id) ON DELETE CASCADE,
    append_key TEXT,
    append_phase TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_append_markers_append_key
    ON public.ledger_append_markers(append_key)
    WHERE append_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_append_markers_tx_phase
    ON public.ledger_append_markers(transaction_id, append_phase)
    WHERE append_phase IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.goals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    target NUMERIC NOT NULL, 
    current NUMERIC DEFAULT 0, 
    target_amount NUMERIC,
    current_amount NUMERIC DEFAULT 0,
    source_wallet_id UUID REFERENCES public.wallets(id),
    deadline TIMESTAMP WITH TIME ZONE, 
    color TEXT, 
    icon TEXT, 
    funding_strategy TEXT DEFAULT 'manual', 
    auto_allocation_enabled BOOLEAN DEFAULT FALSE, 
    linked_income_percentage NUMERIC,
    monthly_target NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='goals' AND column_name='source_wallet_id'
    ) THEN
        ALTER TABLE public.goals ADD COLUMN source_wallet_id UUID REFERENCES public.wallets(id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.goal_auto_allocation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    goal_id UUID REFERENCES public.goals(id) ON DELETE CASCADE,
    source_transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    source_reference_id TEXT,
    source_wallet_id UUID,
    source_amount NUMERIC DEFAULT 0,
    allocated_amount NUMERIC DEFAULT 0,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('DEPOSIT', 'SALARY', 'REMITTANCE', 'CARD_DEPOSIT', 'EXTERNAL_DEPOSIT', 'AGENT_CASH_DEPOSIT', 'MANUAL_REPLAY')),
    status TEXT NOT NULL DEFAULT 'PROCESSING' CHECK (status IN ('PROCESSING', 'COMPLETED', 'SKIPPED', 'FAILED')),
    reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_goal_auto_allocation_goal_tx
    ON public.goal_auto_allocation_events(goal_id, source_transaction_id);
CREATE INDEX IF NOT EXISTS idx_goal_auto_allocation_user_created
    ON public.goal_auto_allocation_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_goal_auto_allocation_goal_created
    ON public.goal_auto_allocation_events(goal_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    name TEXT NOT NULL, 
    budget TEXT, 
    spent_amount NUMERIC DEFAULT 0,
    color TEXT, 
    icon TEXT, 
    budget_period TEXT DEFAULT 'MONTHLY',
    budget_interval TEXT DEFAULT 'MONTHLY',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ORBI WEALTH: structured money planning for everyday users, businesses,
-- enterprises, and premium users.
CREATE TABLE IF NOT EXISTS public.wealth_buckets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    bucket_type TEXT NOT NULL CHECK (bucket_type IN ('OPERATING', 'PLANNED', 'PROTECTED', 'GROWING')),
    wallet_id UUID,
    currency TEXT DEFAULT 'TZS',
    ledger_balance NUMERIC DEFAULT 0,
    available_balance NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, bucket_type, currency)
);

CREATE TABLE IF NOT EXISTS public.allocation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger_type TEXT NOT NULL CHECK (trigger_type IN ('DEPOSIT', 'SALARY', 'ROUNDUP', 'REMITTANCE', 'MANUAL')),
    source_wallet_id UUID,
    target_type TEXT NOT NULL CHECK (target_type IN ('GOAL', 'BUDGET', 'BILL_RESERVE', 'SHARED_POT', 'WEALTH_BUCKET')),
    target_id UUID,
    mode TEXT NOT NULL DEFAULT 'PERCENT' CHECK (mode IN ('FIXED', 'PERCENT')),
    fixed_amount NUMERIC,
    percentage NUMERIC,
    priority INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Organizations are referenced by shared wealth services below, so the
-- canonical table must exist before those foreign keys are declared.
CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    creator_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    primary_admin_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    owner_type TEXT NOT NULL DEFAULT 'ORGANIZATION' CHECK (owner_type IN ('ORGANIZATION', 'GROUP', 'COMPANY')),
    owner_label TEXT,
    registration_number TEXT,
    tax_id TEXT,
    country TEXT,
    base_currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_pots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    purpose TEXT,
    currency TEXT DEFAULT 'TZS',
    target_amount NUMERIC,
    current_amount NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED', 'ARCHIVED')),
    access_model TEXT DEFAULT 'INVITE' CHECK (access_model IN ('INVITE', 'PRIVATE', 'ORG')),
    governance_model TEXT NOT NULL DEFAULT 'OWNER_CONTROLLED' CHECK (governance_model IN ('OWNER_CONTROLLED', 'MEMBER_APPROVAL', 'ORG_APPROVAL')),
    withdrawal_policy TEXT NOT NULL DEFAULT 'OWNER_OR_MANAGER' CHECK (withdrawal_policy IN ('OWNER_ONLY', 'OWNER_OR_MANAGER', 'APPROVAL_REQUIRED')),
    min_withdrawal_approvals INTEGER NOT NULL DEFAULT 1 CHECK (min_withdrawal_approvals >= 1 AND min_withdrawal_approvals <= 10),
    withdrawal_limit_amount NUMERIC,
    maturity_at TIMESTAMPTZ,
    require_withdrawal_reason BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_pot_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'CONTRIBUTOR' CHECK (role IN ('OWNER', 'MANAGER', 'CONTRIBUTOR', 'VIEWER')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'REMOVED')),
    contribution_target NUMERIC,
    contributed_amount NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (pot_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.shared_pot_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    inviter_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_identifier TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'CONTRIBUTOR' CHECK (role IN ('MANAGER', 'CONTRIBUTOR', 'VIEWER')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    message TEXT,
    responded_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_pot_withdrawal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID NOT NULL REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    requester_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    target_wallet_id UUID NOT NULL,
    amount NUMERIC NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL DEFAULT 'TZS',
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXECUTED')),
    required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals >= 1 AND required_approvals <= 10),
    approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    rejection_reason TEXT,
    transaction_id UUID,
    idempotency_key TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS public.shared_pot_delete_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pot_id UUID NOT NULL REFERENCES public.shared_pots(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL'
        CHECK (status IN ('PENDING_APPROVAL', 'SCHEDULED', 'CANCELLED', 'REJECTED', 'ARCHIVED')),
    required_approvals INTEGER NOT NULL DEFAULT 3 CHECK (required_approvals >= 3),
    approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason TEXT,
    otp_verified_at TIMESTAMPTZ,
    scheduled_archive_at TIMESTAMPTZ,
    archived_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS public.shared_budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    purpose TEXT,
    currency TEXT DEFAULT 'TZS',
    budget_limit NUMERIC NOT NULL,
    funded_amount NUMERIC DEFAULT 0,
    spent_amount NUMERIC DEFAULT 0,
    auto_allocate_enabled BOOLEAN DEFAULT FALSE,
    auto_allocate_mode TEXT DEFAULT 'MANUAL' CHECK (auto_allocate_mode IN ('MANUAL', 'FIXED', 'PERCENT')),
    auto_allocate_amount NUMERIC DEFAULT 0,
    auto_allocate_threshold NUMERIC DEFAULT 0,
    period_type TEXT DEFAULT 'MONTHLY' CHECK (period_type IN ('WEEKLY', 'MONTHLY', 'CUSTOM')),
    approval_mode TEXT DEFAULT 'AUTO' CHECK (approval_mode IN ('AUTO', 'REVIEW')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'ARCHIVED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'SPENDER' CHECK (role IN ('OWNER', 'MANAGER', 'SPENDER', 'VIEWER')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'REMOVED')),
    member_limit NUMERIC,
    spent_amount NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (budget_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.shared_budget_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    inviter_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    invitee_identifier TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'SPENDER' CHECK (role IN ('MANAGER', 'SPENDER', 'VIEWER')),
    member_limit NUMERIC,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    message TEXT,
    responded_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    member_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    source_wallet_id UUID,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    merchant_name TEXT,
    provider TEXT,
    category TEXT,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'COMPLETED' CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED', 'REVERSED')),
    note TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.shared_budget_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shared_budget_id UUID REFERENCES public.shared_budgets(id) ON DELETE CASCADE,
    requester_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    reviewer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    provider TEXT,
    bill_category TEXT,
    reference TEXT,
    note TEXT,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    responded_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='shared_budgets' AND column_name='funded_amount'
    ) THEN
        ALTER TABLE public.shared_budgets ADD COLUMN funded_amount NUMERIC DEFAULT 0;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='shared_budgets' AND column_name='auto_allocate_enabled'
    ) THEN
        ALTER TABLE public.shared_budgets ADD COLUMN auto_allocate_enabled BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='shared_budgets' AND column_name='auto_allocate_mode'
    ) THEN
        ALTER TABLE public.shared_budgets ADD COLUMN auto_allocate_mode TEXT DEFAULT 'MANUAL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='shared_budgets' AND column_name='auto_allocate_amount'
    ) THEN
        ALTER TABLE public.shared_budgets ADD COLUMN auto_allocate_amount NUMERIC DEFAULT 0;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='shared_budgets' AND column_name='auto_allocate_threshold'
    ) THEN
        ALTER TABLE public.shared_budgets ADD COLUMN auto_allocate_threshold NUMERIC DEFAULT 0;
    END IF;
    UPDATE public.shared_budgets
       SET funded_amount = COALESCE(funded_amount, 0),
           auto_allocate_enabled = COALESCE(auto_allocate_enabled, FALSE),
           auto_allocate_mode = COALESCE(NULLIF(auto_allocate_mode, ''), 'MANUAL'),
           auto_allocate_amount = COALESCE(auto_allocate_amount, 0),
           auto_allocate_threshold = COALESCE(auto_allocate_threshold, 0)
     WHERE funded_amount IS NULL
        OR auto_allocate_enabled IS NULL
        OR auto_allocate_mode IS NULL
        OR auto_allocate_amount IS NULL
        OR auto_allocate_threshold IS NULL;

    DELETE FROM public.shared_pot_members spm
    WHERE (spm.pot_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.shared_pots sp WHERE sp.id = spm.pot_id))
       OR (spm.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = spm.user_id));

    DELETE FROM public.shared_pot_invitations spi
    WHERE (spi.pot_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.shared_pots sp WHERE sp.id = spi.pot_id))
       OR (spi.inviter_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = spi.inviter_user_id))
       OR (spi.invitee_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = spi.invitee_user_id));

    DELETE FROM public.shared_budget_members sbm
    WHERE (sbm.budget_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.shared_budgets sb WHERE sb.id = sbm.budget_id))
       OR (sbm.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sbm.user_id));

    DELETE FROM public.shared_budget_invitations sbi
    WHERE (sbi.budget_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.shared_budgets sb WHERE sb.id = sbi.budget_id))
       OR (sbi.inviter_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sbi.inviter_user_id))
       OR (sbi.invitee_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sbi.invitee_user_id));

    UPDATE public.shared_budget_transactions sbt
    SET member_user_id = NULL
    WHERE member_user_id IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sbt.member_user_id);

    DELETE FROM public.shared_budget_approvals sba
    WHERE (sba.shared_budget_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.shared_budgets sb WHERE sb.id = sba.shared_budget_id))
       OR (sba.requester_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sba.requester_user_id));

    UPDATE public.shared_budget_approvals sba
    SET reviewer_user_id = NULL
    WHERE reviewer_user_id IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM public.users u WHERE u.id = sba.reviewer_user_id);

    ALTER TABLE public.shared_pot_members
        DROP CONSTRAINT IF EXISTS shared_pot_members_user_id_fkey,
        ADD CONSTRAINT shared_pot_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_pot_invitations
        DROP CONSTRAINT IF EXISTS shared_pot_invitations_pot_id_fkey,
        ADD CONSTRAINT shared_pot_invitations_pot_id_fkey FOREIGN KEY (pot_id) REFERENCES public.shared_pots(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_pot_invitations
        DROP CONSTRAINT IF EXISTS shared_pot_invitations_inviter_user_id_fkey,
        ADD CONSTRAINT shared_pot_invitations_inviter_user_id_fkey FOREIGN KEY (inviter_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_pot_invitations
        DROP CONSTRAINT IF EXISTS shared_pot_invitations_invitee_user_id_fkey,
        ADD CONSTRAINT shared_pot_invitations_invitee_user_id_fkey FOREIGN KEY (invitee_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

    ALTER TABLE public.shared_budget_members
        DROP CONSTRAINT IF EXISTS shared_budget_members_user_id_fkey,
        ADD CONSTRAINT shared_budget_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_budget_invitations
        DROP CONSTRAINT IF EXISTS shared_budget_invitations_budget_id_fkey,
        ADD CONSTRAINT shared_budget_invitations_budget_id_fkey FOREIGN KEY (budget_id) REFERENCES public.shared_budgets(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_budget_invitations
        DROP CONSTRAINT IF EXISTS shared_budget_invitations_inviter_user_id_fkey,
        ADD CONSTRAINT shared_budget_invitations_inviter_user_id_fkey FOREIGN KEY (inviter_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_budget_invitations
        DROP CONSTRAINT IF EXISTS shared_budget_invitations_invitee_user_id_fkey,
        ADD CONSTRAINT shared_budget_invitations_invitee_user_id_fkey FOREIGN KEY (invitee_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_budget_transactions
        DROP CONSTRAINT IF EXISTS shared_budget_transactions_member_user_id_fkey,
        ADD CONSTRAINT shared_budget_transactions_member_user_id_fkey FOREIGN KEY (member_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
    ALTER TABLE public.shared_budget_approvals
        DROP CONSTRAINT IF EXISTS shared_budget_approvals_requester_user_id_fkey,
        ADD CONSTRAINT shared_budget_approvals_requester_user_id_fkey FOREIGN KEY (requester_user_id) REFERENCES public.users(id) ON DELETE CASCADE;
    ALTER TABLE public.shared_budget_approvals
        DROP CONSTRAINT IF EXISTS shared_budget_approvals_reviewer_user_id_fkey,
        ADD CONSTRAINT shared_budget_approvals_reviewer_user_id_fkey FOREIGN KEY (reviewer_user_id) REFERENCES public.users(id) ON DELETE SET NULL;
END $$;

CREATE TABLE IF NOT EXISTS public.bill_reserves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    bill_type TEXT NOT NULL,
    source_wallet_id UUID,
    currency TEXT DEFAULT 'TZS',
    due_pattern TEXT DEFAULT 'MONTHLY',
    due_day INTEGER,
    reserve_mode TEXT DEFAULT 'FIXED' CHECK (reserve_mode IN ('FIXED', 'PERCENT')),
    reserve_amount NUMERIC DEFAULT 0,
    locked_balance NUMERIC DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'ARCHIVED')),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.wealth_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
    currency TEXT DEFAULT 'TZS',
    operating_balance NUMERIC DEFAULT 0,
    planned_balance NUMERIC DEFAULT 0,
    protected_balance NUMERIC DEFAULT 0,
    growing_balance NUMERIC DEFAULT 0,
    net_position NUMERIC DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, snapshot_date, currency)
);

CREATE TABLE IF NOT EXISTS public.wealth_insights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    insight_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO' CHECK (severity IN ('INFO', 'SUCCESS', 'WARNING', 'CRITICAL')),
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISMISSED', 'RESOLVED')),
    action_label TEXT,
    action_route TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='wealth_impact_type'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN wealth_impact_type TEXT DEFAULT 'OPERATING';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='protection_state'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN protection_state TEXT DEFAULT 'OPEN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='allocation_source'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN allocation_source TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='goals' AND column_name='shared_pot_id'
    ) THEN
        ALTER TABLE public.goals ADD COLUMN shared_pot_id UUID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='bill_reserves' AND column_name='status'
    ) THEN
        ALTER TABLE public.bill_reserves ADD COLUMN status TEXT DEFAULT 'ACTIVE';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='shared_pot_members' AND column_name='contributed_amount'
    ) THEN
        ALTER TABLE public.shared_pot_members ADD COLUMN contributed_amount NUMERIC DEFAULT 0;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='shared_pot_members' AND column_name='status'
    ) THEN
        ALTER TABLE public.shared_pot_members ADD COLUMN status TEXT DEFAULT 'ACTIVE';
    END IF;
    ALTER TABLE public.shared_pot_members
        DROP CONSTRAINT IF EXISTS shared_pot_members_status_check,
        ADD CONSTRAINT shared_pot_members_status_check CHECK (status IN ('ACTIVE', 'PAUSED', 'REMOVED'));
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='shared_pot_invitations' AND column_name='message'
    ) THEN
        ALTER TABLE public.shared_pot_invitations ADD COLUMN message TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='financial_ledger' AND column_name='shared_budget_id'
    ) THEN
        ALTER TABLE public.financial_ledger ADD COLUMN shared_budget_id UUID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='transactions' AND column_name='shared_budget_id'
    ) THEN
        ALTER TABLE public.transactions ADD COLUMN shared_budget_id UUID;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_wealth_buckets_user_type
    ON public.wealth_buckets (user_id, bucket_type);
CREATE INDEX IF NOT EXISTS idx_allocation_rules_user_active
    ON public.allocation_rules (user_id, is_active, trigger_type);
CREATE INDEX IF NOT EXISTS idx_bill_reserves_user_active
    ON public.bill_reserves (user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_shared_pots_owner
    ON public.shared_pots (owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_shared_pot_invites_pot
    ON public.shared_pot_invitations (pot_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_invites_invitee
    ON public.shared_pot_invitations (invitee_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_members_pot
    ON public.shared_pot_members (pot_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_members_user
    ON public.shared_pot_members (user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budgets_owner
    ON public.shared_budgets (owner_user_id, status);
CREATE INDEX IF NOT EXISTS idx_shared_budget_members_budget
    ON public.shared_budget_members (budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_members_user
    ON public.shared_budget_members (user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_invites_budget
    ON public.shared_budget_invitations (budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_invites_invitee
    ON public.shared_budget_invitations (invitee_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_transactions_budget
    ON public.shared_budget_transactions (shared_budget_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_transactions_member
    ON public.shared_budget_transactions (member_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_approvals_budget
    ON public.shared_budget_approvals (shared_budget_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wealth_snapshots_user_date
    ON public.wealth_snapshots (user_id, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_wealth_insights_user_status
    ON public.wealth_insights (user_id, status, severity);

-- ENTERPRISE UPGRADE: Organizations & B2B Multi-Tenancy
CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    creator_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    primary_admin_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    owner_type TEXT NOT NULL DEFAULT 'ORGANIZATION' CHECK (owner_type IN ('ORGANIZATION', 'GROUP', 'COMPANY')),
    owner_label TEXT,
    registration_number TEXT,
    tax_id TEXT,
    country TEXT,
    base_currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.organization_role_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    role_key TEXT NOT NULL,
    role_name TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, role_key)
);

CREATE TABLE IF NOT EXISTS public.organization_role_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('ADD_ADMIN', 'REMOVE_ADMIN', 'TRANSFER_PRIMARY_ADMIN')),
    from_role TEXT,
    to_role TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELLED')),
    required_approvals INTEGER NOT NULL DEFAULT 3 CHECK (required_approvals >= 3),
    approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

-- TRUSTBRIDGE: Escrow Agreements
CREATE TABLE IF NOT EXISTS public.escrow_agreements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES public.transactions(id) ON DELETE CASCADE,
    reference_id TEXT,
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    receiver_id UUID NOT NULL REFERENCES auth.users(id),
    source_vault_id UUID REFERENCES public.platform_vaults(id),
    escrow_vault_id UUID REFERENCES public.platform_vaults(id),
    receiver_vault_id UUID REFERENCES public.platform_vaults(id),
    merchant_id UUID,
    service_code TEXT,
    amount NUMERIC NOT NULL,
    currency TEXT NOT NULL,
    conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT DEFAULT 'HELD' CHECK (status IN ('HELD', 'RELEASE_PENDING', 'RETURN_PENDING', 'RELEASED', 'DISPUTED', 'REFUNDED')),
    dispute_metadata JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMP WITH TIME ZONE,
    release_requested_at TIMESTAMP WITH TIME ZONE,
    release_requested_by UUID REFERENCES auth.users(id),
    receiver_accepted_at TIMESTAMP WITH TIME ZONE,
    receiver_accepted_by UUID REFERENCES auth.users(id),
    released_at TIMESTAMP WITH TIME ZONE,
    refunded_at TIMESTAMP WITH TIME ZONE,
    disputed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- TREASURY: Multi-Sig Policies & Approvers
CREATE TABLE IF NOT EXISTS public.treasury_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    min_approvals INTEGER DEFAULT 1,
    max_amount_per_tx NUMERIC,
    daily_limit NUMERIC,
    currency TEXT DEFAULT 'USD',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.treasury_approvers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'APPROVER',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='organization_id') THEN
        ALTER TABLE public.users ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.users ADD COLUMN org_role TEXT;
    END IF;
END $$;

ALTER TABLE public.organizations
    ADD COLUMN IF NOT EXISTS creator_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS primary_admin_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS owner_type TEXT NOT NULL DEFAULT 'ORGANIZATION',
    ADD COLUMN IF NOT EXISTS owner_label TEXT;

DO $$
BEGIN
    ALTER TABLE public.organizations
        DROP CONSTRAINT IF EXISTS organizations_owner_type_check,
        ADD CONSTRAINT organizations_owner_type_check
            CHECK (owner_type IN ('ORGANIZATION', 'GROUP', 'COMPANY'));
    ALTER TABLE public.organization_role_change_requests
        DROP CONSTRAINT IF EXISTS organization_role_change_requests_action_check,
        ADD CONSTRAINT organization_role_change_requests_action_check
            CHECK (action IN ('ADD_ADMIN', 'REMOVE_ADMIN', 'TRANSFER_PRIMARY_ADMIN'));
    ALTER TABLE public.organization_role_change_requests
        DROP CONSTRAINT IF EXISTS organization_role_change_requests_required_approvals_check,
        ADD CONSTRAINT organization_role_change_requests_required_approvals_check
            CHECK (required_approvals >= 3);
END $$;

CREATE INDEX IF NOT EXISTS idx_org_role_defs_org
    ON public.organization_role_definitions(organization_id, role_key);
CREATE INDEX IF NOT EXISTS idx_org_role_change_requests_org
    ON public.organization_role_change_requests(organization_id, status, created_at DESC);

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='organization_id') THEN
        ALTER TABLE public.goals ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.goals ADD COLUMN currency TEXT DEFAULT 'TZS';
        ALTER TABLE public.goals ADD COLUMN status TEXT DEFAULT 'ACTIVE';
        ALTER TABLE public.goals ADD COLUMN is_corporate BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='linked_income_percentage') THEN
        ALTER TABLE public.goals ADD COLUMN linked_income_percentage NUMERIC;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='goals' AND column_name='monthly_target') THEN
        ALTER TABLE public.goals ADD COLUMN monthly_target NUMERIC;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='goals' AND column_name='target_amount') THEN
        ALTER TABLE public.goals ADD COLUMN target_amount NUMERIC;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='goals' AND column_name='current_amount') THEN
        ALTER TABLE public.goals ADD COLUMN current_amount NUMERIC DEFAULT 0;
    END IF;
END $$;

UPDATE public.goals
   SET target_amount = COALESCE(target_amount, target),
       current_amount = COALESCE(current_amount, current, 0)
 WHERE target_amount IS NULL OR current_amount IS NULL;

CREATE OR REPLACE FUNCTION public.sync_goal_amount_columns()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.target_amount := COALESCE(NEW.target_amount, NEW.target);
        NEW.target := COALESCE(NEW.target, NEW.target_amount);
        NEW.current_amount := COALESCE(NEW.current_amount, NEW.current, 0);
        NEW.current := COALESCE(NEW.current, NEW.current_amount, 0);
        RETURN NEW;
    END IF;

    IF NEW.target_amount IS DISTINCT FROM OLD.target_amount AND NEW.target IS NOT DISTINCT FROM OLD.target THEN
        NEW.target := COALESCE(NEW.target_amount, NEW.target, 0);
    ELSIF NEW.target IS DISTINCT FROM OLD.target AND NEW.target_amount IS NOT DISTINCT FROM OLD.target_amount THEN
        NEW.target_amount := NEW.target;
    ELSE
        NEW.target_amount := COALESCE(NEW.target_amount, NEW.target);
        NEW.target := COALESCE(NEW.target, NEW.target_amount);
    END IF;

    IF NEW.current_amount IS DISTINCT FROM OLD.current_amount AND NEW.current IS NOT DISTINCT FROM OLD.current THEN
        NEW.current := COALESCE(NEW.current_amount, 0);
    ELSIF NEW.current IS DISTINCT FROM OLD.current AND NEW.current_amount IS NOT DISTINCT FROM OLD.current_amount THEN
        NEW.current_amount := COALESCE(NEW.current, 0);
    ELSE
        NEW.current_amount := COALESCE(NEW.current_amount, NEW.current, 0);
        NEW.current := COALESCE(NEW.current, NEW.current_amount, 0);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_goal_amount_columns ON public.goals;
CREATE TRIGGER trg_sync_goal_amount_columns
BEFORE INSERT OR UPDATE ON public.goals
FOR EACH ROW
EXECUTE FUNCTION public.sync_goal_amount_columns();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='organization_id') THEN
        ALTER TABLE public.categories ADD COLUMN organization_id UUID REFERENCES public.organizations(id);
        ALTER TABLE public.categories ADD COLUMN currency TEXT DEFAULT 'TZS';
        ALTER TABLE public.categories ADD COLUMN period TEXT DEFAULT 'MONTHLY';
        ALTER TABLE public.categories ADD COLUMN hard_limit BOOLEAN DEFAULT FALSE;
        ALTER TABLE public.categories ADD COLUMN is_corporate BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='budget_interval') THEN
        ALTER TABLE public.categories ADD COLUMN budget_interval TEXT DEFAULT 'MONTHLY';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='categories' AND column_name='budget_period') THEN
        ALTER TABLE public.categories ADD COLUMN budget_period TEXT DEFAULT 'MONTHLY';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='categories' AND column_name='spent_amount') THEN
        ALTER TABLE public.categories ADD COLUMN spent_amount NUMERIC DEFAULT 0;
    END IF;
END $$;

UPDATE public.categories
   SET spent_amount = COALESCE(spent_amount, 0)
 WHERE spent_amount IS NULL;

CREATE TABLE IF NOT EXISTS public.budget_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID REFERENCES public.categories(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    alert_type TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.background_jobs (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    payload JSONB,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS public.tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    text TEXT NOT NULL, 
    completed BOOLEAN DEFAULT FALSE, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    due_date TIMESTAMP WITH TIME ZONE,
    linked_goal_id UUID REFERENCES public.goals(id) ON DELETE SET NULL,
    bounty NUMERIC DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.aml_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    risk_score NUMERIC NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.user_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    subject TEXT NOT NULL, 
    body TEXT NOT NULL, 
    category TEXT NOT NULL, 
    is_read BOOLEAN DEFAULT FALSE, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

COMMENT ON COLUMN public.user_messages.created_at IS 'Canonical UTC audit timestamp. User-facing displays must use metadata.audit_time/clientTimeContext timezone context when present.';
COMMENT ON COLUMN public.user_messages.metadata IS 'Notification audit metadata, including canonical UTC, explicit user/request timezone or UTC offset, and display timestamp context.';

CREATE TABLE IF NOT EXISTS public.staff_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    sender_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    recipient_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    sender_name TEXT, 
    content TEXT NOT NULL, 
    type TEXT DEFAULT 'staff', 
    is_flagged BOOLEAN DEFAULT FALSE, 
    target_role TEXT, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.kms_keys (
    key_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    wrapped_jwk TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.kms_keys
        WHERE status = 'ACTIVE'
        GROUP BY type
        HAVING COUNT(*) > 1
    ) THEN
        RAISE NOTICE 'Skipping kms_keys_one_active_per_type index creation until duplicate ACTIVE KMS keys are cleaned up.';
    ELSE
        EXECUTE '
            CREATE UNIQUE INDEX IF NOT EXISTS kms_keys_one_active_per_type
            ON public.kms_keys(type)
            WHERE status = ''ACTIVE''
        ';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.audit_trail (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    prev_hash TEXT, 
    hash TEXT NOT NULL, 
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(), 
    event_type TEXT NOT NULL, 
    actor_id TEXT, 
    transaction_id TEXT, 
    action TEXT NOT NULL, 
    metadata JSONB, 
    signature TEXT
);

CREATE TABLE IF NOT EXISTS public.operator_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO', 'WARNING', 'HIGH', 'CRITICAL')),
    event_code TEXT NOT NULL,
    target_roles TEXT[] DEFAULT ARRAY['SUPER_ADMIN', 'ADMIN', 'RISK_OFFICER', 'AUDIT']::TEXT[],
    actor_id TEXT,
    transaction_id TEXT,
    resource_type TEXT,
    resource_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    actions JSONB DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'UNREAD' CHECK (status IN ('UNREAD', 'READ', 'RESOLVED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    read_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by TEXT,
    resolution_note TEXT
);

CREATE TABLE IF NOT EXISTS public.api_gateway_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id TEXT,
    actor_ref TEXT,
    route TEXT NOT NULL,
    method TEXT NOT NULL,
    route_group TEXT NOT NULL,
    operation_class TEXT NOT NULL,
    action TEXT NOT NULL,
    risk_score NUMERIC NOT NULL DEFAULT 0,
    ip_hash TEXT,
    device_hash TEXT,
    app_id TEXT,
    trace_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT api_gateway_security_events_action_check
        CHECK (action IN (
            'API_GATEWAY_ALLOWED',
            'API_GATEWAY_THROTTLED',
            'API_GATEWAY_ATTEMPT_LOCKED',
            'API_GATEWAY_QUARANTINED',
            'API_GATEWAY_AI_SCORE_APPLIED'
        ))
);

CREATE TABLE IF NOT EXISTS public.api_gateway_quarantines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id TEXT,
    actor_ref TEXT,
    route_group TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    released_at TIMESTAMP WITH TIME ZONE,
    released_by TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT api_gateway_quarantines_status_check
        CHECK (status IN ('active', 'released', 'expired'))
);

CREATE TABLE IF NOT EXISTS public.provider_anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE, 
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE, 
    wallet_id UUID, 
    risk_score NUMERIC NOT NULL, 
    detection_flags TEXT[] NOT NULL, 
    status TEXT DEFAULT 'OPEN', 
    resolution_notes TEXT, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.financial_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name VARCHAR(50) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (LOWER(type) IN ('mobile_money', 'bank', 'card', 'crypto')),
    supported_currencies TEXT[] DEFAULT ARRAY['TZS']::TEXT[],
    icon TEXT,
    color TEXT,
    connection_secret VARCHAR(255),
    client_id TEXT,
    client_secret TEXT,
    api_key TEXT,
    api_base_url TEXT,
    merchant_id TEXT,
    webhook_secret TEXT,
    token_cache TEXT,
    token_expiry BIGINT,
    provider_metadata JSONB DEFAULT '{}'::jsonb,
    mapping_config JSONB DEFAULT '{}'::jsonb,
    logic_type TEXT DEFAULT 'REGISTRY',
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.provider_config_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    mapping_config JSONB NOT NULL,
    provider_metadata JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'CANARY', 'ACTIVE', 'ARCHIVED', 'ROLLBACK')),
    canary_percentage NUMERIC NOT NULL DEFAULT 0 CHECK (canary_percentage >= 0 AND canary_percentage <= 100),
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    activated_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(provider_id, version)
);

CREATE INDEX IF NOT EXISTS idx_provider_config_versions_provider_status
    ON public.provider_config_versions(provider_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_financial_partners_provider_code
    ON public.financial_partners ((LOWER(provider_metadata->>'provider_code')));

CREATE INDEX IF NOT EXISTS idx_financial_partners_status_type
    ON public.financial_partners(status, type, logic_type);

CREATE INDEX IF NOT EXISTS idx_financial_partners_rail
    ON public.financial_partners ((provider_metadata->>'rail'));

CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_config_versions_one_active
    ON public.provider_config_versions(provider_id)
    WHERE status = 'ACTIVE';

CREATE TABLE IF NOT EXISTS public.payment_orders (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    amount NUMERIC(20, 6) NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'TZS',
    status TEXT NOT NULL DEFAULT 'INITIATED' CHECK (status IN ('INITIATED', 'SETTLEMENT_PENDING', 'SETTLED', 'FAILED', 'REFUNDED', 'CANCELLED')),
    authorization_id TEXT,
    settlement_id UUID,
    refunded_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.provider_performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    metric_date DATE NOT NULL DEFAULT CURRENT_DATE,
    operation_code TEXT NOT NULL DEFAULT 'ALL',
    total_requests INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms NUMERIC NOT NULL DEFAULT 0,
    p95_latency_ms NUMERIC NOT NULL DEFAULT 0,
    p99_latency_ms NUMERIC NOT NULL DEFAULT 0,
    error_rate NUMERIC NOT NULL DEFAULT 0,
    sla_violations INTEGER NOT NULL DEFAULT 0,
    cost_per_transaction NUMERIC NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider_id, metric_date, operation_code)
);

CREATE INDEX IF NOT EXISTS idx_provider_performance_provider_date
    ON public.provider_performance_metrics(provider_id, metric_date DESC);

CREATE TABLE IF NOT EXISTS public.institutional_payment_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role TEXT NOT NULL,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    bank_name TEXT NOT NULL,
    account_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    country_code TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    is_primary BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.external_fund_movements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    direction TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'initiated',
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,
    institutional_source_account_id UUID REFERENCES public.institutional_payment_accounts(id) ON DELETE SET NULL,
    institutional_target_account_id UUID REFERENCES public.institutional_payment_accounts(id) ON DELETE SET NULL,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    source_wallet_id UUID,
    target_wallet_id UUID,
    gross_amount NUMERIC NOT NULL DEFAULT 0,
    net_amount NUMERIC NOT NULL DEFAULT 0,
    fee_amount NUMERIC NOT NULL DEFAULT 0,
    tax_amount NUMERIC NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'TZS',
    description TEXT,
    external_reference TEXT,
    source_external_ref TEXT,
    target_external_ref TEXT,
    -- Added as a deferred foreign key after settlement_lifecycle is created.
    settlement_lifecycle_id UUID,
    provider_event_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.provider_routing_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rail TEXT NOT NULL,
    country_code TEXT,
    currency TEXT,
    operation_code TEXT NOT NULL,
    provider_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 100,
    conditions JSONB DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_scope
    ON public.provider_routing_rules(
        rail,
        operation_code,
        COALESCE(country_code, ''),
        COALESCE(currency, ''),
        provider_id,
        COALESCE(status, 'ACTIVE')
    );

CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_provider_status
    ON public.provider_routing_rules(provider_id, status, priority);

CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_country_currency
    ON public.provider_routing_rules(country_code, currency, status, priority);

CREATE TABLE IF NOT EXISTS public.payment_rail_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    switch_partner_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    capability_code TEXT NOT NULL,
    display_name TEXT NOT NULL,
    rail TEXT NOT NULL,
    country_code TEXT NOT NULL,
    currency TEXT NOT NULL,
    operation_codes TEXT[] NOT NULL DEFAULT ARRAY['COLLECTION_REQUEST','DISBURSEMENT_REQUEST']::TEXT[],
    status TEXT NOT NULL DEFAULT 'INACTIVE',
    priority INTEGER NOT NULL DEFAULT 100,
    min_amount NUMERIC,
    max_amount NUMERIC,
    fee_profile_code TEXT,
    pay_gateway_provider_code TEXT,
    pay_gateway_capability_code TEXT,
    icon TEXT,
    color TEXT,
    requires JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT payment_rail_capabilities_unique_code_per_partner UNIQUE (switch_partner_id, capability_code),
    CONSTRAINT payment_rail_capabilities_rail_check CHECK (rail IN ('MOBILE_MONEY','BANK','CARD_GATEWAY','CRYPTO','WALLET')),
    CONSTRAINT payment_rail_capabilities_status_check CHECK (status IN ('ACTIVE','INACTIVE','MAINTENANCE'))
);

CREATE INDEX IF NOT EXISTS idx_payment_rail_capabilities_lookup
    ON public.payment_rail_capabilities(country_code, currency, rail, status, priority);

CREATE INDEX IF NOT EXISTS idx_payment_rail_capabilities_operations
    ON public.payment_rail_capabilities USING GIN (operation_codes);

CREATE INDEX IF NOT EXISTS idx_payment_rail_capabilities_partner
    ON public.payment_rail_capabilities(switch_partner_id, status, priority);

CREATE TABLE IF NOT EXISTS public.platform_fee_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    flow_code TEXT NOT NULL,
    transaction_model TEXT,
    category_code TEXT,
    category_id TEXT,
    transaction_type TEXT,
    operation_type TEXT,
    direction TEXT,
    rail TEXT,
    channel TEXT,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    currency TEXT,
    country_code TEXT,
    percentage_rate NUMERIC NOT NULL DEFAULT 0,
    fixed_amount NUMERIC NOT NULL DEFAULT 0,
    minimum_fee NUMERIC NOT NULL DEFAULT 0,
    maximum_fee NUMERIC,
    tax_rate NUMERIC NOT NULL DEFAULT 0,
    gov_fee_rate NUMERIC NOT NULL DEFAULT 0,
    stamp_duty_fixed NUMERIC NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.inbound_sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    normalized_message TEXT,
    message_type TEXT,
    request_id TEXT,
    carrier_ref TEXT,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    parse_status TEXT,
    signature_status TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_inbound_sms_gateway_carrier_ref
    ON public.inbound_sms_messages(gateway_id, carrier_ref)
    WHERE carrier_ref IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_inbound_sms_gateway_request
    ON public.inbound_sms_messages(gateway_id, request_id)
    WHERE request_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.offline_transaction_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT NOT NULL UNIQUE,
    tenant_id UUID,
    phone_number TEXT NOT NULL,
    user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    device_id TEXT,
    action TEXT NOT NULL,
    amount NUMERIC(20, 2),
    currency TEXT,
    source_wallet_id TEXT,
    budget_id TEXT,
    recipient_ref TEXT,
    status TEXT NOT NULL,
    challenge_code TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    failure_reason TEXT,
    correlation_id TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.outbound_sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT,
    phone_number TEXT NOT NULL,
    message_body TEXT NOT NULL,
    message_type TEXT,
    send_status TEXT,
    gateway_ref TEXT,
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
DECLARE
    partner_constraint RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='supported_currencies') THEN
        ALTER TABLE public.financial_partners ADD COLUMN supported_currencies TEXT[] DEFAULT ARRAY['TZS']::TEXT[];
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='client_id') THEN
        ALTER TABLE public.financial_partners ADD COLUMN client_id TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='client_secret') THEN
        ALTER TABLE public.financial_partners ADD COLUMN client_secret TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='api_key') THEN
        ALTER TABLE public.financial_partners ADD COLUMN api_key TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='api_base_url') THEN
        ALTER TABLE public.financial_partners ADD COLUMN api_base_url TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='merchant_id') THEN
        ALTER TABLE public.financial_partners ADD COLUMN merchant_id TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='webhook_secret') THEN
        ALTER TABLE public.financial_partners ADD COLUMN webhook_secret TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='token_cache') THEN
        ALTER TABLE public.financial_partners ADD COLUMN token_cache TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='token_expiry') THEN
        ALTER TABLE public.financial_partners ADD COLUMN token_expiry BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='logic_type') THEN
        ALTER TABLE public.financial_partners ADD COLUMN logic_type TEXT DEFAULT 'REGISTRY';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='created_by') THEN
        ALTER TABLE public.financial_partners ADD COLUMN created_by UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='updated_by') THEN
        ALTER TABLE public.financial_partners ADD COLUMN updated_by UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='financial_partners' AND column_name='updated_at') THEN
        ALTER TABLE public.financial_partners ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
    END IF;

    BEGIN
        ALTER TABLE public.financial_partners ALTER COLUMN connection_secret DROP NOT NULL;
    EXCEPTION
        WHEN others THEN NULL;
    END;

    UPDATE public.financial_partners
    SET type = LOWER(type)
    WHERE type IS NOT NULL
      AND type <> LOWER(type);

    FOR partner_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) LIKE '%type%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.financial_partners DROP CONSTRAINT %I',
            partner_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.conname = 'financial_partners_type_check_v2'
    ) THEN
        ALTER TABLE public.financial_partners
            ADD CONSTRAINT financial_partners_type_check_v2
            CHECK (LOWER(type) IN ('mobile_money', 'bank', 'card', 'crypto'));
    END IF;

    ALTER TABLE public.platform_fee_configs
        ADD COLUMN IF NOT EXISTS transaction_model TEXT,
        ADD COLUMN IF NOT EXISTS category_code TEXT,
        ADD COLUMN IF NOT EXISTS category_id TEXT;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'financial_partners'
          AND c.conname = 'financial_partners_logic_type_check'
    ) THEN
        ALTER TABLE public.financial_partners
            ADD CONSTRAINT financial_partners_logic_type_check
            CHECK (logic_type IN ('REGISTRY', 'GENERIC_REST', 'SPECIALIZED'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'institutional_payment_accounts'
          AND c.conname = 'institutional_payment_accounts_role_check'
    ) THEN
        ALTER TABLE public.institutional_payment_accounts
            ADD CONSTRAINT institutional_payment_accounts_role_check
            CHECK (role IN ('MAIN_COLLECTION', 'FEE_COLLECTION', 'TAX_COLLECTION', 'TRANSFER_SAVINGS'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'institutional_payment_accounts'
          AND c.conname = 'institutional_payment_accounts_status_check'
    ) THEN
        ALTER TABLE public.institutional_payment_accounts
            ADD CONSTRAINT institutional_payment_accounts_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'external_fund_movements'
          AND c.conname = 'external_fund_movements_direction_check'
    ) THEN
        ALTER TABLE public.external_fund_movements
            ADD CONSTRAINT external_fund_movements_direction_check
            CHECK (direction IN ('INTERNAL_TO_EXTERNAL', 'EXTERNAL_TO_INTERNAL', 'EXTERNAL_TO_EXTERNAL'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'external_fund_movements'
          AND c.conname = 'external_fund_movements_status_check'
    ) THEN
        ALTER TABLE public.external_fund_movements
            ADD CONSTRAINT external_fund_movements_status_check
            CHECK (status IN ('previewed', 'initiated', 'processing', 'completed', 'failed', 'recorded', 'reversed'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'provider_routing_rules'
          AND c.conname = 'provider_routing_rules_rail_check'
    ) THEN
        ALTER TABLE public.provider_routing_rules
            ADD CONSTRAINT provider_routing_rules_rail_check
            CHECK (rail IN ('MOBILE_MONEY', 'BANK', 'CARD_GATEWAY', 'CRYPTO', 'WALLET'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'provider_routing_rules'
          AND c.conname = 'provider_routing_rules_status_check'
    ) THEN
        ALTER TABLE public.provider_routing_rules
            ADD CONSTRAINT provider_routing_rules_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'platform_fee_configs'
          AND c.conname = 'platform_fee_configs_status_check'
    ) THEN
        ALTER TABLE public.platform_fee_configs
            ADD CONSTRAINT platform_fee_configs_status_check
            CHECK (status IN ('ACTIVE', 'INACTIVE'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'offline_transaction_sessions'
          AND c.conname = 'offline_transaction_sessions_status_check'
    ) THEN
        ALTER TABLE public.offline_transaction_sessions
            ADD CONSTRAINT offline_transaction_sessions_status_check
            CHECK (status IN ('RECEIVED', 'PARSED', 'VALIDATED', 'PENDING_CONFIRMATION', 'FORWARDED_TO_ORBI', 'CHALLENGE_SENT', 'CONFIRMED', 'SUCCESS', 'FAILED', 'EXPIRED', 'REJECTED'));
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.enforce_financial_partner_activation_readiness()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_status TEXT := UPPER(COALESCE(NEW.status, ''));
    v_provider_code TEXT := BTRIM(COALESCE(NEW.provider_metadata->>'provider_code', ''));
    v_rail TEXT := BTRIM(COALESCE(NEW.provider_metadata->>'rail', ''));
    v_operations_count INTEGER := COALESCE(jsonb_array_length(COALESCE(NEW.provider_metadata->'operations', '[]'::jsonb)), 0);
    v_mapping_operations_count INTEGER := COALESCE((
        SELECT COUNT(*)
        FROM jsonb_each(COALESCE(NEW.mapping_config->'operations', '{}'::jsonb))
    ), 0);
    v_supports_webhooks BOOLEAN := COALESCE((NEW.provider_metadata->>'supports_webhooks')::BOOLEAN, FALSE);
    v_has_callback BOOLEAN := COALESCE(NEW.mapping_config ? 'callback', FALSE);
    v_callback_reference TEXT := BTRIM(COALESCE(NEW.mapping_config->'callback'->>'reference_field', ''));
    v_callback_status TEXT := BTRIM(COALESCE(NEW.mapping_config->'callback'->>'status_field', ''));
BEGIN
    IF v_status <> 'ACTIVE' THEN
        RETURN NEW;
    END IF;

    IF COALESCE(NEW.mapping_config, '{}'::jsonb) = '{}'::jsonb THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_MAPPING_CONFIG_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF BTRIM(COALESCE(NEW.mapping_config->>'service_root', '')) = ''
       AND COALESCE((
            SELECT COUNT(*)
            FROM jsonb_each(COALESCE(NEW.mapping_config->'service_roots', '{}'::jsonb))
        ), 0) = 0 THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_SERVICE_ROOT_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_mapping_operations_count = 0
       AND NOT (COALESCE(NEW.mapping_config ? 'stk_push', FALSE)
             OR COALESCE(NEW.mapping_config ? 'disbursement', FALSE)
             OR COALESCE(NEW.mapping_config ? 'balance', FALSE)
             OR COALESCE(NEW.mapping_config ? 'check_status', FALSE)) THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_OPERATION_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_provider_code = '' THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_PROVIDER_CODE_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_rail = '' THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_RAIL_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_operations_count = 0 THEN
        RAISE EXCEPTION 'PROVIDER_ACTIVATION_OPERATIONS_METADATA_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
    END IF;

    IF v_supports_webhooks OR v_has_callback OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(NEW.provider_metadata->'operations', '[]'::jsonb)) AS operation_name
        WHERE UPPER(operation_name) = 'WEBHOOK_VERIFY'
    ) THEN
        IF NOT v_has_callback THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
        IF v_callback_reference = '' THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_REFERENCE_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
        IF v_callback_status = '' THEN
            RAISE EXCEPTION 'PROVIDER_ACTIVATION_CALLBACK_STATUS_REQUIRED:%', COALESCE(NEW.name, 'UNKNOWN_PROVIDER');
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_financial_partner_activation_readiness ON public.financial_partners;
CREATE TRIGGER trg_financial_partner_activation_readiness
BEFORE INSERT OR UPDATE ON public.financial_partners
FOR EACH ROW
EXECUTE FUNCTION public.enforce_financial_partner_activation_readiness();

CREATE TABLE IF NOT EXISTS public.digital_merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    name TEXT NOT NULL,
    category TEXT,
    status TEXT DEFAULT 'ACTIVE',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Multi-Tenant Merchant Architecture
CREATE TABLE IF NOT EXISTS public.merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_name TEXT NOT NULL,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending', -- pending, active, suspended, closed
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.merchant_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    base_wallet_id UUID,
    name TEXT NOT NULL,
    wallet_type TEXT DEFAULT 'operating',
    is_primary BOOLEAN DEFAULT FALSE,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.merchant_settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    bank_name TEXT NOT NULL,
    bank_account TEXT NOT NULL,
    settlement_schedule TEXT DEFAULT 'daily',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);



-- Settlement Lifecycle
CREATE TABLE IF NOT EXISTS public.provider_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id UUID NOT NULL REFERENCES public.financial_partners(id) ON DELETE CASCADE,
    provider_event_id TEXT,
    dedupe_key TEXT NOT NULL,
    replay_key TEXT NOT NULL,
    reference TEXT,
    normalized_status TEXT,
    raw_status TEXT,
    event_timestamp TIMESTAMP WITH TIME ZONE,
    timestamp_source TEXT,
    signature_status TEXT NOT NULL DEFAULT 'pending',
    freshness_status TEXT NOT NULL DEFAULT 'missing',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    application_status TEXT NOT NULL DEFAULT 'received',
    payload_sha256 TEXT NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    raw_headers JSONB DEFAULT '{}'::jsonb,
    source_ip TEXT,
    failure_code TEXT,
    failure_message TEXT,
    applied_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT provider_webhook_events_status_check CHECK (
        application_status IN ('received', 'processing', 'applied', 'rejected', 'failed')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_webhook_events_partner_dedupe
    ON public.provider_webhook_events(partner_id, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_provider_event
    ON public.provider_webhook_events(provider_event_id);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_reference
    ON public.provider_webhook_events(reference);

CREATE TABLE IF NOT EXISTS public.settlement_lifecycle (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    external_movement_id UUID REFERENCES public.external_fund_movements(id) ON DELETE SET NULL,
    merchant_settlement_id UUID REFERENCES public.merchant_settlements(id) ON DELETE SET NULL,
    provider_id UUID REFERENCES public.financial_partners(id) ON DELETE SET NULL,

    lifecycle_key TEXT UNIQUE,
    settlement_batch_id TEXT,
    provider_reference TEXT,
    provider_status TEXT,

    rail TEXT,
    direction TEXT,
    operation_type TEXT,
    currency TEXT DEFAULT 'TZS',

    gross_amount NUMERIC NOT NULL DEFAULT 0,
    fee_amount NUMERIC NOT NULL DEFAULT 0,
    tax_amount NUMERIC NOT NULL DEFAULT 0,
    net_amount NUMERIC NOT NULL DEFAULT 0,

    stage TEXT NOT NULL DEFAULT 'INITIATED',
    status TEXT NOT NULL DEFAULT 'ACTIVE',

    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,

    initiated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    queued_at TIMESTAMP WITH TIME ZONE,
    processing_at TIMESTAMP WITH TIME ZONE,
    sent_to_provider_at TIMESTAMP WITH TIME ZONE,
    provider_confirmed_at TIMESTAMP WITH TIME ZONE,
    settled_at TIMESTAMP WITH TIME ZONE,
    reconciled_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    reversed_at TIMESTAMP WITH TIME ZONE,

    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compatibility columns for the settlement scheduler/manager during the
-- V93 lifecycle schema transition. Keep these populated from authoritative
-- settlement_lifecycle fields and related movement records until all runtime
-- services are fully migrated to stage/status/attempt_count/net_amount.
ALTER TABLE public.settlement_lifecycle
    ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS amount NUMERIC NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS current_phase TEXT NOT NULL DEFAULT 'EXTERNAL_PENDING',
    ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS phase_started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS phase_completed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS auto_settle_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS auto_settle_executed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS external_settlement_id TEXT,
    ADD COLUMN IF NOT EXISTS reconciliation_id TEXT,
    ADD COLUMN IF NOT EXISTS reconciliation_result JSONB,
    ADD COLUMN IF NOT EXISTS financial_tx_id UUID,
    ADD COLUMN IF NOT EXISTS wallet_id UUID REFERENCES public.wallets(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS order_id TEXT;

UPDATE public.settlement_lifecycle sl
SET
    user_id = COALESCE(
        sl.user_id,
        (SELECT t.user_id FROM public.transactions t WHERE t.id = sl.transaction_id LIMIT 1),
        (SELECT efm.user_id FROM public.external_fund_movements efm WHERE efm.id = sl.external_movement_id LIMIT 1)
    ),
    amount = CASE
        WHEN sl.amount IS NULL OR sl.amount = 0 THEN COALESCE(NULLIF(sl.net_amount, 0), sl.gross_amount, 0)
        ELSE sl.amount
    END,
    retry_count = COALESCE(NULLIF(sl.retry_count, 0), sl.attempt_count, 0),
    phase_started_at = COALESCE(
        sl.phase_started_at,
        sl.processing_at,
        sl.queued_at,
        sl.initiated_at,
        sl.created_at,
        NOW()
    ),
    phase_completed_at = COALESCE(
        sl.phase_completed_at,
        sl.reconciled_at,
        sl.settled_at,
        sl.failed_at,
        sl.reversed_at
    ),
    auto_settle_at = COALESCE(sl.auto_settle_at, sl.provider_confirmed_at, sl.sent_to_provider_at),
    current_phase = COALESCE(NULLIF(sl.current_phase, ''), 'EXTERNAL_PENDING'),
    external_settlement_id = COALESCE(sl.external_settlement_id, sl.provider_reference, sl.settlement_batch_id)
WHERE sl.user_id IS NULL
   OR sl.amount = 0
   OR sl.retry_count = 0
   OR sl.phase_started_at IS NULL
   OR sl.phase_completed_at IS NULL
   OR sl.auto_settle_at IS NULL
   OR sl.external_settlement_id IS NULL;

CREATE TABLE IF NOT EXISTS public.guest_escrow_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_code TEXT NOT NULL,
    reference TEXT NOT NULL,
    payment_intent_id TEXT,
    shop_order_id TEXT,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    merchant_wallet_id UUID REFERENCES public.merchant_wallets(id) ON DELETE SET NULL,
    display_name TEXT,
    email_hash TEXT,
    phone_hash TEXT,
    email_hint TEXT,
    phone_hint TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unverified'
        CHECK (verification_status IN ('unverified', 'verified', 'linked', 'blocked')),
    linked_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    refund_policy TEXT NOT NULL DEFAULT 'original_payment_method_only'
        CHECK (refund_policy IN ('original_payment_method_only')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (service_code, reference)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'external_fund_movements_settlement_lifecycle_id_fkey'
          AND conrelid = 'public.external_fund_movements'::regclass
    ) THEN
        ALTER TABLE public.external_fund_movements
            ADD CONSTRAINT external_fund_movements_settlement_lifecycle_id_fkey
            FOREIGN KEY (settlement_lifecycle_id)
            REFERENCES public.settlement_lifecycle(id)
            ON DELETE SET NULL;
    END IF;
END
$$;

DO $$
DECLARE
    settlement_constraint RECORD;
BEGIN
    FOR settlement_constraint IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.contype = 'c'
          AND (
              pg_get_constraintdef(c.oid) LIKE '%stage%'
              OR pg_get_constraintdef(c.oid) LIKE '%status%'
          )
    LOOP
        EXECUTE format(
            'ALTER TABLE public.settlement_lifecycle DROP CONSTRAINT %I',
            settlement_constraint.conname
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.conname = 'settlement_lifecycle_stage_check_v1'
    ) THEN
        ALTER TABLE public.settlement_lifecycle
            ADD CONSTRAINT settlement_lifecycle_stage_check_v1
            CHECK (
                stage IN (
                    'INITIATED',
                    'QUEUED',
                    'PROCESSING',
                    'SENT_TO_PROVIDER',
                    'PROVIDER_CONFIRMED',
                    'SETTLED',
                    'RECONCILED',
                    'FAILED',
                    'REVERSED'
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'settlement_lifecycle'
          AND c.conname = 'settlement_lifecycle_status_check_v1'
    ) THEN
        ALTER TABLE public.settlement_lifecycle
            ADD CONSTRAINT settlement_lifecycle_status_check_v1
            CHECK (
                status IN (
                    'ACTIVE',
                    'COMPLETED',
                    'FAILED',
                    'CANCELLED',
                    'REVERSED'
                )
            );
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.set_settlement_lifecycle_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_settlement_lifecycle_updated_at ON public.settlement_lifecycle;
CREATE TRIGGER trg_settlement_lifecycle_updated_at
BEFORE UPDATE ON public.settlement_lifecycle
FOR EACH ROW
EXECUTE FUNCTION public.set_settlement_lifecycle_updated_at();

CREATE OR REPLACE FUNCTION public.claim_internal_transfer_settlement(
    p_tx_id UUID,
    p_worker_id TEXT,
    p_worker_claim_id TEXT DEFAULT NULL
)
RETURNS TABLE (
    transaction_id UUID,
    lifecycle_id UUID,
    append_key TEXT,
    append_phase TEXT,
    worker_claim_id TEXT,
    transaction_status TEXT,
    lifecycle_stage TEXT,
    lifecycle_status TEXT,
    append_already_applied BOOLEAN,
    already_completed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_lifecycle public.settlement_lifecycle%ROWTYPE;
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_claim_id TEXT := COALESCE(NULLIF(BTRIM(p_worker_claim_id), ''), gen_random_uuid()::TEXT);
    v_lifecycle_key TEXT := 'INTERNAL_TRANSFER:' || p_tx_id::TEXT || ':PAYSAFE_SETTLEMENT';
    v_append_key TEXT := 'settlement:' || p_tx_id::TEXT || ':paysafe_release:v2';
    v_append_phase TEXT := 'PAYSAFE_SETTLEMENT';
    v_existing_claim_id TEXT;
    v_append_applied BOOLEAN := FALSE;
BEGIN
    IF NULLIF(BTRIM(p_worker_id), '') IS NULL THEN
        RAISE EXCEPTION 'WORKER_ID_REQUIRED: claim_internal_transfer_settlement requires a worker identifier';
    END IF;

    SELECT * INTO v_tx
    FROM public.transactions
    WHERE id = p_tx_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % was not found for settlement claim', p_tx_id;
    END IF;

    INSERT INTO public.settlement_lifecycle (
        transaction_id,
        lifecycle_key,
        rail,
        direction,
        operation_type,
        currency,
        stage,
        status,
        initiated_at,
        metadata
    )
    VALUES (
        p_tx_id,
        v_lifecycle_key,
        'SOVEREIGN_LEDGER',
        'INTERNAL',
        'INTERNAL_TRANSFER',
        COALESCE(v_tx.currency, 'TZS'),
        'INITIATED',
        'ACTIVE',
        v_now,
        jsonb_build_object(
            'settlement_model', 'INTERNAL_PAYSAFE_VAULT',
            'append_key', v_append_key,
            'append_phase', v_append_phase
        )
    )
    ON CONFLICT (lifecycle_key) DO NOTHING;

    SELECT * INTO v_lifecycle
    FROM public.settlement_lifecycle
    WHERE lifecycle_key = v_lifecycle_key
    FOR UPDATE;

    SELECT EXISTS (
        SELECT 1
        FROM public.ledger_append_markers lam
        WHERE lam.append_key = v_append_key
           OR (lam.transaction_id = p_tx_id AND lam.append_phase = v_append_phase)
    ) INTO v_append_applied;

    IF LOWER(COALESCE(v_tx.status, '')) = 'completed'
       OR COALESCE(v_lifecycle.status, '') = 'COMPLETED'
       OR COALESCE(v_lifecycle.stage, '') = 'SETTLED' THEN
        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = COALESCE(settled_at, v_now),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', v_append_applied,
                'last_completion_check_at', v_now
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_lifecycle.id,
            v_append_key,
            v_append_phase,
            COALESCE(v_lifecycle.metadata->>'worker_claim_id', v_claim_id),
            v_tx.status,
            'SETTLED',
            'COMPLETED',
            v_append_applied,
            TRUE;
        RETURN;
    END IF;

    IF LOWER(COALESCE(v_tx.status, '')) <> 'processing' THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % is %, expected processing under settlement lock', p_tx_id, v_tx.status;
    END IF;

    v_existing_claim_id := NULLIF(v_lifecycle.metadata->>'worker_claim_id', '');
    IF COALESCE(v_lifecycle.stage, '') = 'PROCESSING'
       AND v_existing_claim_id IS NOT NULL
       AND v_existing_claim_id <> v_claim_id
       AND v_lifecycle.processing_at IS NOT NULL
       AND v_lifecycle.processing_at > (v_now - INTERVAL '5 minutes') THEN
        RAISE EXCEPTION 'CONCURRENCY_CONFLICT: Settlement % is already claimed by another worker', p_tx_id;
    END IF;

    UPDATE public.settlement_lifecycle
    SET
        transaction_id = p_tx_id,
        rail = 'SOVEREIGN_LEDGER',
        direction = 'INTERNAL',
        operation_type = 'INTERNAL_TRANSFER',
        currency = COALESCE(v_lifecycle.currency, v_tx.currency, 'TZS'),
        stage = 'PROCESSING',
        status = 'ACTIVE',
        processing_at = v_now,
        last_error = NULL,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'worker_id', p_worker_id,
            'worker_claim_id', v_claim_id,
            'worker_claimed_at', v_now,
            'append_key', v_append_key,
            'append_phase', v_append_phase,
            'append_applied', v_append_applied,
            'settlement_model', 'INTERNAL_PAYSAFE_VAULT',
            'preconditions_verified_at', v_now,
            'tx_status_verified_under_lock', v_tx.status
        )
    WHERE id = v_lifecycle.id;

    RETURN QUERY
    SELECT
        p_tx_id,
        v_lifecycle.id,
        v_append_key,
        v_append_phase,
        v_claim_id,
        v_tx.status,
        'PROCESSING',
        'ACTIVE',
        v_append_applied,
        FALSE;
END;
$$;

COMMENT ON FUNCTION public.claim_internal_transfer_settlement(UUID, TEXT, TEXT)
IS 'Claims an internal transfer settlement under a transaction row lock, records a durable worker claim/idempotency marker, verifies the transaction is still processing, and checks whether the settlement append marker was already applied. Enterprise repair/worker path only; not for client-facing flow.';

CREATE OR REPLACE FUNCTION public.complete_internal_transfer_settlement(
    p_tx_id UUID,
    p_worker_claim_id TEXT,
    p_result TEXT DEFAULT 'COMPLETED',
    p_result_note TEXT DEFAULT NULL,
    p_zero_sum_valid BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    transaction_id UUID,
    previous_status TEXT,
    final_status TEXT,
    lifecycle_stage TEXT,
    lifecycle_status TEXT,
    already_finalized BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_lifecycle public.settlement_lifecycle%ROWTYPE;
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_result TEXT := UPPER(COALESCE(NULLIF(BTRIM(p_result), ''), 'COMPLETED'));
    v_lifecycle_key TEXT := 'INTERNAL_TRANSFER:' || p_tx_id::TEXT || ':PAYSAFE_SETTLEMENT';
    v_append_key TEXT := 'settlement:' || p_tx_id::TEXT || ':paysafe_release:v2';
    v_append_phase TEXT := 'PAYSAFE_SETTLEMENT';
BEGIN
    IF NULLIF(BTRIM(p_worker_claim_id), '') IS NULL THEN
        RAISE EXCEPTION 'WORKER_CLAIM_REQUIRED: complete_internal_transfer_settlement requires the active worker claim id';
    END IF;

    SELECT * INTO v_tx
    FROM public.transactions
    WHERE id = p_tx_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % was not found for settlement completion', p_tx_id;
    END IF;

    SELECT * INTO v_lifecycle
    FROM public.settlement_lifecycle
    WHERE lifecycle_key = v_lifecycle_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Settlement lifecycle % was not found', v_lifecycle_key;
    END IF;

    IF LOWER(COALESCE(v_tx.status, '')) = 'completed'
       OR COALESCE(v_lifecycle.status, '') = 'COMPLETED'
       OR COALESCE(v_lifecycle.stage, '') = 'SETTLED' THEN
        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = COALESCE(settled_at, v_now),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', TRUE,
                'completed_at', v_now
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'completed',
            'SETTLED',
            'COMPLETED',
            TRUE;
        RETURN;
    END IF;

    IF COALESCE(v_lifecycle.metadata->>'worker_claim_id', '') <> p_worker_claim_id THEN
        RAISE EXCEPTION 'CONCURRENCY_CONFLICT: Settlement % completion attempted with stale worker claim', p_tx_id;
    END IF;

    IF COALESCE(v_lifecycle.stage, '') <> 'PROCESSING' THEN
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Settlement % is %, expected PROCESSING before completion', p_tx_id, v_lifecycle.stage;
    END IF;

    IF v_result = 'COMPLETED' AND NOT p_zero_sum_valid THEN
        v_result := 'HELD_FOR_REVIEW';
    END IF;

    IF v_result = 'COMPLETED' THEN
        IF LOWER(COALESCE(v_tx.status, '')) <> 'processing' THEN
            RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Transaction % is %, expected processing before settlement completion', p_tx_id, v_tx.status;
        END IF;

        UPDATE public.transactions
        SET
            status = 'completed',
            status_notes = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'Settlement finalized by processor.'),
            updated_at = v_now
        WHERE id = p_tx_id;

        UPDATE public.settlement_lifecycle
        SET
            stage = 'SETTLED',
            status = 'COMPLETED',
            settled_at = v_now,
            last_error = NULL,
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'append_applied', TRUE,
                'completed_at', v_now,
                'completion_result', 'COMPLETED'
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'completed',
            'SETTLED',
            'COMPLETED',
            FALSE;
        RETURN;
    ELSIF v_result = 'HELD_FOR_REVIEW' THEN
        IF LOWER(COALESCE(v_tx.status, '')) = 'processing' THEN
            UPDATE public.transactions
            SET
                status = 'held_for_review',
                status_notes = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'Settlement moved to held_for_review.'),
                updated_at = v_now
            WHERE id = p_tx_id;
        END IF;

        UPDATE public.settlement_lifecycle
        SET
            stage = 'FAILED',
            status = 'FAILED',
            failed_at = v_now,
            last_error = COALESCE(NULLIF(BTRIM(p_result_note), ''), 'HELD_FOR_REVIEW'),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'append_key', v_append_key,
                'append_phase', v_append_phase,
                'completion_result', 'HELD_FOR_REVIEW',
                'held_for_review_at', v_now,
                'zero_sum_valid', FALSE
            )
        WHERE id = v_lifecycle.id;

        RETURN QUERY
        SELECT
            p_tx_id,
            v_tx.status,
            'held_for_review',
            'FAILED',
            'FAILED',
            FALSE;
        RETURN;
    ELSE
        RAISE EXCEPTION 'INVALID_SETTLEMENT_STATE: Unsupported settlement completion result %', v_result;
    END IF;
END;
$$;

COMMENT ON FUNCTION public.complete_internal_transfer_settlement(UUID, TEXT, TEXT, TEXT, BOOLEAN)
IS 'Completes an internal transfer settlement under lock using the active worker claim id. It finalizes transaction status only after append/idempotency preconditions were established and records durable lifecycle metadata. Worker path only.';

CREATE TABLE IF NOT EXISTS public.merchant_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE UNIQUE,
    transaction_fee_percent NUMERIC DEFAULT 0.01,
    fixed_fee NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchants' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchants ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='base_wallet_id') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN base_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='wallet_type') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN wallet_type TEXT DEFAULT 'operating';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_wallets' AND column_name='is_primary') THEN
        ALTER TABLE public.merchant_wallets ADD COLUMN is_primary BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    commission_enabled BOOLEAN DEFAULT TRUE,
    service_pay_number TEXT UNIQUE,
    cash_withdraw_till TEXT UNIQUE,
    service_wallet_id UUID,
    commission_wallet_id UUID,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.agent_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES public.agents(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    base_wallet_id UUID,
    name TEXT NOT NULL,
    wallet_type TEXT DEFAULT 'operating',
    is_primary BOOLEAN DEFAULT FALSE,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='service_pay_number') THEN
        ALTER TABLE public.agents ADD COLUMN service_pay_number TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='cash_withdraw_till') THEN
        ALTER TABLE public.agents ADD COLUMN cash_withdraw_till TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='service_wallet_id') THEN
        ALTER TABLE public.agents ADD COLUMN service_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agents' AND column_name='commission_wallet_id') THEN
        ALTER TABLE public.agents ADD COLUMN commission_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='owner_user_id') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='base_wallet_id') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN base_wallet_id UUID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='wallet_type') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN wallet_type TEXT DEFAULT 'operating';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_wallets' AND column_name='is_primary') THEN
        ALTER TABLE public.agent_wallets ADD COLUMN is_primary BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_service_pay_number
    ON public.agents(service_pay_number)
    WHERE service_pay_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_cash_withdraw_till
    ON public.agents(cash_withdraw_till)
    WHERE cash_withdraw_till IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.merchant_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID UNIQUE REFERENCES public.transactions(id) ON DELETE CASCADE,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    merchant_wallet_id UUID REFERENCES public.merchant_wallets(id) ON DELETE SET NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    direction TEXT DEFAULT 'inbound',
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'pending',
    service_type TEXT DEFAULT 'merchant_payment',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_transactions' AND column_name='owner_user_id') THEN
        ALTER TABLE public.merchant_transactions ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='merchant_transactions' AND column_name='customer_user_id') THEN
        ALTER TABLE public.merchant_transactions ADD COLUMN customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.agent_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID UNIQUE REFERENCES public.transactions(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES public.agents(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    agent_wallet_id UUID REFERENCES public.agent_wallets(id) ON DELETE SET NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    direction TEXT DEFAULT 'inbound',
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'pending',
    service_type TEXT DEFAULT 'agent_cash',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_transactions' AND column_name='owner_user_id') THEN
        ALTER TABLE public.agent_transactions ADD COLUMN owner_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='agent_transactions' AND column_name='customer_user_id') THEN
        ALTER TABLE public.agent_transactions ADD COLUMN customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.service_actor_customer_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    actor_role TEXT NOT NULL,
    actor_registry_type TEXT,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    customer_customer_id TEXT,
    relationship_type TEXT DEFAULT 'sponsored_registration',
    status TEXT DEFAULT 'active',
    commission_enabled BOOLEAN DEFAULT TRUE,
    commission_started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    commission_expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.service_commissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    actor_role TEXT NOT NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    source_transaction_id UUID REFERENCES public.transactions(id) ON DELETE CASCADE,
    payout_transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    commission_type TEXT NOT NULL,
    amount NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    rate NUMERIC DEFAULT 0,
    fixed_amount NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'pending',
    effective_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    effective_until TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.merchant_settlement_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    gross_amount NUMERIC NOT NULL DEFAULT 0,
    fee_amount NUMERIC NOT NULL DEFAULT 0,
    tax_amount NUMERIC NOT NULL DEFAULT 0,
    net_amount NUMERIC NOT NULL DEFAULT 0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    settled_transaction_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'generated' CHECK (status IN ('generated', 'reviewed', 'exported', 'void')),
    generated_by TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.agent_float_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES public.agents(id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    currency TEXT NOT NULL DEFAULT 'TZS',
    min_float NUMERIC NOT NULL DEFAULT 0,
    max_float NUMERIC,
    daily_cash_in_limit NUMERIC,
    daily_cash_out_limit NUMERIC,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'locked')),
    reason TEXT NOT NULL DEFAULT 'Initial float governance policy',
    updated_by TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.service_commission_disputes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    commission_id UUID REFERENCES public.service_commissions(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'under_review', 'resolved', 'rejected')),
    reason TEXT NOT NULL,
    resolution_note TEXT,
    opened_by TEXT,
    resolved_by TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.organization_limit_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    currency TEXT NOT NULL DEFAULT 'TZS',
    max_amount_per_tx NUMERIC,
    daily_limit NUMERIC,
    monthly_limit NUMERIC,
    maker_checker_threshold NUMERIC,
    auto_freeze_threshold NUMERIC,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'locked')),
    reason TEXT NOT NULL DEFAULT 'Initial organization limit policy',
    updated_by TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.service_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    requested_role TEXT NOT NULL,
    requested_registry_type TEXT NOT NULL,
    current_user_role TEXT,
    current_user_registry_type TEXT,
    status TEXT DEFAULT 'pending',
    business_name TEXT,
    phone TEXT,
    submitted_via TEXT DEFAULT 'mobile_app',
    note TEXT,
    review_note TEXT,
    reviewed_by UUID REFERENCES public.staff(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    approved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_role'
    ) THEN
        ALTER TABLE public.service_access_requests
            RENAME COLUMN "current_role" TO current_user_role;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_registry_type'
    ) THEN
        ALTER TABLE public.service_access_requests
            RENAME COLUMN "current_registry_type" TO current_user_registry_type;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_user_role'
    ) THEN
        ALTER TABLE public.service_access_requests
            ADD COLUMN current_user_role TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'service_access_requests'
          AND column_name = 'current_user_registry_type'
    ) THEN
        ALTER TABLE public.service_access_requests
            ADD COLUMN current_user_registry_type TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_merchants_owner ON public.merchants(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_merchant ON public.merchant_wallets(merchant_id);
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_owner_user ON public.merchant_wallets(owner_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_actor_customer_unique
    ON public.service_actor_customer_links(actor_user_id, customer_user_id);
CREATE INDEX IF NOT EXISTS idx_agents_user ON public.agents(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_wallets_agent ON public.agent_wallets(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_wallets_owner_user ON public.agent_wallets(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_owner ON public.merchant_transactions(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_customer ON public.merchant_transactions(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_owner ON public.agent_transactions(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_customer ON public.agent_transactions(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_service_links_actor ON public.service_actor_customer_links(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_service_links_customer ON public.service_actor_customer_links(customer_user_id);
CREATE INDEX IF NOT EXISTS idx_service_commissions_actor ON public.service_commissions(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_service_commissions_source_tx ON public.service_commissions(source_transaction_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_merchant_settlement_reports_unique_period ON public.merchant_settlement_reports(merchant_id, period_start, period_end, currency);
CREATE INDEX IF NOT EXISTS idx_merchant_settlement_reports_merchant_period ON public.merchant_settlement_reports(merchant_id, period_end DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_float_controls_unique_currency ON public.agent_float_controls(agent_id, currency);
CREATE INDEX IF NOT EXISTS idx_agent_float_controls_status ON public.agent_float_controls(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_commission_disputes_commission ON public.service_commission_disputes(commission_id);
CREATE INDEX IF NOT EXISTS idx_service_commission_disputes_actor_status ON public.service_commission_disputes(actor_user_id, status, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_limit_configs_unique_currency ON public.organization_limit_configs(organization_id, currency);
CREATE INDEX IF NOT EXISTS idx_organization_limit_configs_status ON public.organization_limit_configs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_user ON public.service_access_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_status ON public.service_access_requests(status);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_role ON public.service_access_requests(requested_role);

CREATE TABLE IF NOT EXISTS public.regulatory_config (
    id TEXT PRIMARY KEY, 
    vat_rate NUMERIC DEFAULT 0.05, 
    service_fee_rate NUMERIC DEFAULT 0.01, 
    gov_fee_rate NUMERIC DEFAULT 0.005, 
    stamp_duty_fixed NUMERIC DEFAULT 1.0, 
    is_active BOOLEAN DEFAULT TRUE, 
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), 
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS public.transfer_tax_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    rate NUMERIC NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.kyc_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    id_type TEXT NOT NULL CHECK (id_type IN ('NATIONAL_ID', 'DRIVER_LICENSE', 'VOTER_ID', 'PASSPORT')),
    id_number TEXT NOT NULL,
    document_url TEXT NOT NULL,
    selfie_url TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    submitted_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    reviewer_id UUID,
    rejection_reason TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    -- Stable device fingerprint for password and biometric/passkey sessions.
    device_fingerprint TEXT,
    ip_address TEXT,
    -- Canonical synthesized device/user-agent label used by security analytics.
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    replaced_by TEXT,
    is_trusted_device BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS public.user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    -- Stable hardware-ish fingerprint. Do not derive from locale/app version.
    device_fingerprint TEXT NOT NULL,
    -- Human-readable device name shown in security views and alerts.
    device_name TEXT,
    -- Expected values include mobile / android / ios / web / desktop.
    device_type TEXT,
    -- Canonical synthesized device/user-agent label used by security analytics.
    user_agent TEXT,
    last_active_at TIMESTAMPTZ DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

-- Biometric/passkey and password-login compatibility hardening for existing databases.
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_name TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_type TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN DEFAULT FALSE;
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';

ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS ip_address TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE public.user_sessions
    ADD COLUMN IF NOT EXISTS is_trusted_device BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS public.user_pin_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    device_fingerprint TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    parent_type TEXT DEFAULT 'biometric',
    source TEXT DEFAULT 'enroll',
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_biometric_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_user_pin_credentials_user
    ON public.user_pin_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_user_pin_credentials_user_device
    ON public.user_pin_credentials(user_id, device_fingerprint);

CREATE TABLE IF NOT EXISTS public.user_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL,
    file_url TEXT NOT NULL,
    file_name TEXT,
    mime_type TEXT,
    size_bytes BIGINT,
    status TEXT DEFAULT 'pending',
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    verified_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    rejection_reason TEXT,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS public.fee_collector_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fee_type TEXT NOT NULL UNIQUE,
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    external_bank_account_id TEXT,
    balance NUMERIC DEFAULT 0,
    currency TEXT DEFAULT 'TZS',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.system_nodes (node_type TEXT PRIMARY KEY, vault_id UUID NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.chargeback_cases (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.payment_reviews (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.payment_metrics_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.transaction_status_logs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.ctr_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.system_catalog (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.reported_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.ai_reports (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.rule_violations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.security_rules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.support_tickets (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.staff_issues (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), data JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), 
    type TEXT NOT NULL, 
    target_id UUID NOT NULL, 
    requester_id UUID REFERENCES auth.users(id) ON DELETE CASCADE, 
    organization_id UUID REFERENCES public.organizations(id),
    policy_id UUID REFERENCES public.treasury_policies(id),
    status TEXT DEFAULT 'PENDING', 
    metadata JSONB, 
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS public.legal_holds (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_type TEXT NOT NULL, target_id UUID NOT NULL, reason TEXT, active BOOLEAN DEFAULT TRUE, issued_by TEXT, issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), released_at TIMESTAMP WITH TIME ZONE);
CREATE TABLE IF NOT EXISTS public.infra_system_matrix (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.infra_app_tokens (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.infra_tx_limits (id TEXT PRIMARY KEY, max_per_transaction NUMERIC, max_daily_total NUMERIC, max_monthly_total NUMERIC, category_limits JSONB, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.infra_snapshots (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), actor_id TEXT, snapshot_data JSONB NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE IF NOT EXISTS public.platform_configs (config_key TEXT PRIMARY KEY, config_data JSONB NOT NULL, updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), updated_by TEXT);
CREATE TABLE IF NOT EXISTS public.app_registry (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, app_id TEXT UNIQUE NOT NULL, app_token TEXT NOT NULL, tier TEXT NOT NULL, status TEXT DEFAULT 'ACTIVE', developer_id TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());

CREATE TABLE IF NOT EXISTS public.ops_action_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_type TEXT NOT NULL CHECK (action_type IN ('DEPLOY_APPROVED_COMMIT', 'RUN_MANUAL_BACKUP', 'RESTORE_BACKUP_DRILL')),
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (status IN ('PENDING_APPROVAL', 'READY', 'QUEUED_FOR_AGENT', 'COMPLETED', 'FAILED', 'CANCELLED')),
    requested_by TEXT NOT NULL,
    requested_reason TEXT NOT NULL,
    target_environment TEXT NOT NULL DEFAULT 'staging',
    command_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    required_approvals INTEGER NOT NULL DEFAULT 2 CHECK (required_approvals >= 2),
    executed_by TEXT,
    execution_result JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE,
    cancelled_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_ops_action_requests_status_created ON public.ops_action_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ops_action_requests_type_created ON public.ops_action_requests(action_type, created_at DESC);

CREATE TABLE IF NOT EXISTS public.fee_correction_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name TEXT NOT NULL,
    description TEXT,
    transaction_type TEXT, 
    fee_type TEXT, 
    correction_formula TEXT, 
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.fee_correction_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES public.transactions(id),
    original_fee_amount NUMERIC,
    corrected_fee_amount NUMERIC,
    correction_rule_id UUID REFERENCES public.fee_correction_rules(id),
    reason TEXT,
    corrected_by UUID REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.item_reconciliation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES public.platform_vaults(id) ON DELETE CASCADE,
    partner_id TEXT,
    internal_balance NUMERIC DEFAULT 0,
    external_balance NUMERIC DEFAULT 0,
    discrepancy NUMERIC DEFAULT 0,
    status TEXT DEFAULT 'MATCHED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.reconciliation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL, -- INTERNAL, SYSTEM, EXTERNAL
    expected_balance NUMERIC NOT NULL,
    actual_balance NUMERIC NOT NULL,
    difference NUMERIC NOT NULL,
    status TEXT NOT NULL, -- MATCHED, MISMATCH, INVESTIGATING
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. CORE FUNCTIONS (REPLACEABLE)
CREATE OR REPLACE FUNCTION public.get_auth_role()
RETURNS TEXT AS $$
DECLARE
  r TEXT;
BEGIN
  SELECT role INTO r FROM public.staff WHERE id = auth.uid();
  IF r IS NULL THEN
    SELECT role INTO r FROM public.users WHERE id = auth.uid();
  END IF;
  RETURN COALESCE(r, 'USER');
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.repair_wallet_balance_emergency(
    target_wallet_id UUID,
    new_balance NUMERIC,
    new_encrypted TEXT,
    repair_actor_id TEXT,
    repair_reason TEXT
)
RETURNS TABLE(entity_type TEXT, previous_balance NUMERIC, repaired_balance NUMERIC) AS $$
DECLARE
    resolved_role TEXT;
    previous_amount NUMERIC;
BEGIN
    IF new_balance IS NULL THEN
        RAISE EXCEPTION 'BALANCE_REQUIRED: repair_wallet_balance_emergency requires a numeric balance';
    END IF;

    IF NULLIF(BTRIM(COALESCE(repair_actor_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'REPAIR_ACTOR_REQUIRED: repair_wallet_balance_emergency requires an actor id';
    END IF;

    IF NULLIF(BTRIM(COALESCE(repair_reason, '')), '') IS NULL THEN
        RAISE EXCEPTION 'REPAIR_REASON_REQUIRED: repair_wallet_balance_emergency requires a human-readable reason';
    END IF;

    SELECT COALESCE(NULLIF(auth.role(), ''), public.get_auth_role()) INTO resolved_role;
    IF resolved_role IS NULL OR resolved_role NOT IN ('service_role', 'SUPER_ADMIN', 'ADMIN', 'AUDIT') THEN
        RAISE EXCEPTION 'PRIVILEGED_REPAIR_ONLY: repair_wallet_balance_emergency is restricted to emergency reconciliation and incident repair';
    END IF;

    SELECT w.balance
      INTO previous_amount
      FROM public.wallets w
     WHERE w.id = target_wallet_id
       AND NOT (
            COALESCE(w.is_locked, FALSE)
            OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
       )
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.wallets
           SET balance = new_balance
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'wallet',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'wallet'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    SELECT pv.balance
      INTO previous_amount
      FROM public.platform_vaults pv
     WHERE pv.id = target_wallet_id
       AND NOT (
            COALESCE(pv.is_locked, FALSE)
            OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
       )
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.platform_vaults
           SET balance = new_balance,
               encrypted_balance = COALESCE(new_encrypted, encrypted_balance)
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'platform_vault',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'platform_vault'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    SELECT g.current
      INTO previous_amount
      FROM public.goals g
     WHERE g.id = target_wallet_id
     FOR UPDATE;

    IF FOUND THEN
        UPDATE public.goals
           SET current = new_balance,
               updated_at = NOW()
         WHERE id = target_wallet_id;

        INSERT INTO public.audit_trail (
            event_type,
            actor_id,
            transaction_id,
            action,
            metadata,
            hash,
            signature
        )
        VALUES (
            'FINANCIAL',
            repair_actor_id,
            target_wallet_id::TEXT,
            'EMERGENCY_BALANCE_REPAIR',
            jsonb_build_object(
                'tool', 'repair_wallet_balance_emergency',
                'entity_type', 'goal',
                'target_wallet_id', target_wallet_id,
                'previous_balance', previous_amount,
                'new_balance', new_balance,
                'reason', repair_reason,
                'warning', 'Privileged repair-only reconciliation. Never call from normal financial flow.'
            ),
            md5(gen_random_uuid()::TEXT || clock_timestamp()::TEXT),
            'repair_tool'
        );

        RETURN QUERY SELECT 'goal'::TEXT, previous_amount, new_balance;
        RETURN;
    END IF;

    RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found or is locked', target_wallet_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

COMMENT ON FUNCTION public.repair_wallet_balance_emergency(UUID, NUMERIC, TEXT, TEXT, TEXT)
IS 'EMERGENCY REPAIR TOOL ONLY. Allowed only for privileged reconciliation, incident repair, or auditor-approved cache repair after ledger truth is independently verified. Requires actor id and human-readable reason. Must never be called from normal payment, transfer, settlement, wealth, or wallet mutation flows.';

CREATE OR REPLACE FUNCTION public.delete_old_activity()
RETURNS void AS $$
BEGIN
    DELETE FROM public.audit_trail WHERE timestamp < NOW() - INTERVAL '1 year';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Atomic Banking RPC
CREATE OR REPLACE FUNCTION public.post_transaction_v2(
    p_tx_id UUID,
    p_user_id UUID,
    p_wallet_id UUID,
    p_to_wallet_id UUID,
    p_amount TEXT,
    p_description TEXT,
    p_type TEXT,
    p_status TEXT,
    p_date DATE,
    p_metadata JSONB,
    p_category_id UUID,
    p_legs JSONB,
    p_reference_id TEXT DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    leg JSONB;
    v_lock_target RECORD;
    v_update_target RECORD;
    v_leg_wallet_id UUID;
    v_leg_entity_type TEXT;
    v_leg_amount NUMERIC;
    v_leg_currency TEXT;
    v_entity_currency TEXT;
    v_check_currency TEXT;
    v_current_balance NUMERIC;
    v_next_balance NUMERIC;
    v_total_credits NUMERIC := 0;
    v_total_debits NUMERIC := 0;
    v_currency_credits JSONB := '{}'::jsonb;
    v_currency_debits JSONB := '{}'::jsonb;
    v_balance_map JSONB := '{}'::jsonb;
    v_entity_type_map JSONB := '{}'::jsonb;
    v_effective_reference_id TEXT;
    v_leg_user_id UUID;
BEGIN
    IF p_legs IS NULL OR jsonb_typeof(p_legs) <> 'array' OR jsonb_array_length(p_legs) = 0 THEN
        RAISE EXCEPTION 'LEDGER_LEGS_REQUIRED: post_transaction_v2 requires at least one ledger leg';
    END IF;

    v_effective_reference_id := COALESCE(NULLIF(BTRIM(p_reference_id), ''), p_tx_id::TEXT);

    FOR v_lock_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        header_ids AS (
            SELECT DISTINCT x.entity_id
            FROM (
                SELECT p_wallet_id AS entity_id
                UNION ALL
                SELECT p_to_wallet_id AS entity_id
            ) x
            WHERE x.entity_id IS NOT NULL
              AND (
                    EXISTS (SELECT 1 FROM public.wallets w WHERE w.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.platform_vaults pv WHERE pv.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.goals g WHERE g.id = x.entity_id)
              )
        ),
        raw_ids AS (
            SELECT entity_id FROM leg_ids
            UNION
            SELECT entity_id FROM header_ids
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM raw_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_lock_target.match_count = 0 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.match_count > 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to multiple tables', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.entity_type = 'wallet' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.wallets w
             WHERE w.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(w.is_locked, FALSE)
                    OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Wallet % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'vault' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.platform_vaults pv
             WHERE pv.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(pv.is_locked, FALSE)
                    OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Vault % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'goal' THEN
            SELECT current
              INTO v_current_balance
              FROM public.goals g
             WHERE g.id = v_lock_target.entity_id
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'GOAL_MISSING: Goal % is unavailable', v_lock_target.entity_id;
            END IF;
        ELSE
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(COALESCE(v_current_balance, 0)),
            TRUE
        );
        v_entity_type_map := jsonb_set(
            v_entity_type_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(v_lock_target.entity_type),
            TRUE
        );
    END LOOP;

    BEGIN
        INSERT INTO public.transactions (
            id,
            reference_id,
            user_id,
            wallet_id,
            to_wallet_id,
            amount,
            description,
            type,
            status,
            date,
            metadata,
            merchant_name,
            category,
            provider,
            category_id
        ) VALUES (
            p_tx_id,
            v_effective_reference_id,
            p_user_id,
            p_wallet_id,
            p_to_wallet_id,
            p_amount,
            p_description,
            p_type,
            p_status,
            p_date,
            COALESCE(p_metadata, '{}'::jsonb),
            NULLIF(BTRIM(COALESCE(
                p_metadata->>'merchant_name',
                p_metadata->>'merchantName',
                p_metadata->>'business_name',
                p_metadata->>'businessName'
            )), ''),
            NULLIF(BTRIM(COALESCE(
                p_metadata->>'category',
                p_metadata->>'category_name',
                p_metadata->>'categoryName',
                p_metadata->>'category_code',
                p_metadata->>'categoryCode'
            )), ''),
            NULLIF(BTRIM(COALESCE(
                p_metadata->>'provider',
                p_metadata->>'provider_name',
                p_metadata->>'providerName',
                p_metadata->>'provider_code',
                p_metadata->>'providerCode'
            )), ''),
            p_category_id
        );
    EXCEPTION
        WHEN unique_violation THEN
            IF EXISTS (
                SELECT 1
                FROM public.transactions t
                WHERE t.reference_id = v_effective_reference_id
            ) THEN
                RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION: Transaction with reference % already exists', v_effective_reference_id;
            END IF;
            RAISE;
    END;

    -- Compatibility note:
    --   * leg.balance_before is ignored as authoritative; SQL re-reads the locked row state.
    --   * leg.balance_after is ignored; SQL computes the next balance internally.
    --   * leg.balance_after_encrypted is ignored; SQL writes SQL-computed plaintext balance_after.
    --   * leg.amount remains the stored payload for financial_ledger.amount.
    --   * leg.amount_plain is the authoritative arithmetic input when supplied. If absent,
    --     SQL only accepts leg.amount when it is already a numeric plaintext value.
    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        v_leg_wallet_id := (leg->>'wallet_id')::UUID;

        IF v_leg_wallet_id IS NULL THEN
            RAISE EXCEPTION 'LEDGER_LEG_WALLET_REQUIRED: Each leg must include wallet_id';
        END IF;

        v_leg_entity_type := v_entity_type_map->>v_leg_wallet_id::TEXT;
        IF v_leg_entity_type IS NULL THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not locked for this transaction', v_leg_wallet_id;
        END IF;

        IF NULLIF(BTRIM(leg->>'amount_plain'), '') IS NOT NULL THEN
            v_leg_amount := (leg->>'amount_plain')::NUMERIC;
        ELSIF NULLIF(BTRIM(leg->>'amount'), '') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN
            v_leg_amount := (leg->>'amount')::NUMERIC;
        ELSE
            RAISE EXCEPTION 'LEG_AMOUNT_REQUIRED: Leg for % must include numeric amount_plain when amount is encrypted', v_leg_wallet_id;
        END IF;

        IF v_leg_amount <= 0 THEN
            RAISE EXCEPTION 'LEG_AMOUNT_INVALID: Leg for % must have a positive amount', v_leg_wallet_id;
        END IF;

        CASE v_leg_entity_type
            WHEN 'wallet' THEN SELECT UPPER(currency) INTO v_entity_currency FROM public.wallets WHERE id = v_leg_wallet_id;
            WHEN 'vault' THEN SELECT UPPER(currency) INTO v_entity_currency FROM public.platform_vaults WHERE id = v_leg_wallet_id;
            WHEN 'goal' THEN SELECT UPPER(currency) INTO v_entity_currency FROM public.goals WHERE id = v_leg_wallet_id;
            ELSE RAISE EXCEPTION 'LEDGER_ENTITY_CURRENCY_UNKNOWN: %', v_leg_wallet_id;
        END CASE;
        v_leg_currency := UPPER(COALESCE(NULLIF(BTRIM(leg->>'currency'), ''), v_entity_currency));
        IF v_entity_currency IS NULL OR v_leg_currency <> v_entity_currency THEN
            RAISE EXCEPTION 'LEDGER_CURRENCY_MISMATCH: Entity % uses %, leg uses %', v_leg_wallet_id, v_entity_currency, v_leg_currency;
        END IF;

        v_current_balance := COALESCE((v_balance_map->>v_leg_wallet_id::TEXT)::NUMERIC, 0);

        CASE UPPER(COALESCE(leg->>'entry_type', ''))
            WHEN 'CREDIT' THEN
                v_next_balance := ROUND((v_current_balance + v_leg_amount)::NUMERIC, 4);
                v_total_credits := v_total_credits + v_leg_amount;
                v_currency_credits := jsonb_set(v_currency_credits, ARRAY[v_leg_currency],
                    to_jsonb(COALESCE((v_currency_credits->>v_leg_currency)::NUMERIC, 0) + v_leg_amount), TRUE);
            WHEN 'DEBIT' THEN
                v_next_balance := ROUND((v_current_balance - v_leg_amount)::NUMERIC, 4);
                v_total_debits := v_total_debits + v_leg_amount;
                v_currency_debits := jsonb_set(v_currency_debits, ARRAY[v_leg_currency],
                    to_jsonb(COALESCE((v_currency_debits->>v_leg_currency)::NUMERIC, 0) + v_leg_amount), TRUE);
                IF v_next_balance < 0 THEN
                    RAISE EXCEPTION 'INSUFFICIENT_FUNDS: Internal entity % would go negative', v_leg_wallet_id;
                END IF;
            ELSE
                RAISE EXCEPTION 'LEDGER_ENTRY_TYPE_INVALID: Leg for % must be CREDIT or DEBIT', v_leg_wallet_id;
        END CASE;

        INSERT INTO public.financial_ledger (
            id,
            transaction_id,
            user_id,
            wallet_id,
            entry_type,
            amount,
            balance_after,
            balance_after_encrypted,
            description,
            currency
        ) VALUES (
            gen_random_uuid(),
            p_tx_id,
            COALESCE(NULLIF(leg->>'user_id', '')::UUID, public.resolve_financial_ledger_wallet_owner(v_leg_wallet_id, p_user_id)),
            v_leg_wallet_id,
            UPPER(leg->>'entry_type'),
            leg->>'amount',
            v_next_balance::TEXT,
            NULL,
            leg->>'description',
            v_leg_currency
        );

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_leg_wallet_id::TEXT],
            to_jsonb(v_next_balance),
            TRUE
        );
    END LOOP;

    IF ROUND(ABS(v_total_credits - v_total_debits)::NUMERIC, 4) <> 0 THEN
        RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE: credits % do not equal debits %', v_total_credits, v_total_debits;
    END IF;
    FOR v_check_currency IN SELECT jsonb_object_keys(v_currency_credits || v_currency_debits) LOOP
        IF ROUND(ABS(COALESCE((v_currency_credits->>v_check_currency)::NUMERIC, 0)
            - COALESCE((v_currency_debits->>v_check_currency)::NUMERIC, 0))::NUMERIC, 4) <> 0 THEN
            RAISE EXCEPTION 'LEDGER_CURRENCY_OUT_OF_BALANCE: % credits % debits %', v_check_currency,
                v_currency_credits->>v_check_currency, v_currency_debits->>v_check_currency;
        END IF;
    END LOOP;

    FOR v_update_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        header_ids AS (
            SELECT DISTINCT x.entity_id
            FROM (
                SELECT p_wallet_id AS entity_id
                UNION ALL
                SELECT p_to_wallet_id AS entity_id
            ) x
            WHERE x.entity_id IS NOT NULL
              AND (
                    EXISTS (SELECT 1 FROM public.wallets w WHERE w.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.platform_vaults pv WHERE pv.id = x.entity_id)
                 OR EXISTS (SELECT 1 FROM public.goals g WHERE g.id = x.entity_id)
              )
        ),
        raw_ids AS (
            SELECT entity_id FROM leg_ids
            UNION
            SELECT entity_id FROM header_ids
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM raw_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_update_target.match_count <> 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to % matches', v_update_target.entity_id, v_update_target.match_count;
        END IF;

        IF v_update_target.entity_type = 'wallet' THEN
            UPDATE public.wallets
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'vault' THEN
            UPDATE public.platform_vaults
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'goal' THEN
            UPDATE public.goals
               SET current = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, current),
                   updated_at = NOW()
             WHERE id = v_update_target.entity_id;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Atomic Append Ledger Legs RPC
CREATE OR REPLACE FUNCTION public.append_ledger_entries_v1(
    p_tx_id UUID,
    p_legs JSONB,
    p_append_key TEXT DEFAULT NULL,
    p_append_phase TEXT DEFAULT NULL
)
RETURNS void AS $$
DECLARE
    leg JSONB;
    v_lock_target RECORD;
    v_update_target RECORD;
    v_leg_wallet_id UUID;
    v_leg_entity_type TEXT;
    v_leg_amount NUMERIC;
    v_current_balance NUMERIC;
    v_next_balance NUMERIC;
    v_total_credits NUMERIC := 0;
    v_total_debits NUMERIC := 0;
    v_balance_map JSONB := '{}'::jsonb;
    v_entity_type_map JSONB := '{}'::jsonb;
    v_tx_user_id UUID;
    v_leg_user_id UUID;
BEGIN
    IF p_legs IS NULL OR jsonb_typeof(p_legs) <> 'array' OR jsonb_array_length(p_legs) = 0 THEN
        RAISE EXCEPTION 'LEDGER_LEGS_REQUIRED: append_ledger_entries_v1 requires at least one ledger leg';
    END IF;

    SELECT t.user_id
      INTO v_tx_user_id
      FROM public.transactions t
     WHERE t.id = p_tx_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TRANSACTION_MISSING: Transaction % was not found', p_tx_id;
    END IF;

    IF NULLIF(BTRIM(COALESCE(p_append_key, '')), '') IS NOT NULL
       OR NULLIF(BTRIM(COALESCE(p_append_phase, '')), '') IS NOT NULL THEN
        BEGIN
            INSERT INTO public.ledger_append_markers (
                transaction_id,
                append_key,
                append_phase,
                metadata
            ) VALUES (
                p_tx_id,
                NULLIF(BTRIM(p_append_key), ''),
                NULLIF(BTRIM(p_append_phase), ''),
                jsonb_build_object(
                    'leg_count', jsonb_array_length(p_legs),
                    'registered_at', NOW(),
                    'append_phase', NULLIF(BTRIM(p_append_phase), ''),
                    'append_key', NULLIF(BTRIM(p_append_key), '')
                )
            );
        EXCEPTION
            WHEN unique_violation THEN
                RAISE EXCEPTION 'APPEND_ALREADY_APPLIED: transaction %, append_key %, append_phase %',
                    p_tx_id,
                    COALESCE(NULLIF(BTRIM(p_append_key), ''), '<null>'),
                    COALESCE(NULLIF(BTRIM(p_append_phase), ''), '<null>');
        END;
    END IF;

    FOR v_lock_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM leg_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_lock_target.match_count = 0 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.match_count > 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to multiple tables', v_lock_target.entity_id;
        END IF;

        IF v_lock_target.entity_type = 'wallet' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.wallets w
             WHERE w.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(w.is_locked, FALSE)
                    OR lower(COALESCE(w.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Wallet % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'vault' THEN
            SELECT balance
              INTO v_current_balance
              FROM public.platform_vaults pv
             WHERE pv.id = v_lock_target.entity_id
               AND NOT (
                    COALESCE(pv.is_locked, FALSE)
                    OR lower(COALESCE(pv.status, '')) IN ('locked', 'frozen', 'blocked', 'suspended')
               )
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'WALLET_LOCKED: Vault % is locked or unavailable', v_lock_target.entity_id;
            END IF;
        ELSIF v_lock_target.entity_type = 'goal' THEN
            SELECT current
              INTO v_current_balance
              FROM public.goals g
             WHERE g.id = v_lock_target.entity_id
             FOR UPDATE;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'GOAL_MISSING: Goal % is unavailable', v_lock_target.entity_id;
            END IF;
        ELSE
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not found', v_lock_target.entity_id;
        END IF;

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(COALESCE(v_current_balance, 0)),
            TRUE
        );
        v_entity_type_map := jsonb_set(
            v_entity_type_map,
            ARRAY[v_lock_target.entity_id::TEXT],
            to_jsonb(v_lock_target.entity_type),
            TRUE
        );
    END LOOP;

    -- Compatibility note:
    --   * leg.balance_before is ignored as authoritative; SQL re-reads the locked row state.
    --   * leg.balance_after is ignored; SQL computes the next balance internally.
    --   * leg.balance_after_encrypted is ignored; SQL writes SQL-computed plaintext balance_after.
    --   * leg.amount remains the stored payload for financial_ledger.amount.
    --   * leg.amount_plain is the authoritative arithmetic input when supplied. If absent,
    --     SQL only accepts leg.amount when it is already a numeric plaintext value.
    FOR leg IN SELECT * FROM jsonb_array_elements(p_legs)
    LOOP
        v_leg_wallet_id := (leg->>'wallet_id')::UUID;

        IF v_leg_wallet_id IS NULL THEN
            RAISE EXCEPTION 'LEDGER_LEG_WALLET_REQUIRED: Each leg must include wallet_id';
        END IF;

        v_leg_entity_type := v_entity_type_map->>v_leg_wallet_id::TEXT;
        IF v_leg_entity_type IS NULL THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_MISSING: Internal entity % was not locked for this append', v_leg_wallet_id;
        END IF;

        IF NULLIF(BTRIM(leg->>'amount_plain'), '') IS NOT NULL THEN
            v_leg_amount := (leg->>'amount_plain')::NUMERIC;
        ELSIF NULLIF(BTRIM(leg->>'amount'), '') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN
            v_leg_amount := (leg->>'amount')::NUMERIC;
        ELSE
            RAISE EXCEPTION 'LEG_AMOUNT_REQUIRED: Leg for % must include numeric amount_plain when amount is encrypted', v_leg_wallet_id;
        END IF;

        IF v_leg_amount <= 0 THEN
            RAISE EXCEPTION 'LEG_AMOUNT_INVALID: Leg for % must have a positive amount', v_leg_wallet_id;
        END IF;

        v_leg_user_id := COALESCE(NULLIF(leg->>'user_id', '')::UUID, public.resolve_financial_ledger_wallet_owner(v_leg_wallet_id, v_tx_user_id));

        v_current_balance := COALESCE((v_balance_map->>v_leg_wallet_id::TEXT)::NUMERIC, 0);

        CASE UPPER(COALESCE(leg->>'entry_type', ''))
            WHEN 'CREDIT' THEN
                v_next_balance := ROUND((v_current_balance + v_leg_amount)::NUMERIC, 4);
                v_total_credits := v_total_credits + v_leg_amount;
            WHEN 'DEBIT' THEN
                v_next_balance := ROUND((v_current_balance - v_leg_amount)::NUMERIC, 4);
                v_total_debits := v_total_debits + v_leg_amount;
                IF v_next_balance < 0 THEN
                    RAISE EXCEPTION 'INSUFFICIENT_FUNDS: Internal entity % would go negative', v_leg_wallet_id;
                END IF;
            ELSE
                RAISE EXCEPTION 'LEDGER_ENTRY_TYPE_INVALID: Leg for % must be CREDIT or DEBIT', v_leg_wallet_id;
        END CASE;

        INSERT INTO public.financial_ledger (
            id,
            transaction_id,
            user_id,
            wallet_id,
            entry_type,
            amount,
            balance_after,
            balance_after_encrypted,
            description
        ) VALUES (
            gen_random_uuid(),
            p_tx_id,
            v_leg_user_id,
            v_leg_wallet_id,
            UPPER(leg->>'entry_type'),
            leg->>'amount',
            v_next_balance::TEXT,
            NULL,
            leg->>'description'
        );

        v_balance_map := jsonb_set(
            v_balance_map,
            ARRAY[v_leg_wallet_id::TEXT],
            to_jsonb(v_next_balance),
            TRUE
        );
    END LOOP;

    IF ROUND(ABS(v_total_credits - v_total_debits)::NUMERIC, 4) <> 0 THEN
        RAISE EXCEPTION 'LEDGER_OUT_OF_BALANCE: credits % do not equal debits %', v_total_credits, v_total_debits;
    END IF;

    FOR v_update_target IN
        WITH leg_ids AS (
            SELECT DISTINCT (leg_item->>'wallet_id')::UUID AS entity_id
            FROM jsonb_array_elements(p_legs) AS leg_item
            WHERE NULLIF(leg_item->>'wallet_id', '') IS NOT NULL
        ),
        resolved AS (
            SELECT
                r.entity_id,
                CASE
                    WHEN w.id IS NOT NULL THEN 'wallet'
                    WHEN pv.id IS NOT NULL THEN 'vault'
                    WHEN g.id IS NOT NULL THEN 'goal'
                    ELSE NULL
                END AS entity_type,
                (CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN pv.id IS NOT NULL THEN 1 ELSE 0 END
                 + CASE WHEN g.id IS NOT NULL THEN 1 ELSE 0 END) AS match_count
            FROM leg_ids r
            LEFT JOIN public.wallets w ON w.id = r.entity_id
            LEFT JOIN public.platform_vaults pv ON pv.id = r.entity_id
            LEFT JOIN public.goals g ON g.id = r.entity_id
        )
        SELECT entity_id, entity_type, match_count
        FROM resolved
        ORDER BY entity_type, entity_id
    LOOP
        IF v_update_target.match_count <> 1 THEN
            RAISE EXCEPTION 'LEDGER_ENTITY_AMBIGUOUS: Internal entity % resolves to % matches', v_update_target.entity_id, v_update_target.match_count;
        END IF;

        IF v_update_target.entity_type = 'wallet' THEN
            UPDATE public.wallets
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'vault' THEN
            UPDATE public.platform_vaults
               SET balance = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, balance)
             WHERE id = v_update_target.entity_id;
        ELSIF v_update_target.entity_type = 'goal' THEN
            UPDATE public.goals
               SET current = COALESCE((v_balance_map->>v_update_target.entity_id::TEXT)::NUMERIC, current),
                   updated_at = NOW()
             WHERE id = v_update_target.entity_id;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Card settlement functions compile against these row types, so the core card
-- tables must exist before the function definitions below.
CREATE TABLE IF NOT EXISTS public.card_tokens (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    masked_card_number TEXT NOT NULL,
    tokenized_card_number TEXT NOT NULL,
    expiry_month INTEGER NOT NULL,
    expiry_year INTEGER NOT NULL,
    cardholder_name TEXT NOT NULL,
    card_brand TEXT NOT NULL CHECK (card_brand IN ('VISA', 'MASTERCARD', 'AMEX', 'DISCOVERY')),
    card_type TEXT DEFAULT 'CREDIT' CHECK (card_type IN ('CREDIT', 'DEBIT')),
    last_four_digits TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'EXPIRED')),
    encrypted_cvv TEXT,
    billing_address JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS public.card_transactions (
    id TEXT PRIMARY KEY,
    card_token_id TEXT REFERENCES public.card_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'AUTHORIZED', 'SETTLED', 'FAILED', 'DECLINED', 'REVERSED')),
    authorization_code TEXT,
    rrn TEXT,
    stan_number TEXT,
    response_code TEXT,
    response_message TEXT,
    risk_score NUMERIC DEFAULT 0,
    fraud_flags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    settled_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE OR REPLACE FUNCTION public.card_settle_v1(
    p_card_transaction_id TEXT,
    p_target_wallet_id UUID,
    p_fee_wallet_id UUID,
    p_fee_amount NUMERIC DEFAULT 0
)
RETURNS JSONB AS $$
DECLARE
    v_card_tx public.card_transactions%ROWTYPE;
    v_target_wallet public.wallets%ROWTYPE;
    v_service_revenue_vault public.platform_vaults%ROWTYPE;
    v_financial_tx public.transactions%ROWTYPE;
    v_currency TEXT;
    v_target_balance_after NUMERIC;
    v_fee_balance_after NUMERIC := 0;
    v_reference_id TEXT;
BEGIN
    IF p_card_transaction_id IS NULL OR trim(p_card_transaction_id) = '' THEN RAISE EXCEPTION 'CARD_TRANSACTION_REQUIRED'; END IF;
    IF p_target_wallet_id IS NULL THEN RAISE EXCEPTION 'TARGET_WALLET_REQUIRED'; END IF;

    SELECT * INTO v_card_tx FROM public.card_transactions WHERE id = p_card_transaction_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'CARD_TRANSACTION_NOT_FOUND'; END IF;
    IF upper(COALESCE(v_card_tx.status, '')) <> 'AUTHORIZED' THEN RAISE EXCEPTION 'CARD_TRANSACTION_NOT_AUTHORIZED'; END IF;

    SELECT * INTO v_target_wallet FROM public.wallets WHERE id = p_target_wallet_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'TARGET_WALLET_NOT_FOUND'; END IF;
    IF COALESCE(v_card_tx.amount, 0) <= 0 THEN RAISE EXCEPTION 'INVALID_CARD_SETTLEMENT_AMOUNT'; END IF;
    IF COALESCE(p_fee_amount, 0) < 0 THEN RAISE EXCEPTION 'INVALID_FEE_AMOUNT'; END IF;

    v_currency := upper(COALESCE(NULLIF(trim(v_card_tx.currency), ''), 'TZS'));
    IF upper(COALESCE(v_target_wallet.currency, '')) <> v_currency THEN RAISE EXCEPTION 'CARD_SETTLEMENT_CURRENCY_MISMATCH'; END IF;

    IF COALESCE(p_fee_amount, 0) > 0 THEN
        SELECT pv.* INTO v_service_revenue_vault
        FROM public.system_settlement_accounts ssa
        JOIN public.platform_vaults pv ON pv.id = ssa.vault_id
        WHERE ssa.role = 'SERVICE_REVENUE'
          AND ssa.currency = v_currency
          AND ssa.status = 'ACTIVE'
          AND upper(COALESCE(pv.currency, '')) = v_currency
          AND NOT COALESCE(pv.is_locked, FALSE)
          AND lower(COALESCE(pv.status, 'active')) = 'active'
        FOR UPDATE OF pv;
        IF NOT FOUND THEN RAISE EXCEPTION 'CARD_SERVICE_REVENUE_ACCOUNT_UNAVAILABLE:%', v_currency; END IF;
        IF p_fee_wallet_id IS DISTINCT FROM v_service_revenue_vault.id THEN RAISE EXCEPTION 'CARD_FEE_ACCOUNT_MISMATCH'; END IF;
        v_fee_balance_after := COALESCE(v_service_revenue_vault.balance, 0) + p_fee_amount;
    END IF;

    v_target_balance_after := COALESCE(v_target_wallet.balance, 0) + COALESCE(v_card_tx.amount, 0);
    v_reference_id := 'card_' || trim(p_card_transaction_id);

    INSERT INTO public.transactions (id, reference_id, user_id, wallet_id, to_wallet_id, amount, currency, description, type, status, date, metadata)
    VALUES (gen_random_uuid(), v_reference_id, COALESCE(v_target_wallet.user_id, v_card_tx.user_id), NULL, v_target_wallet.id, v_card_tx.amount::text, v_currency, 'Card payment settlement - ' || p_card_transaction_id, 'deposit', 'completed', CURRENT_DATE, jsonb_build_object('card_transaction_id', p_card_transaction_id, 'source_wallet_type', 'EXTERNAL', 'target_wallet_type', COALESCE(v_target_wallet.wallet_type, 'INTERNAL'), 'settlement_path', 'SOVEREIGN_LEDGER', 'service_revenue_vault_id', CASE WHEN p_fee_amount > 0 THEN v_service_revenue_vault.id ELSE NULL END))
    RETURNING * INTO v_financial_tx;

    INSERT INTO public.financial_ledger (id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description, currency)
    VALUES (gen_random_uuid(), v_financial_tx.id, COALESCE(v_target_wallet.user_id, v_card_tx.user_id), v_target_wallet.id, 'CREDIT', v_card_tx.amount::text, v_target_balance_after::text, 'Card deposit - ' || p_card_transaction_id, v_currency);

    IF COALESCE(p_fee_amount, 0) > 0 THEN
        UPDATE public.platform_vaults SET balance = v_fee_balance_after, updated_at = NOW() WHERE id = v_service_revenue_vault.id;
        INSERT INTO public.financial_ledger (id, transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description, currency)
        VALUES (gen_random_uuid(), v_financial_tx.id, v_service_revenue_vault.user_id, v_service_revenue_vault.id, 'CREDIT', p_fee_amount::text, v_fee_balance_after::text, 'Card processor service revenue - ' || p_card_transaction_id, v_currency);
    END IF;

    UPDATE public.wallets SET balance = v_target_balance_after, updated_at = NOW() WHERE id = v_target_wallet.id;
    UPDATE public.card_transactions SET status = 'SETTLED', settled_at = NOW(), updated_at = NOW() WHERE id = p_card_transaction_id;

    RETURN jsonb_build_object('success', true, 'settlement_id', v_financial_tx.id, 'transaction_id', p_card_transaction_id, 'amount', COALESCE(v_card_tx.amount, 0), 'fee', COALESCE(p_fee_amount, 0), 'target_balance_after', v_target_balance_after, 'fee_balance_after', v_fee_balance_after, 'service_revenue_vault_id', CASE WHEN p_fee_amount > 0 THEN v_service_revenue_vault.id ELSE NULL END, 'status', 'COMPLETED');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.bill_reserve_adjust_v1(
    p_user_id UUID,
    p_reserve_id UUID,
    p_source_wallet_id UUID,
    p_amount NUMERIC,
    p_action TEXT,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb,
    p_desired_locked_balance NUMERIC DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_reserve public.bill_reserves%ROWTYPE;
    v_source_wallet public.wallets%ROWTYPE;
    v_source_vault public.platform_vaults%ROWTYPE;
    v_source_table TEXT;
    v_source_balance_before NUMERIC;
    v_source_balance_after NUMERIC;
    v_locked_balance_before NUMERIC;
    v_locked_balance_after NUMERIC;
    v_action TEXT := upper(COALESCE(trim(p_action), ''));
    v_tx public.transactions%ROWTYPE;
    v_reference_id TEXT := 'wealth_' || extract(epoch from now())::bigint || '_' || substr(md5(random()::text), 1, 8);
    v_source_wallet_role TEXT;
BEGIN
    IF p_reserve_id IS NULL THEN RAISE EXCEPTION 'BILL_RESERVE_REQUIRED'; END IF;
    IF p_source_wallet_id IS NULL THEN RAISE EXCEPTION 'SOURCE_WALLET_REQUIRED'; END IF;
    IF p_amount IS NULL OR p_amount < 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_action NOT IN ('LOCK', 'RELEASE') THEN RAISE EXCEPTION 'INVALID_BILL_RESERVE_ACTION'; END IF;

    SELECT * INTO v_reserve
      FROM public.bill_reserves
     WHERE id = p_reserve_id
       AND user_id = p_user_id
     FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'BILL_RESERVE_NOT_FOUND'; END IF;

    SELECT * INTO v_source_wallet
      FROM public.wallets
     WHERE id = p_source_wallet_id
       AND user_id = p_user_id
     FOR UPDATE;

    IF FOUND THEN
        v_source_table := 'wallets';
        v_source_balance_before := COALESCE(v_source_wallet.balance, 0);
        v_source_wallet_role := COALESCE(v_source_wallet.type, NULL);
    ELSE
        SELECT * INTO v_source_vault
          FROM public.platform_vaults
         WHERE id = p_source_wallet_id
           AND user_id = p_user_id
         FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'SOURCE_WALLET_NOT_FOUND'; END IF;
        v_source_table := 'platform_vaults';
        v_source_balance_before := COALESCE(v_source_vault.balance, 0);
        v_source_wallet_role := COALESCE(v_source_vault.vault_role, NULL);
    END IF;

    v_locked_balance_before := COALESCE(v_reserve.locked_balance, 0);
    v_locked_balance_after := COALESCE(p_desired_locked_balance,
      CASE WHEN v_action = 'LOCK' THEN v_locked_balance_before + p_amount
      ELSE GREATEST(v_locked_balance_before - p_amount, 0) END);

    IF v_action = 'LOCK' THEN
        IF v_source_balance_before < p_amount THEN RAISE EXCEPTION 'INSUFFICIENT_FUNDS'; END IF;
        v_source_balance_after := v_source_balance_before - p_amount;
    ELSE
        IF v_locked_balance_before < p_amount THEN RAISE EXCEPTION 'BILL_RESERVE_INSUFFICIENT_BALANCE'; END IF;
        v_source_balance_after := v_source_balance_before + p_amount;
    END IF;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description, type, status, date,
        wealth_impact_type, protection_state, allocation_source, metadata
    ) VALUES (
        gen_random_uuid(),
        v_reference_id,
        p_user_id,
        p_source_wallet_id,
        p_amount::text,
        upper(COALESCE(NULLIF(trim(p_currency), ''), 'TZS')),
        COALESCE(NULLIF(trim(p_description), ''), 'Bill reserve adjustment'),
        COALESCE(NULLIF(trim(p_metadata->>'transaction_type'), ''), 'internal_transfer'),
        COALESCE(NULLIF(trim(p_metadata->>'transaction_status'), ''), 'completed'),
        CURRENT_DATE,
        COALESCE(NULLIF(trim(p_metadata->>'wealth_impact_type'), ''), 'PLANNED'),
        'OPEN',
        NULLIF(trim(COALESCE(p_metadata->>'allocation_source', '')), ''),
        p_metadata
    )
    RETURNING * INTO v_tx;

    IF v_source_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_source_balance_after, updated_at = NOW()
         WHERE id = p_source_wallet_id AND user_id = p_user_id;
    ELSE
        UPDATE public.platform_vaults SET balance = v_source_balance_after, updated_at = NOW()
         WHERE id = p_source_wallet_id AND user_id = p_user_id;
    END IF;

    UPDATE public.bill_reserves
       SET locked_balance = v_locked_balance_after,
           source_wallet_id = p_source_wallet_id,
           updated_at = NOW()
     WHERE id = p_reserve_id
       AND user_id = p_user_id
    RETURNING * INTO v_reserve;

    INSERT INTO public.financial_ledger (
        id, transaction_id, user_id, wallet_id, bill_reserve_id, bucket_type, entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (
        gen_random_uuid(), v_tx.id, p_user_id, p_source_wallet_id, p_reserve_id, 'OPERATING',
        CASE WHEN v_action = 'LOCK' THEN 'DEBIT' ELSE 'CREDIT' END,
        CASE WHEN v_action = 'LOCK' THEN 'DEBIT' ELSE 'CREDIT' END,
        p_amount::text, v_source_balance_after::text,
        CASE WHEN v_action = 'LOCK' THEN 'Bill reserve funding debit' ELSE 'Bill reserve release credit' END
    ),
    (
        gen_random_uuid(), v_tx.id, p_user_id, p_source_wallet_id, p_reserve_id, 'PLANNED',
        CASE WHEN v_action = 'LOCK' THEN 'CREDIT' ELSE 'DEBIT' END,
        CASE WHEN v_action = 'LOCK' THEN 'CREDIT' ELSE 'DEBIT' END,
        p_amount::text, v_locked_balance_after::text,
        CASE WHEN v_action = 'LOCK' THEN 'Bill reserve protected balance credit' ELSE 'Bill reserve protected balance release' END
    );

    RETURN jsonb_build_object(
        'success', true,
        'transaction_id', v_tx.id,
        'reference_id', v_reference_id,
        'source_balance_after', v_source_balance_after,
        'reserve', to_jsonb(v_reserve),
        'source_table', v_source_table,
        'source_wallet_role', v_source_wallet_role,
        'atomic_commit', true
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.settle_bill_payment_from_reserve_v1(
    p_user_id UUID,
    p_reserve_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_provider TEXT DEFAULT NULL,
    p_bill_category TEXT DEFAULT NULL,
    p_reference TEXT DEFAULT NULL,
    p_description TEXT DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_reserve public.bill_reserves%ROWTYPE;
    v_transaction public.transactions%ROWTYPE;
    v_source_wallet_id UUID;
    v_source_wallet_role TEXT;
    v_source_metadata JSONB := '{}'::jsonb;
    v_source_kind TEXT;
    v_locked_balance NUMERIC;
    v_reserve_balance_after NUMERIC;
    v_reference_id TEXT := 'billreserve_' || extract(epoch from now())::bigint || '_' || substr(md5(random()::text), 1, 8);
    v_provider_key TEXT;
    v_reserve_provider_key TEXT;
    v_category_key TEXT;
    v_reserve_category_key TEXT;
    v_reference_key TEXT;
    v_reserve_reference_key TEXT;
    v_updated_reserve JSONB;
BEGIN
    IF p_amount IS NULL OR p_amount <= 0 THEN
        RAISE EXCEPTION 'INVALID_AMOUNT';
    END IF;

    SELECT *
      INTO v_reserve
      FROM public.bill_reserves
     WHERE id = p_reserve_id
       AND user_id = p_user_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'BILL_RESERVE_NOT_FOUND';
    END IF;

    IF COALESCE(v_reserve.is_active, TRUE) = FALSE
       OR upper(COALESCE(v_reserve.status, 'ACTIVE')) <> 'ACTIVE' THEN
        RAISE EXCEPTION 'BILL_RESERVE_INACTIVE';
    END IF;

    v_provider_key := regexp_replace(replace(lower(trim(COALESCE(p_provider, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_provider_key := regexp_replace(replace(lower(trim(COALESCE(v_reserve.provider_name, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    IF v_provider_key <> '' AND v_reserve_provider_key <> ''
       AND v_provider_key <> v_reserve_provider_key
       AND strpos(v_provider_key, v_reserve_provider_key) = 0
       AND strpos(v_reserve_provider_key, v_provider_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_PROVIDER_MISMATCH';
    END IF;

    v_category_key := regexp_replace(replace(lower(trim(COALESCE(p_bill_category, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_category_key := regexp_replace(replace(lower(trim(COALESCE(v_reserve.bill_type, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    IF v_category_key <> '' AND v_reserve_category_key <> ''
       AND v_category_key <> v_reserve_category_key
       AND strpos(v_category_key, v_reserve_category_key) = 0
       AND strpos(v_reserve_category_key, v_category_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_CATEGORY_MISMATCH';
    END IF;

    v_reference_key := regexp_replace(replace(lower(trim(COALESCE(p_reference, ''))), '&', 'and'), '[^a-z0-9]+', ' ', 'g');
    v_reserve_reference_key := regexp_replace(
        replace(
            lower(
                trim(
                    COALESCE(
                        v_reserve.metadata->>'reference',
                        v_reserve.metadata->>'bill_reference',
                        v_reserve.metadata->>'account_number',
                        v_reserve.metadata->>'meter_number',
                        v_reserve.metadata->>'customer_number',
                        ''
                    )
                )
            ),
            '&',
            'and'
        ),
        '[^a-z0-9]+',
        ' ',
        'g'
    );
    IF v_reference_key <> '' AND v_reserve_reference_key <> ''
       AND v_reference_key <> v_reserve_reference_key
       AND strpos(v_reference_key, v_reserve_reference_key) = 0
       AND strpos(v_reserve_reference_key, v_reference_key) = 0 THEN
        RAISE EXCEPTION 'BILL_RESERVE_REFERENCE_MISMATCH';
    END IF;

    v_locked_balance := COALESCE(v_reserve.locked_balance, v_reserve.reserve_amount, 0);
    IF v_locked_balance < p_amount THEN
        RAISE EXCEPTION 'BILL_RESERVE_INSUFFICIENT_BALANCE';
    END IF;

    v_source_wallet_id := v_reserve.source_wallet_id;

    IF v_source_wallet_id IS NOT NULL THEN
        SELECT id, vault_role, COALESCE(metadata, '{}'::jsonb)
          INTO v_source_wallet_id, v_source_wallet_role, v_source_metadata
          FROM public.platform_vaults
         WHERE id = v_reserve.source_wallet_id
           AND user_id = p_user_id
         LIMIT 1;

        IF v_source_wallet_id IS NULL THEN
            SELECT id, type, COALESCE(metadata, '{}'::jsonb)
              INTO v_source_wallet_id, v_source_wallet_role, v_source_metadata
              FROM public.wallets
             WHERE id = v_reserve.source_wallet_id
               AND user_id = p_user_id
             LIMIT 1;
        END IF;
    END IF;

    v_source_kind := lower(
        COALESCE(
            v_source_metadata->>'source_kind',
            v_source_metadata->>'sourceKind',
            v_source_metadata->>'wallet_kind',
            v_source_wallet_role,
            ''
        )
    );
    IF strpos(v_source_kind, 'goal') > 0
       OR v_source_metadata ? 'goal_id'
       OR v_source_metadata ? 'goalId' THEN
        RAISE EXCEPTION 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED';
    END IF;

    v_reserve_balance_after := v_locked_balance - p_amount;

    INSERT INTO public.transactions (
        id,
        reference_id,
        user_id,
        wallet_id,
        amount,
        currency,
        description,
        type,
        status,
        date,
        metadata,
        wealth_impact_type,
        protection_state,
        allocation_source
    ) VALUES (
        gen_random_uuid(),
        v_reference_id,
        p_user_id,
        v_source_wallet_id,
        p_amount::text,
        upper(COALESCE(NULLIF(trim(p_currency), ''), v_reserve.currency, 'TZS')),
        COALESCE(NULLIF(trim(p_description), ''), 'Bill payment from reserve: ' || COALESCE(p_provider, v_reserve.provider_name, 'Provider')),
        'bill_payment',
        'completed',
        CURRENT_DATE,
        jsonb_strip_nulls(jsonb_build_object(
            'bill_reserve_id', v_reserve.id,
            'service_context', 'BILL_PAYMENT',
            'funding_mode', 'RESERVE',
            'bill_provider', COALESCE(p_provider, v_reserve.provider_name),
            'bill_category', COALESCE(p_bill_category, v_reserve.bill_type),
            'bill_reference', COALESCE(NULLIF(trim(p_reference), ''), NULLIF(trim(v_reserve.metadata->>'reference'), ''), NULLIF(trim(v_reserve.metadata->>'bill_reference'), '')),
            'source_wallet_role', v_source_wallet_role,
            'source_kind', NULLIF(v_source_kind, ''),
            'reserve_balance_before', v_locked_balance,
            'reserve_balance_after', v_reserve_balance_after
        )),
        'PLANNED',
        'PROTECTED',
        'BILL_RESERVE_PAYMENT'
    )
    RETURNING * INTO v_transaction;

    UPDATE public.bill_reserves
       SET locked_balance = v_reserve_balance_after,
           updated_at = NOW()
     WHERE id = v_reserve.id
       AND user_id = p_user_id
    RETURNING to_jsonb(bill_reserves.*) INTO v_updated_reserve;

    INSERT INTO public.financial_ledger (
        id,
        transaction_id,
        user_id,
        wallet_id,
        bill_reserve_id,
        bucket_type,
        entry_side,
        entry_type,
        amount,
        balance_after,
        description
    ) VALUES (
        gen_random_uuid(),
        v_transaction.id,
        p_user_id,
        v_source_wallet_id,
        v_reserve.id,
        'PLANNED',
        'DEBIT',
        'DEBIT',
        p_amount::text,
        v_reserve_balance_after::text,
        'Bill reserve payment debit: ' || COALESCE(p_provider, v_reserve.provider_name, 'Provider')
    );

    RETURN jsonb_build_object(
        'success', true,
        'transaction', to_jsonb(v_transaction),
        'reserve', v_updated_reserve,
        'funding_mode', 'RESERVE',
        'reserve_balance', v_reserve_balance_after
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- User Registration Handler
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
DECLARE
    new_user_id UUID;
    new_customer_id TEXT;
    encrypted_zero TEXT;
    wallet1_id UUID;
    wallet2_id UUID;
    meta_customer_id TEXT;
    profile_currency TEXT;
    profile_language TEXT;
BEGIN
    new_user_id := NEW.id;
    meta_customer_id := NEW.raw_user_meta_data->>'customer_id';
    profile_currency := COALESCE(NULLIF(UPPER(TRIM(NEW.raw_user_meta_data->>'currency')), ''), 'TZS');
    profile_language := COALESCE(NULLIF(NEW.raw_user_meta_data->>'language', ''), 'en');
    
    IF meta_customer_id IS NOT NULL THEN
        new_customer_id := meta_customer_id;
    ELSE
        new_customer_id := 'OB' || to_char(NOW(), 'YY') || '-' || 
                           (floor(random() * 9000 + 1000)::text) || '-' || 
                           (floor(random() * 9000 + 1000)::text);
    END IF;
    
    encrypted_zero := 'enc_v2_eyJ2ZXJzaW9uIjoxLCJpdiI6IkFBQUFBQUFBQUFBQSIsImNpcGhlcnRleHQiOiJBQUFBQUFBQUFBQUEiLCJ0YWciOiJBQUFBQUFBQUFBQUEiLCJ0aW1lc3RhbXAiOjAsImtleUlkIjoicC1ub2RlLWFjdGl2ZSIsImFsZ29yaXRobSI6IkFFUy1HQ00tMjU2In0='; 
    
    wallet1_id := md5(new_user_id::text || 'Orbi')::uuid;
    wallet2_id := md5(new_user_id::text || 'PaySafe')::uuid;

    INSERT INTO public.users (
        id, email, full_name, customer_id, phone, nationality, address, currency, preferred_currency,
        country_code, country_name, dial_code, language, registry_type, role, app_origin, fcm_token, metadata
    )
    VALUES (
        new_user_id,
        NEW.email,
        NEW.raw_user_meta_data->>'full_name',
        new_customer_id,
        NEW.raw_user_meta_data->>'phone',
        COALESCE(NEW.raw_user_meta_data->>'nationality', 'Tanzania'),
        NEW.raw_user_meta_data->>'address',
        profile_currency,
        COALESCE(NULLIF(UPPER(TRIM(NEW.raw_user_meta_data->>'preferred_currency')), ''), profile_currency),
        NEW.raw_user_meta_data->>'country_code',
        NEW.raw_user_meta_data->>'country_name',
        NEW.raw_user_meta_data->>'dial_code',
        profile_language,
        COALESCE(NEW.raw_user_meta_data->>'registry_type', 'CONSUMER'),
        COALESCE(NEW.raw_user_meta_data->>'role', 'USER'),
        COALESCE(NEW.raw_user_meta_data->>'app_origin', 'OBI_INSTITUTIONAL_CORE_V25'),
        NEW.raw_user_meta_data->>'fcm_token',
        jsonb_build_object('transfer_card', jsonb_build_object(
            'holder_name', NEW.raw_user_meta_data->>'full_name',
            'card_number_masked', new_customer_id,
            'brand', 'mastercard_style',
            'status', 'ready',
            'provisioned_at', NOW(),
            'product_name', 'Orbi'
        )) || COALESCE(NEW.raw_user_meta_data, '{}'::jsonb)
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = COALESCE(EXCLUDED.full_name, public.users.full_name),
        customer_id = COALESCE(public.users.customer_id, EXCLUDED.customer_id),
        phone = COALESCE(EXCLUDED.phone, public.users.phone),
        nationality = COALESCE(EXCLUDED.nationality, public.users.nationality),
        address = COALESCE(EXCLUDED.address, public.users.address),
        currency = COALESCE(EXCLUDED.currency, public.users.currency),
        preferred_currency = COALESCE(EXCLUDED.preferred_currency, public.users.preferred_currency),
        country_code = COALESCE(EXCLUDED.country_code, public.users.country_code),
        country_name = COALESCE(EXCLUDED.country_name, public.users.country_name),
        dial_code = COALESCE(EXCLUDED.dial_code, public.users.dial_code),
        language = COALESCE(EXCLUDED.language, public.users.language),
        registry_type = COALESCE(EXCLUDED.registry_type, public.users.registry_type),
        role = COALESCE(EXCLUDED.role, public.users.role),
        app_origin = COALESCE(EXCLUDED.app_origin, public.users.app_origin),
        fcm_token = COALESCE(EXCLUDED.fcm_token, public.users.fcm_token),
        metadata = COALESCE(public.users.metadata, '{}'::jsonb) || EXCLUDED.metadata;

    INSERT INTO public.platform_vaults (
        id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon, metadata
    )
    VALUES (
        wallet1_id, new_user_id, 'OPERATING', 'Orbi', 0, encrypted_zero, profile_currency, '#10B981', 'credit-card',
        jsonb_build_object(
            'linked_customer_id', new_customer_id,
            'account_number', new_customer_id,
            'display_name', NEW.raw_user_meta_data->>'full_name',
            'card_type', 'Virtual Master'
        )
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (
        id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon, metadata
    )
    VALUES (
        wallet2_id, new_user_id, 'INTERNAL_TRANSFER', 'PaySafe', 0, encrypted_zero, profile_currency, '#6366F1', 'shield-check',
        jsonb_build_object(
            'is_secure_escrow', true,
            'slogan', 'Secure Internal Transfers',
            'display_mode', 'mask',
            'account_number', 'ESC-' || new_customer_id
        )
    )
    ON CONFLICT (id) DO NOTHING;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 4. TRIGGERS
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. RLS POLICIES (IDEMPOTENT)
DO $$ 
BEGIN
    -- Enable RLS for all tables
    ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.staff ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.tenant_users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.tenant_settlements ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.behavior_profiles ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.payment_orders ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.settlement_payouts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.financial_ledger ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.financial_partners ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.provider_config_versions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.provider_performance_metrics ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fx_corridors ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fx_provider_health ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fx_treasury_exposure_limits ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fx_reconciliation_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.payment_rail_capabilities ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.institutional_payment_accounts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.external_fund_movements ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.settlement_lifecycle ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.provider_routing_rules ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.inbound_sms_messages ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.offline_transaction_sessions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.outbound_sms_messages ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.system_nodes ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.chargeback_cases ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.payment_reviews ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.payment_metrics_snapshots ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.transaction_status_logs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.ctr_reports ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.digital_merchants ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.system_catalog ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.reported_issues ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.ai_reports ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.rule_violations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.security_rules ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.staff_issues ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.audit_trail ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.operator_alerts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.api_gateway_security_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.api_gateway_quarantines ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.approval_requests ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.legal_holds ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.infra_system_matrix ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.infra_app_tokens ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.infra_tx_limits ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.user_messages ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.regulatory_config ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.transfer_tax_rules ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.wallets ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.ent_system_vaults ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.platform_vaults ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.staff_messages ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.goals ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.infra_snapshots ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.platform_configs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.app_registry ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.provider_anomalies ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.kyc_requests ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.user_documents ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fee_correction_rules ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.fee_correction_logs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.item_reconciliation_audit ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.organization_role_definitions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.organization_role_change_requests ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.escrow_agreements ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.treasury_policies ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.treasury_approvers ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.budget_alerts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.reconciliation_reports ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.schema_migrations ENABLE ROW LEVEL SECURITY;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Drop and Recreate Policies to ensure latest logic
DROP POLICY IF EXISTS "Users view own organization" ON public.organizations;
CREATE POLICY "Users view own organization" ON public.organizations 
    FOR SELECT USING (id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()));

DROP POLICY IF EXISTS organization_role_definitions_service_role ON public.organization_role_definitions;
CREATE POLICY organization_role_definitions_service_role ON public.organization_role_definitions
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS organization_role_change_requests_service_role ON public.organization_role_change_requests;
CREATE POLICY organization_role_change_requests_service_role ON public.organization_role_change_requests
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS "Users view corporate goals" ON public.goals;
DROP POLICY IF EXISTS "Users manage own goals" ON public.goals;
CREATE POLICY "Users view corporate goals" ON public.goals 
    FOR SELECT USING (
        user_id = auth.uid() OR 
        (is_corporate = true AND organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()))
    );

CREATE POLICY "Users manage own goals" ON public.goals
    FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view corporate budgets" ON public.categories;
CREATE POLICY "Users view corporate budgets" ON public.categories 
    FOR SELECT USING (
        user_id = auth.uid() OR 
        (is_corporate = true AND organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid()))
    );

DROP POLICY IF EXISTS "Users manage own categories" ON public.categories;
CREATE POLICY "Users manage own categories" ON public.categories
    FOR ALL USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users manage own tasks" ON public.tasks;
CREATE POLICY "Users manage own tasks" ON public.tasks
    FOR ALL USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role category bypass" ON public.categories;
CREATE POLICY "Service role category bypass" ON public.categories
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role task bypass" ON public.tasks;
CREATE POLICY "Service role task bypass" ON public.tasks
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Forensic Ledger Read" ON public.audit_trail;
CREATE POLICY "Forensic Ledger Read" ON public.audit_trail FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "Audit WORM Write" ON public.audit_trail;
CREATE POLICY "Audit WORM Write" ON public.audit_trail FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

-- SYSTEM BYPASS: Ensure service_role (Admin Client) can always manage audit trails
DROP POLICY IF EXISTS "System bypass audit trail" ON public.audit_trail;
CREATE POLICY "System bypass audit trail" ON public.audit_trail FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Operator alert read" ON public.operator_alerts;
CREATE POLICY "Operator alert read" ON public.operator_alerts FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT', 'CUSTOMER_CARE'));

DROP POLICY IF EXISTS "Operator alert system write" ON public.operator_alerts;
CREATE POLICY "Operator alert system write" ON public.operator_alerts FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "API gateway security event read" ON public.api_gateway_security_events;
CREATE POLICY "API gateway security event read" ON public.api_gateway_security_events
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT'));

DROP POLICY IF EXISTS "API gateway security event system write" ON public.api_gateway_security_events;
CREATE POLICY "API gateway security event system write" ON public.api_gateway_security_events
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "API gateway quarantine read" ON public.api_gateway_quarantines;
CREATE POLICY "API gateway quarantine read" ON public.api_gateway_quarantines
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT'));

DROP POLICY IF EXISTS "API gateway quarantine system write" ON public.api_gateway_quarantines;
CREATE POLICY "API gateway quarantine system write" ON public.api_gateway_quarantines
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users create transactions" ON public.transactions;

DROP POLICY IF EXISTS "Users view own transactions" ON public.transactions;
CREATE POLICY "Users view own transactions" ON public.transactions FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role transaction bypass" ON public.transactions;
CREATE POLICY "Service role transaction bypass" ON public.transactions FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin manage institutional accounts" ON public.institutional_payment_accounts;
CREATE POLICY "Admin manage institutional accounts" ON public.institutional_payment_accounts
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role institutional account bypass" ON public.institutional_payment_accounts;
CREATE POLICY "Service role institutional account bypass" ON public.institutional_payment_accounts
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own external fund movements" ON public.external_fund_movements;
CREATE POLICY "Users view own external fund movements" ON public.external_fund_movements
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users create own external fund movements" ON public.external_fund_movements;
CREATE POLICY "Users create own external fund movements" ON public.external_fund_movements
    FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admin view external fund movements" ON public.external_fund_movements;
CREATE POLICY "Admin view external fund movements" ON public.external_fund_movements
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role external fund movement bypass" ON public.external_fund_movements;
CREATE POLICY "Service role external fund movement bypass" ON public.external_fund_movements
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own settlement lifecycle" ON public.settlement_lifecycle;
CREATE POLICY "Users view own settlement lifecycle"
ON public.settlement_lifecycle
FOR SELECT
USING (
    EXISTS (
        SELECT 1
        FROM public.transactions t
        WHERE t.id = settlement_lifecycle.transaction_id
          AND t.user_id = auth.uid()
    )
    OR EXISTS (
        SELECT 1
        FROM public.external_fund_movements efm
        WHERE efm.id = settlement_lifecycle.external_movement_id
          AND efm.user_id = auth.uid()
    )
);

DROP POLICY IF EXISTS "Admin view settlement lifecycle" ON public.settlement_lifecycle;
CREATE POLICY "Admin view settlement lifecycle"
ON public.settlement_lifecycle
FOR SELECT
USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role settlement lifecycle bypass" ON public.settlement_lifecycle;
CREATE POLICY "Service role settlement lifecycle bypass"
ON public.settlement_lifecycle
FOR ALL TO service_role
USING (true)
WITH CHECK (true);


DROP POLICY IF EXISTS "Admin manage provider routing rules" ON public.provider_routing_rules;
CREATE POLICY "Admin manage provider routing rules" ON public.provider_routing_rules
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role provider routing bypass" ON public.provider_routing_rules;
CREATE POLICY "Service role provider routing bypass" ON public.provider_routing_rules
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Authenticated read active fx corridors" ON public.fx_corridors;
CREATE POLICY "Authenticated read active fx corridors" ON public.fx_corridors
    FOR SELECT USING (status = 'ACTIVE');

DROP POLICY IF EXISTS "Admin manage fx corridors" ON public.fx_corridors;
CREATE POLICY "Admin manage fx corridors" ON public.fx_corridors
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role fx corridors bypass" ON public.fx_corridors;
CREATE POLICY "Service role fx corridors bypass" ON public.fx_corridors
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin view fx provider health" ON public.fx_provider_health;
CREATE POLICY "Admin view fx provider health" ON public.fx_provider_health
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE', 'AUDIT', 'RISK_OFFICER'));

DROP POLICY IF EXISTS "Service role fx provider health bypass" ON public.fx_provider_health;
CREATE POLICY "Service role fx provider health bypass" ON public.fx_provider_health
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin manage fx exposure limits" ON public.fx_treasury_exposure_limits;
CREATE POLICY "Admin manage fx exposure limits" ON public.fx_treasury_exposure_limits
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE', 'RISK_OFFICER'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE', 'RISK_OFFICER'));

DROP POLICY IF EXISTS "Service role fx exposure limits bypass" ON public.fx_treasury_exposure_limits;
CREATE POLICY "Service role fx exposure limits bypass" ON public.fx_treasury_exposure_limits
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin view fx reconciliation events" ON public.fx_reconciliation_events;
CREATE POLICY "Admin view fx reconciliation events" ON public.fx_reconciliation_events
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT', 'FINANCE', 'RISK_OFFICER'));

DROP POLICY IF EXISTS "Service role fx reconciliation events bypass" ON public.fx_reconciliation_events;
CREATE POLICY "Service role fx reconciliation events bypass" ON public.fx_reconciliation_events
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Authenticated read active payment rail capabilities" ON public.payment_rail_capabilities;
CREATE POLICY "Authenticated read active payment rail capabilities" ON public.payment_rail_capabilities
    FOR SELECT USING (status = 'ACTIVE');

DROP POLICY IF EXISTS "Admin manage payment rail capabilities" ON public.payment_rail_capabilities;
CREATE POLICY "Admin manage payment rail capabilities" ON public.payment_rail_capabilities
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role payment rail capability bypass" ON public.payment_rail_capabilities;
CREATE POLICY "Service role payment rail capability bypass" ON public.payment_rail_capabilities
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin manage provider config versions" ON public.provider_config_versions;
CREATE POLICY "Admin manage provider config versions" ON public.provider_config_versions
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE'));

DROP POLICY IF EXISTS "Service role provider config version bypass" ON public.provider_config_versions;
CREATE POLICY "Service role provider config version bypass" ON public.provider_config_versions
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin view provider performance metrics" ON public.provider_performance_metrics;
CREATE POLICY "Admin view provider performance metrics" ON public.provider_performance_metrics
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'FINANCE', 'AUDIT'));

DROP POLICY IF EXISTS "Service role provider performance bypass" ON public.provider_performance_metrics;
CREATE POLICY "Service role provider performance bypass" ON public.provider_performance_metrics
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admin manage schema migrations" ON public.schema_migrations;
CREATE POLICY "Admin manage schema migrations" ON public.schema_migrations
    FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT'))
    WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT'));

DROP POLICY IF EXISTS "Service role schema migrations bypass" ON public.schema_migrations;
CREATE POLICY "Service role schema migrations bypass" ON public.schema_migrations
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role inbound sms bypass" ON public.inbound_sms_messages;
CREATE POLICY "Service role inbound sms bypass" ON public.inbound_sms_messages
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role offline session bypass" ON public.offline_transaction_sessions;
CREATE POLICY "Service role offline session bypass" ON public.offline_transaction_sessions
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role outbound sms bypass" ON public.outbound_sms_messages;
CREATE POLICY "Service role outbound sms bypass" ON public.outbound_sms_messages
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Workforce Consumer Access" ON public.users;
CREATE POLICY "Workforce Consumer Access" ON public.users FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));

DROP POLICY IF EXISTS "Consumer Self Management" ON public.users;
CREATE POLICY "Consumer Self Management" ON public.users FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Admins manage workforce" ON public.staff;
CREATE POLICY "Admins manage workforce" ON public.staff FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN'));

DROP POLICY IF EXISTS "Staff visible to themselves" ON public.staff;
CREATE POLICY "Staff visible to themselves" ON public.staff FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users manage own wallets" ON public.wallets;
DROP POLICY IF EXISTS "Users view own wallets" ON public.wallets;
CREATE POLICY "Users view own wallets" ON public.wallets FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users manage own vaults" ON public.platform_vaults;
DROP POLICY IF EXISTS "Users view own vaults" ON public.platform_vaults;
CREATE POLICY "Users view own vaults" ON public.platform_vaults FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role vault bypass" ON public.platform_vaults;
CREATE POLICY "Service role vault bypass" ON public.platform_vaults FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own messages" ON public.user_messages;
CREATE POLICY "Users view own messages" ON public.user_messages FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Staff view messages" ON public.staff_messages;
CREATE POLICY "Staff view messages" ON public.staff_messages FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE', 'AUDIT'));

DROP POLICY IF EXISTS "Admin Node Management" ON public.infra_system_matrix;
CREATE POLICY "Admin Node Management" ON public.infra_system_matrix FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'IT'));

DROP POLICY IF EXISTS "Admin manage regulatory" ON public.regulatory_config;
CREATE POLICY "Admin manage regulatory" ON public.regulatory_config FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT'));

DROP POLICY IF EXISTS "Admins manage KYC requests" ON public.kyc_requests;
CREATE POLICY "Admins manage KYC requests" ON public.kyc_requests FOR ALL USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'CUSTOMER_CARE'));

DROP POLICY IF EXISTS "Admins view fee logs" ON public.fee_correction_logs;
CREATE POLICY "Admins view fee logs" ON public.fee_correction_logs FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'FINANCE', 'AUDIT'));

DROP POLICY IF EXISTS "Admins view reconciliation audits" ON public.item_reconciliation_audit;
CREATE POLICY "Admins view reconciliation audits" ON public.item_reconciliation_audit FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "Admins insert reconciliation audits" ON public.item_reconciliation_audit;
CREATE POLICY "Admins insert reconciliation audits" ON public.item_reconciliation_audit FOR INSERT WITH CHECK ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'IT', 'AUDIT'));

-- SYSTEM BYPASS: Ensure service_role (Admin Client) can always manage reconciliation logs
DROP POLICY IF EXISTS "System bypass reconciliation" ON public.item_reconciliation_audit;
CREATE POLICY "System bypass reconciliation" ON public.item_reconciliation_audit FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admins view reconciliation reports" ON public.reconciliation_reports;
CREATE POLICY "Admins view reconciliation reports" ON public.reconciliation_reports 
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN', 'AUDIT'));

DROP POLICY IF EXISTS "System manage reconciliation reports" ON public.reconciliation_reports;
CREATE POLICY "System manage reconciliation reports" ON public.reconciliation_reports 
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Tenant members read tenants" ON public.tenants;
CREATE POLICY "Tenant members read tenants" ON public.tenants
    FOR SELECT USING (id IN (SELECT tenant_id FROM public.tenant_users WHERE user_id = auth.uid() AND status = 'ACTIVE'));

DROP POLICY IF EXISTS "Tenant users read own memberships" ON public.tenant_users;
CREATE POLICY "Tenant users read own memberships" ON public.tenant_users
    FOR SELECT USING (user_id = auth.uid());

DROP POLICY IF EXISTS "Tenant owners manage API keys" ON public.api_keys;
CREATE POLICY "Tenant owners manage API keys" ON public.api_keys
    FOR SELECT USING (
        tenant_id IN (
            SELECT tenant_id FROM public.tenant_users
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin') AND status = 'ACTIVE'
        )
    );

DROP POLICY IF EXISTS "Tenant members read settlement config" ON public.tenant_settlements;
CREATE POLICY "Tenant members read settlement config" ON public.tenant_settlements
    FOR SELECT USING (tenant_id IN (SELECT tenant_id FROM public.tenant_users WHERE user_id = auth.uid() AND status = 'ACTIVE'));

DROP POLICY IF EXISTS "Tenant members read settlement payouts" ON public.settlement_payouts;
CREATE POLICY "Tenant members read settlement payouts" ON public.settlement_payouts
    FOR SELECT USING (tenant_id IN (SELECT tenant_id FROM public.tenant_users WHERE user_id = auth.uid() AND status = 'ACTIVE'));

DROP POLICY IF EXISTS "Users manage own behavior profile" ON public.behavior_profiles;
CREATE POLICY "Users manage own behavior profile" ON public.behavior_profiles
    FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "Users read own payment orders" ON public.payment_orders;
CREATE POLICY "Users read own payment orders" ON public.payment_orders
    FOR SELECT USING (user_id = auth.uid());

DROP POLICY IF EXISTS "System bypass tenants" ON public.tenants;
CREATE POLICY "System bypass tenants" ON public.tenants FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass tenant users" ON public.tenant_users;
CREATE POLICY "System bypass tenant users" ON public.tenant_users FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass api keys" ON public.api_keys;
CREATE POLICY "System bypass api keys" ON public.api_keys FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass tenant settlements" ON public.tenant_settlements;
CREATE POLICY "System bypass tenant settlements" ON public.tenant_settlements FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass settlement payouts" ON public.settlement_payouts;
CREATE POLICY "System bypass settlement payouts" ON public.settlement_payouts FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass payment orders" ON public.payment_orders;
CREATE POLICY "System bypass payment orders" ON public.payment_orders FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass behavior profiles" ON public.behavior_profiles;
CREATE POLICY "System bypass behavior profiles" ON public.behavior_profiles FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "System bypass ent system vaults" ON public.ent_system_vaults;
CREATE POLICY "System bypass ent system vaults" ON public.ent_system_vaults FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ==========================================
-- NEXT-GEN SECURITY ARCHITECTURE (V26)
-- ==========================================

-- Layer 1: Passkeys (WebAuthn)
CREATE TABLE IF NOT EXISTS public.passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    transports JSONB DEFAULT '[]'::jsonb,
    device_type TEXT,
    backed_up BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_passkey_user ON public.passkeys(user_id);

-- Layer 2: Device Fingerprinting
CREATE TABLE IF NOT EXISTS public.device_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    platform TEXT,
    os_version TEXT,
    browser TEXT,
    ip_address TEXT,
    is_trusted BOOLEAN DEFAULT FALSE,
    risk_score NUMERIC DEFAULT 0,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, device_hash)
);
CREATE INDEX IF NOT EXISTS idx_device_fp_user ON public.device_fingerprints(user_id);

-- Layer 3: Behavioral Biometrics
CREATE TABLE IF NOT EXISTS public.behavioral_biometrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT,
    typing_speed NUMERIC,
    swipe_velocity NUMERIC,
    touch_pressure NUMERIC,
    anomaly_score NUMERIC DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_behavior_user ON public.behavioral_biometrics(user_id);

-- Layer 5 & 6: AI Fraud & Risk Logs
CREATE TABLE IF NOT EXISTS public.ai_risk_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    risk_score NUMERIC NOT NULL,
    ai_confidence NUMERIC,
    features JSONB DEFAULT '{}'::jsonb,
    action_taken TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_risk_user ON public.ai_risk_logs(user_id);

-- Layer 8: Hardware Security Modules (HSM) / Secure Enclave
CREATE TABLE IF NOT EXISTS public.secure_enclave_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES public.device_fingerprints(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    attestation_token TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enclave_user ON public.secure_enclave_keys(user_id);

-- Security Tables
ALTER TABLE public.passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_biometrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_risk_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secure_enclave_keys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users manage own passkeys" ON public.passkeys;
CREATE POLICY "Users manage own passkeys" ON public.passkeys FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own device fingerprints" ON public.device_fingerprints;
CREATE POLICY "Users view own device fingerprints" ON public.device_fingerprints FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own behavioral biometrics" ON public.behavioral_biometrics;
CREATE POLICY "Users view own behavioral biometrics" ON public.behavioral_biometrics FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users view own ai risk logs" ON public.ai_risk_logs;
CREATE POLICY "Users view own ai risk logs" ON public.ai_risk_logs FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users manage own secure enclave keys" ON public.secure_enclave_keys;
CREATE POLICY "Users manage own secure enclave keys" ON public.secure_enclave_keys FOR ALL USING (auth.uid() = user_id);

-- System bypass for security tables
DROP POLICY IF EXISTS "Service role passkeys bypass" ON public.passkeys;
CREATE POLICY "Service role passkeys bypass" ON public.passkeys FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role device fingerprints bypass" ON public.device_fingerprints;
CREATE POLICY "Service role device fingerprints bypass" ON public.device_fingerprints FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role behavioral biometrics bypass" ON public.behavioral_biometrics;
CREATE POLICY "Service role behavioral biometrics bypass" ON public.behavioral_biometrics FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role ai risk logs bypass" ON public.ai_risk_logs;
CREATE POLICY "Service role ai risk logs bypass" ON public.ai_risk_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role secure enclave keys bypass" ON public.secure_enclave_keys;
CREATE POLICY "Service role secure enclave keys bypass" ON public.secure_enclave_keys FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Escrow Agreements
DROP POLICY IF EXISTS "Users view own escrow agreements" ON public.escrow_agreements;
CREATE POLICY "Users view own escrow agreements" ON public.escrow_agreements
    FOR SELECT USING (auth.uid() = sender_id OR auth.uid() = receiver_id);

-- Treasury Policies
DROP POLICY IF EXISTS "Org members view treasury policies" ON public.treasury_policies;
CREATE POLICY "Org members view treasury policies" ON public.treasury_policies
    FOR SELECT USING (
        organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid())
    );

-- Treasury Approvers
DROP POLICY IF EXISTS "Approvers view assignments" ON public.treasury_approvers;
CREATE POLICY "Approvers view assignments" ON public.treasury_approvers
    FOR SELECT USING (
        organization_id IN (SELECT organization_id FROM public.users WHERE id = auth.uid())
    );

-- 6. INDEXES
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON public.transactions(user_id, date);
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON public.financial_ledger(transaction_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_wallet ON public.transactions(user_id, wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_created ON public.transactions(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_to_wallet_created ON public.transactions(to_wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_created ON public.financial_ledger(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_wallet_tx ON public.financial_ledger(wallet_id, transaction_id);
CREATE INDEX IF NOT EXISTS idx_goals_source_wallet ON public.goals(source_wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status_updated ON public.transactions(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_review_timeout ON public.transactions(updated_at DESC) WHERE status = 'held_for_review';
CREATE INDEX IF NOT EXISTS idx_transactions_processing_timeout ON public.transactions(updated_at DESC) WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_transaction_events_transaction_created ON public.transaction_events(transaction_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_transaction_timestamp ON public.audit_trail(transaction_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_event_timestamp ON public.audit_trail(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_actor_timestamp ON public.audit_trail(actor_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_operator_alerts_status_created ON public.operator_alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_alerts_event_created ON public.operator_alerts(event_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_alerts_transaction_created ON public.operator_alerts(transaction_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_created ON public.api_gateway_security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_actor_created ON public.api_gateway_security_events(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_route_group_created ON public.api_gateway_security_events(route_group, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_action_created ON public.api_gateway_security_events(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_quarantines_active ON public.api_gateway_quarantines(status, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_quarantines_actor_created ON public.api_gateway_quarantines(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_quarantines_scope_key ON public.api_gateway_quarantines(scope_key);
CREATE INDEX IF NOT EXISTS idx_tenant_users_user_status ON public.tenant_users(user_id, status, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_role ON public.tenant_users(tenant_id, role, status);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_status ON public.api_keys(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_settlements_tenant_status ON public.tenant_settlements(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_settlement_payouts_tenant_created ON public.settlement_payouts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payment_orders_user_created ON public.payment_orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payment_orders_provider_status ON public.payment_orders(provider_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_user_updated ON public.behavior_profiles(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_wallets_tenant_status ON public.wallets(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_transactions_tenant_settlement ON public.transactions(tenant_id, settlement_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_system_vaults_active ON public.ent_system_vaults(vault_purpose, is_active);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_role ON public.institutional_payment_accounts(role, currency, status);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_provider ON public.institutional_payment_accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_user_date ON public.external_fund_movements(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_transaction ON public.external_fund_movements(transaction_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_provider_status ON public.external_fund_movements(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_status_updated ON public.external_fund_movements(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_lookup_basic ON public.provider_routing_rules(rail, operation_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_inbound_sms_request_id ON public.inbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_request_id ON public.offline_transaction_sessions(request_id);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_status ON public.offline_transaction_sessions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_outbound_sms_request_id ON public.outbound_sms_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_wallets_user ON public.wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_wallets_lock_reason ON public.wallets(status, is_locked, locked_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_vaults_lock_reason ON public.platform_vaults(status, is_locked, locked_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_user ON public.goals(user_id);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_user ON public.external_fund_movements(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_provider ON public.external_fund_movements(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_external_fund_movements_reference ON public.external_fund_movements(external_reference);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_tx ON public.settlement_lifecycle(transaction_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_external_movement ON public.settlement_lifecycle(external_movement_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_merchant_settlement ON public.settlement_lifecycle(merchant_settlement_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_provider ON public.settlement_lifecycle(provider_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_stage ON public.settlement_lifecycle(stage);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_status ON public.settlement_lifecycle(status);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_created_at ON public.settlement_lifecycle(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_batch ON public.settlement_lifecycle(settlement_batch_id);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_provider_reference ON public.settlement_lifecycle(provider_reference);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_lifecycle_key ON public.settlement_lifecycle(lifecycle_key);
CREATE INDEX IF NOT EXISTS idx_provider_routing_rules_lookup ON public.provider_routing_rules(rail, operation_code, currency, country_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_platform_fee_configs_lookup ON public.platform_fee_configs(flow_code, status, currency, provider_id, rail, channel, direction, transaction_model, category_code, category_id, operation_type, transaction_type, priority);
CREATE INDEX IF NOT EXISTS idx_platform_fee_configs_model ON public.platform_fee_configs(flow_code, transaction_model, status, priority);
CREATE INDEX IF NOT EXISTS idx_platform_fee_configs_category_code ON public.platform_fee_configs(flow_code, category_code, status, priority);
CREATE INDEX IF NOT EXISTS idx_platform_fee_configs_category_id ON public.platform_fee_configs(flow_code, category_id, status, priority);
COMMENT ON COLUMN public.platform_fee_configs.transaction_model IS 'Canonical fee model resolved from transaction type, rail, and service context, e.g. WALLET_TRANSFER, BILL_PAYMENT, EXTERNAL_MOBILE_MONEY, AGENT_CASH.';
COMMENT ON COLUMN public.platform_fee_configs.category_code IS 'Optional normalized business category code for fee specialization, e.g. ELECTRICITY, AIRTIME, SCHOOL_FEES, MERCHANT_GROCERY.';
COMMENT ON COLUMN public.platform_fee_configs.category_id IS 'Optional application category id for exact category-level fee specialization.';
CREATE INDEX IF NOT EXISTS idx_service_commissions_actor ON public.service_commissions(actor_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_commissions_source ON public.service_commissions(source_transaction_id);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_owner ON public.agent_transactions(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_owner ON public.merchant_transactions(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_categories_user ON public.categories(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON public.tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_user_messages_user_read ON public.user_messages(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_user_id ON public.kyc_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_status ON public.kyc_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_devices_user ON public.user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON public.user_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_devices_user_trust ON public.user_devices(user_id, is_trusted, status);
CREATE INDEX IF NOT EXISTS idx_user_documents_user ON public.user_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON public.user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device_fingerprint ON public.user_sessions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON public.user_sessions(user_id, is_revoked, last_active_at);
CREATE INDEX IF NOT EXISTS idx_escrow_tx_id ON public.escrow_agreements(transaction_id);
CREATE INDEX IF NOT EXISTS idx_escrow_sender ON public.escrow_agreements(sender_id);
CREATE INDEX IF NOT EXISTS idx_escrow_receiver ON public.escrow_agreements(receiver_id);
-- Mobile read model / GraphQL snapshot indexes.
-- These keep app boot, dashboard refresh, transaction history, wealth, and PaySafe reads fast
-- without changing the audited write paths.
CREATE INDEX IF NOT EXISTS idx_transactions_user_created_mobile ON public.transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_user_status_created_mobile ON public.transactions(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transaction_quotes_user_status_updated_mobile ON public.transaction_quotes(user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_financial_ledger_user_created_mobile ON public.financial_ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_vaults_user_role_updated_mobile ON public.platform_vaults(user_id, vault_role, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_wallets_user_tier_updated_mobile ON public.wallets(user_id, management_tier, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_escrow_agreements_sender_status_created_mobile ON public.escrow_agreements(sender_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_escrow_agreements_receiver_status_created_mobile ON public.escrow_agreements(receiver_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_user_updated_mobile ON public.goals(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_categories_user_period_created_mobile ON public.categories(user_id, budget_period, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bill_reserves_user_status_updated_mobile ON public.bill_reserves(user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pots_owner_status_updated_mobile ON public.shared_pots(owner_user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_members_user_status_created_mobile ON public.shared_pot_members(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budgets_owner_status_updated_mobile ON public.shared_budgets(owner_user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_budget_members_user_status_updated_mobile ON public.shared_budget_members(user_id, status, updated_at DESC);
-- Enterprise critical read indexes.
-- These cover high-traffic identity, session, realtime, messaging, risk,
-- provider, settlement, merchant, BaaS, and operator-control reads.
CREATE INDEX IF NOT EXISTS idx_users_customer_status_mobile ON public.users(customer_id, account_status);
CREATE INDEX IF NOT EXISTS idx_users_email_status_mobile ON public.users(email, account_status) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_registry_status_active_mobile ON public.users(registry_type, account_status, last_active DESC);
CREATE INDEX IF NOT EXISTS idx_users_phone_status_mobile ON public.users(phone, account_status) WHERE phone IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_kyc_status_level_mobile ON public.users(kyc_status, kyc_level, last_active DESC);
CREATE INDEX IF NOT EXISTS idx_staff_role_status_active_mobile ON public.staff(role, account_status, last_active DESC);
CREATE INDEX IF NOT EXISTS idx_tenants_status_updated_mobile ON public.tenants(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_public_status_mobile ON public.api_keys(public_key, status);
CREATE INDEX IF NOT EXISTS idx_payment_orders_status_updated_mobile ON public.payment_orders(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_payment_orders_authorization_mobile ON public.payment_orders(authorization_id) WHERE authorization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_status_created_mobile ON public.provider_webhook_events(application_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_replay_mobile ON public.provider_webhook_events(replay_key, application_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_webhook_events_status_reference_mobile ON public.provider_webhook_events(normalized_status, reference, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_user_phase_mobile ON public.settlement_lifecycle(user_id, current_phase, phase_started_at DESC);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_phase_retry_mobile ON public.settlement_lifecycle(current_phase, retry_count, phase_started_at DESC);
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_auto_settle_mobile ON public.settlement_lifecycle(current_phase, auto_settle_at DESC)
    WHERE auto_settle_executed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_settlement_lifecycle_provider_status_mobile ON public.settlement_lifecycle(provider_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_aml_alerts_user_status_created_mobile ON public.aml_alerts(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aml_alerts_status_score_created_mobile ON public.aml_alerts(status, risk_score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_messages_user_category_created_mobile ON public.user_messages(user_id, category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_messages_unread_created_mobile ON public.user_messages(user_id, created_at DESC) WHERE is_read = FALSE;
CREATE INDEX IF NOT EXISTS idx_staff_messages_recipient_created_mobile ON public.staff_messages(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_staff_messages_sender_created_mobile ON public.staff_messages(sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_alerts_severity_status_mobile ON public.operator_alerts(severity, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_alerts_resource_mobile ON public.operator_alerts(resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_trace_mobile ON public.api_gateway_security_events(trace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_security_events_ip_created_mobile ON public.api_gateway_security_events(ip_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_gateway_quarantines_scope_status_mobile ON public.api_gateway_quarantines(route_group, scope_key, status, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_anomalies_user_status_created_mobile ON public.provider_anomalies(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_financial_partners_name_status_mobile ON public.financial_partners(LOWER(name), status, type);
CREATE INDEX IF NOT EXISTS idx_institutional_payment_accounts_provider_role_mobile ON public.institutional_payment_accounts(provider_id, role, status);
CREATE INDEX IF NOT EXISTS idx_inbound_sms_phone_status_created_mobile ON public.inbound_sms_messages(phone_number, parse_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbound_sms_phone_status_created_mobile ON public.outbound_sms_messages(phone_number, send_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_offline_transaction_sessions_user_status_mobile ON public.offline_transaction_sessions(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchants_owner_status_mobile ON public.merchants(owner_user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_wallets_status_balance_mobile ON public.merchant_wallets(merchant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_merchant_status_mobile ON public.merchant_transactions(merchant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_transactions_customer_status_mobile ON public.merchant_transactions(customer_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agents_user_status_mobile ON public.agents(user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_wallets_status_balance_mobile ON public.agent_wallets(agent_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_transactions_agent_status_mobile ON public.agent_transactions(agent_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_actor_links_customer_status_mobile ON public.service_actor_customer_links(customer_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_actor_links_actor_status_mobile ON public.service_actor_customer_links(actor_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_commissions_customer_status_mobile ON public.service_commissions(customer_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_user_status_mobile ON public.service_access_requests(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_service_access_requests_role_status_mobile ON public.service_access_requests(requested_role, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_kyc_requests_status_submitted_mobile ON public.kyc_requests(status, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_expiry_mobile ON public.user_sessions(user_id, is_revoked, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash_mobile ON public.user_sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_user_devices_status_active_mobile ON public.user_devices(user_id, status, last_active_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_documents_user_status_mobile ON public.user_documents(user_id, status, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_treasury_org ON public.treasury_policies(organization_id);

-- 7. SYSTEM PROVISIONING (IDEMPOTENT)
DO $$
DECLARE
    enc_zero TEXT := 'enc_v2_eyJ2ZXJzaW9uIjoxLCJpdiI6IkFBQUFBQUFBQUFBQSIsImNpcGhlcnRleHQiOiJBQUFBQUFBQUFBQUEiLCJ0YWciOiJBQUFBQUFBQUFBQUEiLCJ0aW1lc3RhbXAiOjAsImtleUlkIjoicC1ub2RlLWFjdGl2ZSIsImFsZ29yaXRobSI6IkFFUy1HQ00tMjU2In0=';
BEGIN
    -- Provision System Vaults

    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000001', NULL, 'ESCROW_VAULT', 'System Escrow Vault', 0, enc_zero, 'USD', '#6366F1', 'shield-check')
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000004', NULL, 'TAX_RESERVE', 'System Tax Reserve', 0, enc_zero, 'USD', '#EF4444', 'landmark')
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.platform_vaults (id, user_id, vault_role, name, balance, encrypted_balance, currency, color, icon)
    VALUES ('00000000-0000-0000-0000-000000000005', NULL, 'FX_CLEARING', 'System FX Clearing', 0, enc_zero, 'USD', '#0EA5E9', 'currency-exchange')
    ON CONFLICT (id) DO NOTHING;

    -- Map System Nodes
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('ESCROW_VAULT', '00000000-0000-0000-0000-000000000001') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('TAX_RESERVE', '00000000-0000-0000-0000-000000000004') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('FX_CLEARING', '00000000-0000-0000-0000-000000000005') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
    INSERT INTO public.system_nodes (node_type, vault_id) VALUES ('GOV_TAX', '00000000-0000-0000-0000-000000000004') ON CONFLICT (node_type) DO UPDATE SET vault_id = EXCLUDED.vault_id;
END $$;

-- 7B. PAYMENT PROVIDER BOOTSTRAP (IDEMPOTENT)
DO $$
BEGIN
    -- Production safety: do not seed placeholder payment providers.
    -- Operators must create real providers, settlement accounts, routing, and fee rules from the Admin Configuration Studio.
    DELETE FROM public.provider_routing_rules
    WHERE provider_id IN (
        '10000000-0000-0000-0000-000000000101',
        '10000000-0000-0000-0000-000000000102',
        '10000000-0000-0000-0000-000000000103',
        '10000000-0000-0000-0000-000000000104'
    )
    OR id IN (
        '10000000-0000-0000-0000-000000000301',
        '10000000-0000-0000-0000-000000000302',
        '10000000-0000-0000-0000-000000000303',
        '10000000-0000-0000-0000-000000000304',
        '10000000-0000-0000-0000-000000000305',
        '10000000-0000-0000-0000-000000000306',
        '10000000-0000-0000-0000-000000000307'
    );

    DELETE FROM public.institutional_payment_accounts
    WHERE provider_id IN (
        '10000000-0000-0000-0000-000000000101',
        '10000000-0000-0000-0000-000000000102',
        '10000000-0000-0000-0000-000000000103',
        '10000000-0000-0000-0000-000000000104'
    )
    OR id BETWEEN '10000000-0000-0000-0000-000000000201'::uuid
          AND '10000000-0000-0000-0000-000000000212'::uuid;

    DELETE FROM public.financial_partners
    WHERE id IN (
        '10000000-0000-0000-0000-000000000101',
        '10000000-0000-0000-0000-000000000102',
        '10000000-0000-0000-0000-000000000103',
        '10000000-0000-0000-0000-000000000104'
    )
    OR api_base_url LIKE 'https://api.example.com/%';

END $$;

WITH base_fee_configs(flow_code, transaction_model, operation_type, direction, rail) AS (
  VALUES
    ('CORE_TRANSACTION', 'CORE_LEDGER', 'CORE_TRANSACTION', 'INTERNAL_TO_INTERNAL', 'WALLET'),
    ('INTERNAL_TRANSFER', 'WALLET_TRANSFER', 'LEDGER_TRANSFER', 'INTERNAL_TO_INTERNAL', 'WALLET'),
    ('EXTERNAL_PAYMENT', 'EXTERNAL_MOBILE_MONEY', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('BILL_PAYMENT', 'BILL_PAYMENT', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('WITHDRAWAL', 'EXTERNAL_MOBILE_MONEY', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('DEPOSIT', 'EXTERNAL_MOBILE_MONEY', 'COLLECTION_REQUEST', 'EXTERNAL_TO_INTERNAL', 'MOBILE_MONEY'),
    ('EXTERNAL_TO_INTERNAL', 'EXTERNAL_MOBILE_MONEY', 'COLLECTION_REQUEST', 'EXTERNAL_TO_INTERNAL', 'MOBILE_MONEY'),
    ('INTERNAL_TO_EXTERNAL', 'EXTERNAL_MOBILE_MONEY', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('EXTERNAL_TO_EXTERNAL', 'EXTERNAL_MOBILE_MONEY', 'TRANSFER_REQUEST', 'EXTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('MERCHANT_PAYMENT', 'MERCHANT_PAYMENT', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('AGENT_CASH_DEPOSIT', 'AGENT_CASH', 'COLLECTION_REQUEST', 'EXTERNAL_TO_INTERNAL', 'MOBILE_MONEY'),
    ('AGENT_CASH_WITHDRAWAL', 'AGENT_CASH', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'MOBILE_MONEY'),
    ('AGENT_REFERRAL_COMMISSION', 'SERVICE_COMMISSION', 'COMMISSION_POSTING', 'INTERNAL_TO_INTERNAL', 'WALLET'),
    ('AGENT_CASH_COMMISSION', 'SERVICE_COMMISSION', 'COMMISSION_POSTING', 'INTERNAL_TO_INTERNAL', 'WALLET'),
    ('CARD_SETTLEMENT', 'CARD_SETTLEMENT', 'SETTLEMENT', 'EXTERNAL_TO_INTERNAL', 'CARD_GATEWAY'),
    ('GATEWAY_SETTLEMENT', 'GATEWAY_SETTLEMENT', 'SETTLEMENT', 'EXTERNAL_TO_INTERNAL', 'WALLET'),
    ('FX_CONVERSION', 'FX_CONVERSION', 'FX_CONVERSION', 'INTERNAL_TO_INTERNAL', 'WALLET'),
    ('TENANT_SETTLEMENT_PAYOUT', 'TENANT_SETTLEMENT_PAYOUT', 'DISBURSEMENT_REQUEST', 'INTERNAL_TO_EXTERNAL', 'BANK'),
    ('SYSTEM_OPERATION', 'SYSTEM_OPERATION', 'SYSTEM_OPERATION', 'INTERNAL_TO_INTERNAL', 'WALLET')
)
INSERT INTO public.platform_fee_configs (
  name,
  flow_code,
  transaction_model,
  operation_type,
  direction,
  rail,
  percentage_rate,
  fixed_amount,
  minimum_fee,
  tax_rate,
  gov_fee_rate,
  stamp_duty_fixed,
  priority,
  status,
  metadata
)
SELECT
  'Base ' || flow_code || ' fee policy',
  flow_code,
  transaction_model,
  operation_type,
  direction,
  rail,
  0,
  0,
  0,
  0,
  0,
  0,
  1000,
  'ACTIVE',
  jsonb_build_object(
    'seeded_by', 'database/main.sql',
    'purpose', 'base production fee policy; update rates in admin/config before monetized launch'
  )
FROM base_fee_configs seed
WHERE NOT EXISTS (
  SELECT 1
  FROM public.platform_fee_configs existing
  WHERE existing.flow_code = seed.flow_code
    AND existing.name = 'Base ' || seed.flow_code || ' fee policy'
);

-- 8. EVENT SOURCING LAYER
CREATE TABLE IF NOT EXISTS public.financial_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL, -- Transaction ID or Wallet ID
    payload JSONB NOT NULL,
    actor TEXT DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_financial_events_aggregate ON public.financial_events(aggregate_id);
CREATE INDEX IF NOT EXISTS idx_financial_events_type ON public.financial_events(event_type);

-- ==========================================
-- ENTERPRISE FALLBACKS (NO-REDIS MODE)
-- ==========================================

-- 1. Database-Backed Idempotency
CREATE TABLE IF NOT EXISTS public.ent_idempotency_keys (
    key TEXT PRIMARY KEY,
    client_id TEXT,
    request_path TEXT,
    status TEXT DEFAULT 'PROCESSING',
    response_status INTEGER,
    response_body JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Database-Backed Distributed Locks
CREATE TABLE IF NOT EXISTS public.ent_locks (
    lock_key TEXT PRIMARY KEY,
    acquired_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 3. Transactional Outbox (EventBus)
CREATE TABLE IF NOT EXISTS public.outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS public.fraud_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    payload JSONB NOT NULL,
    risk_score NUMERIC NOT NULL,
    decision TEXT NOT NULL,
    flags TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE public.fraud_checks
    ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS payload JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS risk_score NUMERIC DEFAULT 0,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_fraud_checks_transaction_id ON public.fraud_checks(transaction_id);
CREATE INDEX IF NOT EXISTS idx_fraud_checks_user_created ON public.fraud_checks(user_id, created_at DESC);

-- PAYMENT CARD PROCESSING (PCI-DSS Compliant)
CREATE TABLE IF NOT EXISTS public.card_tokens (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    masked_card_number TEXT NOT NULL,
    tokenized_card_number TEXT NOT NULL, -- Encrypted
    expiry_month INTEGER NOT NULL,
    expiry_year INTEGER NOT NULL,
    cardholder_name TEXT NOT NULL,
    card_brand TEXT NOT NULL CHECK (card_brand IN ('VISA', 'MASTERCARD', 'AMEX', 'DISCOVERY')),
    card_type TEXT DEFAULT 'CREDIT' CHECK (card_type IN ('CREDIT', 'DEBIT')),
    last_four_digits TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'EXPIRED')),
    encrypted_cvv TEXT, -- Encrypted CVV for one-click payments
    billing_address JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS public.card_transactions (
    id TEXT PRIMARY KEY,
    card_token_id TEXT REFERENCES public.card_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'TZS',
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'AUTHORIZED', 'SETTLED', 'FAILED', 'DECLINED', 'REVERSED')),
    authorization_code TEXT,
    rrn TEXT, -- Retrieval Reference Number
    stan_number TEXT, -- System Trace Audit Number
    response_code TEXT,
    response_message TEXT,
    risk_score NUMERIC DEFAULT 0,
    fraud_flags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    settled_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Card Transaction Audit Trail
CREATE TABLE IF NOT EXISTS public.card_transaction_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    card_transaction_id TEXT REFERENCES public.card_transactions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    actor TEXT DEFAULT 'system',
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Merchant Card Acceptance Settings
CREATE TABLE IF NOT EXISTS public.merchant_card_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE CASCADE,
    min_amount NUMERIC DEFAULT 0,
    max_amount NUMERIC,
    accepted_card_brands TEXT[] DEFAULT ARRAY['VISA', 'MASTERCARD'],
    avs_enabled BOOLEAN DEFAULT TRUE,
    cvv_required BOOLEAN DEFAULT TRUE,
    three_d_secure_enabled BOOLEAN DEFAULT TRUE,
    fraud_check_level TEXT DEFAULT 'MEDIUM' CHECK (fraud_check_level IN ('LOW', 'MEDIUM', 'HIGH')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(merchant_id)
);

-- Card Network Processing Fees
CREATE TABLE IF NOT EXISTS public.card_processing_fees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    card_brand TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    percentage_fee NUMERIC DEFAULT 0.025, -- 2.5% default
    fixed_fee NUMERIC DEFAULT 0.30,
    currency TEXT DEFAULT 'TZS',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for Card Processing
CREATE INDEX IF NOT EXISTS idx_card_tokens_user ON public.card_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_card_tokens_status ON public.card_tokens(status);
CREATE INDEX IF NOT EXISTS idx_card_tokens_fingerprint ON public.card_tokens(fingerprint);
CREATE INDEX IF NOT EXISTS idx_card_transactions_user ON public.card_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_card_token ON public.card_transactions(card_token_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_status ON public.card_transactions(status);
CREATE INDEX IF NOT EXISTS idx_card_transactions_merchant ON public.card_transactions(merchant_id);
CREATE INDEX IF NOT EXISTS idx_card_transactions_created ON public.card_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_card_transaction_audit_user ON public.card_transaction_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_merchant_card_settings_merchant ON public.merchant_card_settings(merchant_id);

-- Enable RLS for Card Tables
ALTER TABLE public.card_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_transaction_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merchant_card_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.card_processing_fees ENABLE ROW LEVEL SECURITY;

-- Card Processing RLS Policies
DROP POLICY IF EXISTS "Users manage own card tokens" ON public.card_tokens;
CREATE POLICY "Users manage own card tokens" ON public.card_tokens
    FOR ALL USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role card tokens bypass" ON public.card_tokens;
CREATE POLICY "Service role card tokens bypass" ON public.card_tokens
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Users view own card transactions" ON public.card_transactions;
CREATE POLICY "Users view own card transactions" ON public.card_transactions
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role card transactions bypass" ON public.card_transactions;
CREATE POLICY "Service role card transactions bypass" ON public.card_transactions
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Admins view card settings" ON public.merchant_card_settings;
CREATE POLICY "Admins view card settings" ON public.merchant_card_settings
    FOR SELECT USING ((SELECT public.get_auth_role()) IN ('SUPER_ADMIN', 'ADMIN'));

CREATE TABLE IF NOT EXISTS public.background_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON public.background_jobs(status);
CREATE INDEX IF NOT EXISTS idx_background_jobs_claim ON public.background_jobs(status, attempts, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_events_pending ON public.outbox_events(status, created_at);

-- 4. JWT Revocation Blocklist
CREATE TABLE IF NOT EXISTS public.revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Keycloak / self-hosted auth compatibility schema
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS orbi_auth;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID,
    aud TEXT DEFAULT 'authenticated',
    role TEXT DEFAULT 'authenticated',
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    encrypted_password TEXT NOT NULL,
    email_confirmed_at TIMESTAMPTZ,
    phone_confirmed_at TIMESTAMPTZ,
    confirmation_sent_at TIMESTAMPTZ,
    recovery_sent_at TIMESTAMPTZ,
    last_sign_in_at TIMESTAMPTZ,
    raw_app_meta_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_user_meta_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION auth.uid()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION auth.role()
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        NULLIF(current_setting('request.jwt.claim.role', true), ''),
        NULLIF(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role',
        'anon'
    )
$$;

CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS JSONB
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
        jsonb_strip_nulls(jsonb_build_object(
            'sub', NULLIF(current_setting('request.jwt.claim.sub', true), ''),
            'role', NULLIF(current_setting('request.jwt.claim.role', true), '')
        )),
        '{}'::jsonb
    )
$$;

CREATE OR REPLACE FUNCTION orbi_auth.set_request_context(
    p_user_id UUID,
    p_role TEXT DEFAULT 'authenticated',
    p_claims JSONB DEFAULT '{}'::jsonb
)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_claims JSONB;
BEGIN
    v_claims := COALESCE(p_claims, '{}'::jsonb)
        || jsonb_build_object(
            'sub', CASE WHEN p_user_id IS NULL THEN NULL ELSE p_user_id::text END,
            'role', COALESCE(NULLIF(p_role, ''), 'authenticated')
        );

    PERFORM set_config('request.jwt.claim.sub', COALESCE(p_user_id::text, ''), true);
    PERFORM set_config('request.jwt.claim.role', COALESCE(NULLIF(p_role, ''), 'authenticated'), true);
    PERFORM set_config('request.jwt.claims', v_claims::text, true);
END
$$;

CREATE TABLE IF NOT EXISTS orbi_auth.refresh_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    device_fingerprint TEXT,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    replaced_by_session_id UUID REFERENCES orbi_auth.refresh_sessions(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orbi_refresh_sessions_user_active
ON orbi_auth.refresh_sessions(user_id, expires_at)
WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_orbi_refresh_sessions_family
ON orbi_auth.refresh_sessions(family_id);

CREATE TABLE IF NOT EXISTS orbi_auth.revoked_access_tokens (
    jti TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE IF EXISTS orbi_auth.revoked_access_tokens
  ALTER COLUMN jti TYPE TEXT USING jti::text;

CREATE INDEX IF NOT EXISTS idx_orbi_revoked_access_tokens_expiry
ON orbi_auth.revoked_access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS orbi_auth.identity_links (
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider_username TEXT,
    provider_email TEXT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_authenticated_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (provider, provider_subject),
    UNIQUE (provider, user_id)
);

CREATE INDEX IF NOT EXISTS idx_orbi_identity_links_user
ON orbi_auth.identity_links(user_id);

REVOKE ALL ON SCHEMA auth FROM PUBLIC;
REVOKE ALL ON SCHEMA orbi_auth FROM PUBLIC;
REVOKE ALL ON orbi_auth.identity_links FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;
GRANT USAGE ON SCHEMA orbi_auth TO service_role;
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.role() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.jwt() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION orbi_auth.set_request_context(UUID, TEXT, JSONB) TO service_role;

-- BEGIN 20260618 SHARED FINANCE AND PAYSAFE HARDENING SYNC

-- BEGIN SYNCED MIGRATION: 20260618_paysafe_escrow_hardening.sql
-- Canonical PaySafe escrow lifecycle.
-- Financial movement and lifecycle state changes remain SQL-authoritative.

ALTER TABLE public.escrow_agreements
    ADD COLUMN IF NOT EXISTS reference_id TEXT,
    ADD COLUMN IF NOT EXISTS source_vault_id UUID REFERENCES public.platform_vaults(id),
    ADD COLUMN IF NOT EXISTS escrow_vault_id UUID REFERENCES public.platform_vaults(id),
    ADD COLUMN IF NOT EXISTS receiver_vault_id UUID REFERENCES public.platform_vaults(id),
    ADD COLUMN IF NOT EXISTS merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS service_code TEXT,
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS release_requested_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS release_requested_by UUID REFERENCES auth.users(id),
    ADD COLUMN IF NOT EXISTS receiver_accepted_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS receiver_accepted_by UUID REFERENCES auth.users(id),
    ADD COLUMN IF NOT EXISTS released_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS disputed_at TIMESTAMP WITH TIME ZONE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'escrow_agreements_status_check'
          AND conrelid = 'public.escrow_agreements'::regclass
    ) THEN
        ALTER TABLE public.escrow_agreements
            DROP CONSTRAINT escrow_agreements_status_check;
    END IF;
END $$;

ALTER TABLE public.escrow_agreements
    ADD CONSTRAINT escrow_agreements_status_check
    CHECK (status IN ('HELD', 'RELEASE_PENDING', 'RETURN_PENDING', 'RELEASED', 'DISPUTED', 'REFUNDED'));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'escrow_agreements_merchant_id_fkey'
          AND conrelid = 'public.escrow_agreements'::regclass
    ) THEN
        ALTER TABLE public.escrow_agreements
            ADD CONSTRAINT escrow_agreements_merchant_id_fkey
            FOREIGN KEY (merchant_id) REFERENCES public.merchants(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_escrow_agreements_reference
    ON public.escrow_agreements(reference_id)
    WHERE reference_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_escrow_agreements_transaction
    ON public.escrow_agreements(transaction_id);

CREATE INDEX IF NOT EXISTS idx_escrow_agreements_merchant_status
    ON public.escrow_agreements(merchant_id, status, created_at DESC);

CREATE OR REPLACE FUNCTION public.apply_transaction_currency_from_metadata()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF NULLIF(BTRIM(COALESCE(NEW.metadata->>'currency', '')), '') IS NOT NULL THEN
        NEW.currency := UPPER(BTRIM(NEW.metadata->>'currency'));
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_apply_transaction_currency_from_metadata ON public.transactions;
CREATE TRIGGER trg_apply_transaction_currency_from_metadata
BEFORE INSERT ON public.transactions
FOR EACH ROW
EXECUTE FUNCTION public.apply_transaction_currency_from_metadata();

CREATE OR REPLACE FUNCTION public.create_escrow_agreement_from_transaction()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_receiver_id UUID;
    v_amount NUMERIC;
    v_source_vault_id UUID;
    v_escrow_vault_id UUID;
    v_receiver_vault_id UUID;
    v_merchant_id UUID;
BEGIN
    IF LOWER(COALESCE(NEW.type, '')) <> 'escrow'
       OR COALESCE((NEW.metadata->>'is_conditional_escrow')::BOOLEAN, FALSE) IS NOT TRUE THEN
        RETURN NEW;
    END IF;

    v_receiver_id := NULLIF(NEW.metadata->>'recipient_id', '')::UUID;
    v_amount := NULLIF(NEW.metadata->>'escrow_amount_plain', '')::NUMERIC;
    v_source_vault_id := COALESCE(
        NULLIF(NEW.metadata->>'source_vault_id', '')::UUID,
        NEW.wallet_id
    );
    v_escrow_vault_id := NULLIF(NEW.metadata->>'escrow_vault_id', '')::UUID;
    v_receiver_vault_id := NULLIF(NEW.metadata->>'receiver_vault_id', '')::UUID;
    v_merchant_id := NULLIF(NEW.metadata->>'merchant_id', '')::UUID;

    IF v_receiver_id IS NULL OR v_amount IS NULL OR v_amount <= 0
       OR v_source_vault_id IS NULL OR v_escrow_vault_id IS NULL OR v_receiver_vault_id IS NULL THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_METADATA_INVALID: canonical escrow metadata is incomplete';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.users WHERE id = v_receiver_id) THEN
        RAISE EXCEPTION 'PAYSAFE_RECEIVER_NOT_FOUND: receiver % does not exist', v_receiver_id;
    END IF;

    INSERT INTO public.escrow_agreements (
        transaction_id,
        reference_id,
        sender_id,
        receiver_id,
        source_vault_id,
        escrow_vault_id,
        receiver_vault_id,
        merchant_id,
        service_code,
        amount,
        currency,
        conditions,
        status,
        expires_at,
        metadata
    )
    VALUES (
        NEW.id,
        NEW.reference_id,
        NEW.user_id,
        v_receiver_id,
        v_source_vault_id,
        v_escrow_vault_id,
        v_receiver_vault_id,
        v_merchant_id,
        NULLIF(NEW.metadata->>'service_code', ''),
        v_amount,
        UPPER(COALESCE(NULLIF(NEW.currency, ''), 'TZS')),
        COALESCE(NEW.metadata->'conditions', '{}'::jsonb),
        'HELD',
        NULLIF(NEW.metadata->>'expires_at', '')::TIMESTAMP WITH TIME ZONE,
        jsonb_build_object(
            'created_from', 'post_transaction_v2',
            'created_at', NOW(),
            'idempotency_reference', NEW.reference_id
        )
    )
    ON CONFLICT (transaction_id) DO NOTHING;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_create_escrow_agreement_from_transaction ON public.transactions;
CREATE TRIGGER trg_create_escrow_agreement_from_transaction
AFTER INSERT ON public.transactions
FOR EACH ROW
EXECUTE FUNCTION public.create_escrow_agreement_from_transaction();

CREATE OR REPLACE FUNCTION public.transition_paysafe_escrow_v1(
    p_reference_id TEXT,
    p_actor_id UUID,
    p_action TEXT,
    p_receiver_vault_id UUID DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_action TEXT := UPPER(BTRIM(COALESCE(p_action, '')));
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_agreement public.escrow_agreements%ROWTYPE;
    v_tx public.transactions%ROWTYPE;
    v_escrow_vault public.platform_vaults%ROWTYPE;
    v_target_vault public.platform_vaults%ROWTYPE;
    v_target_vault_id UUID;
    v_target_user_id UUID;
    v_next_escrow_balance NUMERIC;
    v_next_target_balance NUMERIC;
    v_append_key TEXT;
BEGIN
    IF NULLIF(BTRIM(COALESCE(p_reference_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'PAYSAFE_REFERENCE_REQUIRED';
    END IF;

    IF v_action NOT IN ('RELEASE', 'ACCEPT', 'DISPUTE', 'REFUND') THEN
        RAISE EXCEPTION 'PAYSAFE_ACTION_INVALID: %', v_action;
    END IF;

    SELECT ea.* INTO v_agreement
    FROM public.escrow_agreements ea
    WHERE ea.reference_id = p_reference_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_NOT_FOUND';
    END IF;

    SELECT t.* INTO v_tx
    FROM public.transactions t
    WHERE t.id = v_agreement.transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_TRANSACTION_NOT_FOUND';
    END IF;

    IF v_action = 'DISPUTE' THEN
        IF p_actor_id NOT IN (v_agreement.sender_id, v_agreement.receiver_id) THEN
            RAISE EXCEPTION 'PAYSAFE_ACTOR_UNAUTHORIZED';
        END IF;
        IF v_agreement.status = 'DISPUTED' THEN
            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_agreement.transaction_id,
                'status', v_agreement.status,
                'idempotent', TRUE
            );
        END IF;
        IF v_agreement.status NOT IN ('HELD', 'RELEASE_PENDING', 'RETURN_PENDING') THEN
            RAISE EXCEPTION 'PAYSAFE_STATE_INVALID: cannot dispute escrow in state %', v_agreement.status;
        END IF;
        IF NULLIF(BTRIM(COALESCE(p_reason, '')), '') IS NULL THEN
            RAISE EXCEPTION 'PAYSAFE_DISPUTE_REASON_REQUIRED';
        END IF;

        UPDATE public.escrow_agreements
        SET
            status = 'DISPUTED',
            disputed_at = v_now,
            dispute_metadata = COALESCE(dispute_metadata, '{}'::jsonb) || jsonb_build_object(
                'reason', p_reason,
                'actor_id', p_actor_id,
                'disputed_at', v_now
            ),
            updated_at = v_now
        WHERE id = v_agreement.id;

        UPDATE public.transactions
        SET
            status = 'held_for_review',
            status_notes = p_reason,
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'escrow_status', 'DISPUTED',
                'dispute_reason', p_reason,
                'disputed_by', p_actor_id,
                'disputed_at', v_now
            ),
            updated_at = v_now
        WHERE id = v_tx.id;

        INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
        VALUES (v_tx.id, v_tx.status, 'held_for_review', p_actor_id::TEXT, jsonb_build_object('reason', p_reason));

        RETURN jsonb_build_object(
            'referenceId', p_reference_id,
            'transactionId', v_tx.id,
            'status', 'DISPUTED',
            'idempotent', FALSE
        );
    END IF;

    IF v_action = 'RELEASE' THEN
        IF p_actor_id <> v_agreement.sender_id THEN
            RAISE EXCEPTION 'PAYSAFE_ACTOR_UNAUTHORIZED';
        END IF;
        IF v_agreement.status = 'RELEASED' THEN
            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_agreement.transaction_id,
                'status', v_agreement.status,
                'idempotent', TRUE
            );
        END IF;
        IF v_agreement.status <> 'HELD' THEN
            RAISE EXCEPTION 'PAYSAFE_STATE_INVALID: cannot release escrow in state %', v_agreement.status;
        END IF;
        IF v_agreement.receiver_accepted_at IS NULL AND v_agreement.receiver_accepted_by IS NULL THEN
            RAISE EXCEPTION 'PAYSAFE_RECEIVER_CONFIRM_REQUIRED';
        END IF;
        UPDATE public.escrow_agreements
        SET
            status = 'RELEASE_PENDING',
            release_requested_at = v_now,
            release_requested_by = p_actor_id,
            expires_at = v_now + make_interval(hours => GREATEST(1, LEAST(168, COALESCE((metadata->>'hold_window_hours')::INT, 24)))),
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'escrow_status', 'RELEASE_PENDING',
                'release_requested_at', v_now,
                'release_requested_by', p_actor_id,
                'release_response_required_by', v_now + make_interval(hours => GREATEST(1, LEAST(168, COALESCE((metadata->>'hold_window_hours')::INT, 24))))
            ),
            updated_at = v_now
        WHERE id = v_agreement.id;

        UPDATE public.transactions
        SET
            status = 'awaiting_receiver_acceptance',
            status_notes = 'PaySafe release requested and waiting for receiver final acceptance.',
            metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                'escrow_status', 'RELEASE_PENDING',
                'release_requested_at', v_now,
                'release_requested_by', p_actor_id
            ),
            updated_at = v_now
        WHERE id = v_tx.id;

        INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
        VALUES (
            v_tx.id,
            v_tx.status,
            'awaiting_receiver_acceptance',
            p_actor_id::TEXT,
            jsonb_build_object('paysafe_action', 'RELEASE_REQUEST')
        );

        RETURN jsonb_build_object(
            'referenceId', p_reference_id,
            'transactionId', v_tx.id,
            'status', 'RELEASE_PENDING',
            'releaseRequestedAt', v_now,
            'requiresReceiverFinalAcceptance', TRUE,
            'idempotent', FALSE
        );
    ELSIF v_action = 'ACCEPT' THEN
        IF p_actor_id <> v_agreement.receiver_id THEN
            RAISE EXCEPTION 'PAYSAFE_ACTOR_UNAUTHORIZED';
        END IF;
        IF v_agreement.status = 'RELEASED' THEN
            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_agreement.transaction_id,
                'status', v_agreement.status,
                'idempotent', TRUE
            );
        END IF;
        IF v_agreement.status = 'RETURN_PENDING' THEN
            IF v_agreement.expires_at IS NOT NULL AND v_agreement.expires_at < v_now THEN
                RAISE EXCEPTION 'PAYSAFE_RETURN_WINDOW_EXPIRED';
            END IF;
            v_action := 'REFUND';
            p_reason := COALESCE(NULLIF(BTRIM(p_reason), ''), 'Return accepted by receiver.');
            v_target_user_id := v_agreement.sender_id;
            v_target_vault_id := COALESCE(p_receiver_vault_id, v_agreement.source_vault_id);
        ELSIF v_agreement.status = 'RELEASE_PENDING' THEN
            IF v_agreement.expires_at IS NOT NULL AND v_agreement.expires_at < v_now THEN
                IF v_agreement.receiver_accepted_at IS NULL AND v_agreement.receiver_accepted_by IS NULL THEN
                    v_action := 'REFUND';
                    p_reason := COALESCE(
                        NULLIF(BTRIM(p_reason), ''),
                        'PaySafe acceptance window expired before receiver confirmation.'
                    );
                    v_target_user_id := v_agreement.sender_id;
                    v_target_vault_id := COALESCE(p_receiver_vault_id, v_agreement.source_vault_id);
                ELSE
                UPDATE public.escrow_agreements
                SET
                    status = 'DISPUTED',
                    disputed_at = v_now,
                    dispute_metadata = COALESCE(dispute_metadata, '{}'::jsonb) || jsonb_build_object(
                        'reason', 'PAYSAFE_RELEASE_WINDOW_EXPIRED',
                        'actor_id', p_actor_id,
                        'disputed_at', v_now,
                        'auto_flagged', TRUE
                    ),
                    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                        'escrow_status', 'DISPUTED',
                        'auto_flagged_reason', 'PAYSAFE_RELEASE_WINDOW_EXPIRED',
                        'auto_flagged_at', v_now
                    ),
                    updated_at = v_now
                WHERE id = v_agreement.id;

                UPDATE public.transactions
                SET
                    status = 'held_for_review',
                    status_notes = 'PaySafe release window expired. Customer care resolution required.',
                    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                        'escrow_status', 'DISPUTED',
                        'auto_flagged_reason', 'PAYSAFE_RELEASE_WINDOW_EXPIRED',
                        'auto_flagged_at', v_now
                    ),
                    updated_at = v_now
                WHERE id = v_tx.id;

                INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
                VALUES (
                    v_tx.id,
                    v_tx.status,
                    'held_for_review',
                    p_actor_id::TEXT,
                    jsonb_build_object('paysafe_action', 'AUTO_FLAG_EXPIRED_RELEASE')
                );

                RETURN jsonb_build_object(
                    'referenceId', p_reference_id,
                    'transactionId', v_tx.id,
                    'status', 'DISPUTED',
                    'flaggedReason', 'PAYSAFE_RELEASE_WINDOW_EXPIRED',
                    'idempotent', FALSE
                );
                END IF;
            ELSE
                v_action := 'RELEASE';
                v_target_user_id := v_agreement.receiver_id;
                v_target_vault_id := COALESCE(p_receiver_vault_id, v_agreement.receiver_vault_id);
            END IF;
        ELSIF v_agreement.status = 'HELD' THEN
            IF v_agreement.receiver_accepted_at IS NOT NULL OR v_agreement.receiver_accepted_by IS NOT NULL THEN
                RETURN jsonb_build_object(
                    'referenceId', p_reference_id,
                    'transactionId', v_agreement.transaction_id,
                    'status', v_agreement.status,
                    'receiverAccepted', TRUE,
                    'idempotent', TRUE
                );
            END IF;
            IF v_agreement.expires_at IS NOT NULL AND v_agreement.expires_at < v_now THEN
                RAISE EXCEPTION 'PAYSAFE_CONFIRM_WINDOW_EXPIRED';
            END IF;

            UPDATE public.escrow_agreements
            SET
                receiver_accepted_at = v_now,
                receiver_accepted_by = p_actor_id,
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'escrow_status', 'HELD',
                    'receiver_confirmed_at', v_now,
                    'receiver_confirmed_by', p_actor_id
                ),
                updated_at = v_now
            WHERE id = v_agreement.id;

            UPDATE public.transactions
            SET
                status = 'paysafe_confirmed',
                status_notes = 'PaySafe hold confirmed by receiver. Sender release is required for settlement.',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'escrow_status', 'HELD',
                    'receiver_confirmed_at', v_now,
                    'receiver_confirmed_by', p_actor_id
                ),
                updated_at = v_now
            WHERE id = v_tx.id;

            INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
            VALUES (
                v_tx.id,
                v_tx.status,
                'paysafe_confirmed',
                p_actor_id::TEXT,
                jsonb_build_object('paysafe_action', 'CONFIRM_HOLD')
            );

            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_tx.id,
                'status', 'HELD',
                'receiverAccepted', TRUE,
                'requiresSenderRelease', TRUE,
                'idempotent', FALSE
            );
        ELSE
            RAISE EXCEPTION 'PAYSAFE_STATE_INVALID: cannot accept escrow in state %', v_agreement.status;
        END IF;
    ELSE
        IF v_agreement.status = 'REFUNDED' THEN
            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_agreement.transaction_id,
                'status', v_agreement.status,
                'idempotent', TRUE
            );
        END IF;
        IF p_actor_id <> v_agreement.sender_id THEN
            RAISE EXCEPTION 'PAYSAFE_ACTOR_UNAUTHORIZED';
        END IF;
        IF v_agreement.status NOT IN ('HELD', 'RELEASE_PENDING', 'DISPUTED') THEN
            RAISE EXCEPTION 'PAYSAFE_STATE_INVALID: cannot refund escrow in state %', v_agreement.status;
        END IF;
        IF NULLIF(BTRIM(COALESCE(p_reason, '')), '') IS NULL THEN
            RAISE EXCEPTION 'PAYSAFE_REFUND_REASON_REQUIRED';
        END IF;
        IF (v_agreement.receiver_accepted_at IS NOT NULL OR v_agreement.receiver_accepted_by IS NOT NULL)
           AND v_agreement.status <> 'DISPUTED' THEN
            UPDATE public.escrow_agreements
            SET
                status = 'RETURN_PENDING',
                expires_at = v_now + INTERVAL '24 hours',
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'escrow_status', 'RETURN_PENDING',
                    'return_requested_at', v_now,
                    'return_requested_by', p_actor_id,
                    'return_reason', p_reason,
                    'return_auto_refund_at', v_now + INTERVAL '24 hours'
                ),
                updated_at = v_now
            WHERE id = v_agreement.id;

            UPDATE public.transactions
            SET
                status = 'return_requested',
                status_notes = p_reason,
                metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                    'escrow_status', 'RETURN_PENDING',
                    'return_requested_at', v_now,
                    'return_requested_by', p_actor_id,
                    'return_reason', p_reason,
                    'return_auto_refund_at', v_now + INTERVAL '24 hours'
                ),
                updated_at = v_now
            WHERE id = v_tx.id;

            INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
            VALUES (
                v_tx.id,
                v_tx.status,
                'return_requested',
                p_actor_id::TEXT,
                jsonb_build_object('paysafe_action', 'RETURN_REQUEST', 'reason', p_reason)
            );

            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_tx.id,
                'status', 'RETURN_PENDING',
                'returnRequestedAt', v_now,
                'autoRefundAt', v_now + INTERVAL '24 hours',
                'idempotent', FALSE
            );
        END IF;
        v_target_user_id := v_agreement.sender_id;
        v_target_vault_id := COALESCE(p_receiver_vault_id, v_agreement.source_vault_id);
    END IF;

    SELECT pv.* INTO v_escrow_vault
    FROM public.platform_vaults pv
    WHERE pv.id = v_agreement.escrow_vault_id
      AND pv.user_id = v_agreement.sender_id
      AND pv.vault_role = 'INTERNAL_TRANSFER'
      AND NOT COALESCE(pv.is_locked, FALSE)
      AND LOWER(COALESCE(pv.status, 'active')) NOT IN ('locked', 'frozen', 'blocked', 'suspended')
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_VAULT_UNAVAILABLE';
    END IF;

    IF v_target_vault_id IS NULL THEN
        SELECT pv.id INTO v_target_vault_id
        FROM public.platform_vaults pv
        WHERE pv.user_id = v_target_user_id
          AND pv.vault_role = 'OPERATING'
          AND UPPER(COALESCE(pv.currency, 'TZS')) = UPPER(v_agreement.currency)
          AND NOT COALESCE(pv.is_locked, FALSE)
          AND LOWER(COALESCE(pv.status, 'active')) NOT IN ('locked', 'frozen', 'blocked', 'suspended')
        ORDER BY pv.created_at
        LIMIT 1;
    END IF;

    SELECT pv.* INTO v_target_vault
    FROM public.platform_vaults pv
    WHERE pv.id = v_target_vault_id
      AND pv.user_id = v_target_user_id
      AND pv.vault_role = 'OPERATING'
      AND UPPER(COALESCE(pv.currency, 'TZS')) = UPPER(v_agreement.currency)
      AND NOT COALESCE(pv.is_locked, FALSE)
      AND LOWER(COALESCE(pv.status, 'active')) NOT IN ('locked', 'frozen', 'blocked', 'suspended')
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_TARGET_VAULT_UNAVAILABLE';
    END IF;

    IF UPPER(COALESCE(v_escrow_vault.currency, 'TZS')) <> UPPER(v_agreement.currency) THEN
        RAISE EXCEPTION 'PAYSAFE_CURRENCY_MISMATCH';
    END IF;

    IF COALESCE(v_escrow_vault.balance, 0) < v_agreement.amount THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_BALANCE_INSUFFICIENT';
    END IF;

    v_append_key := 'paysafe:' || v_agreement.id::TEXT || ':' || LOWER(v_action) || ':v1';
    INSERT INTO public.ledger_append_markers (transaction_id, append_key, append_phase, metadata)
    VALUES (
        v_tx.id,
        v_append_key,
        'PAYSAFE_' || v_action,
        jsonb_build_object('actor_id', p_actor_id, 'reference_id', p_reference_id)
    );

    v_next_escrow_balance := ROUND((COALESCE(v_escrow_vault.balance, 0) - v_agreement.amount)::NUMERIC, 4);
    v_next_target_balance := ROUND((COALESCE(v_target_vault.balance, 0) + v_agreement.amount)::NUMERIC, 4);

    UPDATE public.platform_vaults
    SET balance = v_next_escrow_balance, updated_at = v_now
    WHERE id = v_escrow_vault.id;

    UPDATE public.platform_vaults
    SET balance = v_next_target_balance, updated_at = v_now
    WHERE id = v_target_vault.id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description
    )
    VALUES
        (
            v_tx.id,
            v_agreement.sender_id,
            v_escrow_vault.id,
            'DEBIT',
            v_tx.amount,
            v_next_escrow_balance::TEXT,
            'PaySafe ' || INITCAP(LOWER(v_action)) || ': ' || p_reference_id
        ),
        (
            v_tx.id,
            v_target_user_id,
            v_target_vault.id,
            'CREDIT',
            v_tx.amount,
            v_next_target_balance::TEXT,
            'PaySafe ' || INITCAP(LOWER(v_action)) || ': ' || p_reference_id
        );

    UPDATE public.escrow_agreements
    SET
        status = CASE WHEN v_action = 'RELEASE' THEN 'RELEASED' ELSE 'REFUNDED' END,
        receiver_vault_id = CASE WHEN v_action = 'RELEASE' THEN v_target_vault.id ELSE receiver_vault_id END,
        released_at = CASE WHEN v_action = 'RELEASE' THEN v_now ELSE released_at END,
        refunded_at = CASE WHEN v_action = 'REFUND' THEN v_now ELSE refunded_at END,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'last_action', v_action,
            'last_actor_id', p_actor_id,
            'last_action_at', v_now,
            'target_vault_id', v_target_vault.id,
            'reason', p_reason,
            'escrow_status', CASE WHEN v_action = 'RELEASE' THEN 'RELEASED' ELSE 'REFUNDED' END
        ),
        updated_at = v_now
    WHERE id = v_agreement.id;

    UPDATE public.transactions
    SET
        status = CASE WHEN v_action = 'RELEASE' THEN 'completed' ELSE 'refunded' END,
        status_notes = COALESCE(NULLIF(BTRIM(p_reason), ''), 'PaySafe ' || LOWER(v_action) || ' completed.'),
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'escrow_status', CASE WHEN v_action = 'RELEASE' THEN 'RELEASED' ELSE 'REFUNDED' END,
            'escrow_action_at', v_now,
            'escrow_action_by', p_actor_id,
            'escrow_target_vault_id', v_target_vault.id
        ),
        updated_at = v_now
    WHERE id = v_tx.id;

    INSERT INTO public.transaction_events (transaction_id, old_state, new_state, actor, metadata)
    VALUES (
        v_tx.id,
        v_tx.status,
        CASE WHEN v_action = 'RELEASE' THEN 'completed' ELSE 'refunded' END,
        p_actor_id::TEXT,
        jsonb_build_object('paysafe_action', v_action, 'reason', p_reason)
    );

    RETURN jsonb_build_object(
        'referenceId', p_reference_id,
        'transactionId', v_tx.id,
        'status', CASE WHEN v_action = 'RELEASE' THEN 'RELEASED' ELSE 'REFUNDED' END,
        'amount', v_agreement.amount,
        'currency', v_agreement.currency,
        'targetVaultId', v_target_vault.id,
        'idempotent', FALSE
    );
EXCEPTION
    WHEN unique_violation THEN
        IF v_append_key IS NOT NULL AND EXISTS (
            SELECT 1 FROM public.ledger_append_markers WHERE append_key = v_append_key
        ) THEN
            RAISE EXCEPTION 'PAYSAFE_ACTION_ALREADY_APPLIED';
        END IF;
        RAISE;
END;
$$;

REVOKE ALL ON FUNCTION public.create_escrow_agreement_from_transaction() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_transaction_currency_from_metadata() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.transition_paysafe_escrow_v1(TEXT, UUID, TEXT, UUID, TEXT) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.transition_paysafe_escrow_v1(TEXT, UUID, TEXT, UUID, TEXT) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.transition_paysafe_escrow_v1(TEXT, UUID, TEXT, UUID, TEXT) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.transition_paysafe_escrow_v1(TEXT, UUID, TEXT, UUID, TEXT) TO service_role';
    END IF;
END $$;
-- END SYNCED MIGRATION: 20260618_paysafe_escrow_hardening.sql

-- BEGIN SYNCED MIGRATION: 20260618_merchant_paysafe_settlement.sql
-- Merchant PaySafe settlement and fee lifecycle.
-- Fee values are snapshotted at escrow authorization and consumed atomically.

INSERT INTO public.platform_fee_configs (
    name,
    flow_code,
    transaction_model,
    transaction_type,
    operation_type,
    direction,
    rail,
    channel,
    percentage_rate,
    fixed_amount,
    minimum_fee,
    tax_rate,
    gov_fee_rate,
    stamp_duty_fixed,
    priority,
    status,
    metadata
)
SELECT
    'Base PaySafe merchant release fee policy',
    'MERCHANT_PAYMENT',
    'MERCHANT_PAYMENT',
    'MERCHANT_PAYMENT',
    'PAYSAFE_RELEASE',
    'INBOUND',
    'WALLET',
    'PAYSAFE',
    0,
    0,
    0,
    0,
    0,
    0,
    1000,
    'ACTIVE',
    jsonb_build_object(
        'seeded_by', 'database/migrations/20260618_merchant_paysafe_settlement.sql',
        'purpose', 'safe zero-rate baseline; configure commercial PaySafe merchant fees before monetized launch'
    )
WHERE NOT EXISTS (
    SELECT 1
    FROM public.platform_fee_configs existing
    WHERE existing.flow_code = 'MERCHANT_PAYMENT'
      AND existing.operation_type = 'PAYSAFE_RELEASE'
      AND existing.rail = 'WALLET'
      AND existing.channel = 'PAYSAFE'
      AND existing.status = 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS public.merchant_paysafe_settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    escrow_agreement_id UUID NOT NULL UNIQUE REFERENCES public.escrow_agreements(id) ON DELETE RESTRICT,
    transaction_id UUID NOT NULL UNIQUE REFERENCES public.transactions(id) ON DELETE RESTRICT,
    merchant_id UUID NOT NULL REFERENCES public.merchants(id) ON DELETE RESTRICT,
    owner_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    merchant_wallet_id UUID NOT NULL REFERENCES public.merchant_wallets(id) ON DELETE RESTRICT,
    fee_collector_wallet_id UUID REFERENCES public.fee_collector_wallets(id) ON DELETE RESTRICT,
    fee_config_id UUID REFERENCES public.platform_fee_configs(id) ON DELETE SET NULL,
    gross_amount NUMERIC NOT NULL CHECK (gross_amount > 0),
    fee_amount NUMERIC NOT NULL DEFAULT 0 CHECK (fee_amount >= 0),
    tax_amount NUMERIC NOT NULL DEFAULT 0 CHECK (tax_amount >= 0),
    net_amount NUMERIC NOT NULL CHECK (net_amount > 0),
    currency TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'SETTLED'
        CHECK (status IN ('SETTLED', 'REVERSED', 'HELD_FOR_REVIEW')),
    settled_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    reversed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT merchant_paysafe_settlement_amounts_balance
        CHECK (ABS(gross_amount - (fee_amount + tax_amount + net_amount)) <= 0.01)
);

CREATE INDEX IF NOT EXISTS idx_merchant_paysafe_settlements_merchant_period
    ON public.merchant_paysafe_settlements(merchant_id, settled_at DESC);

CREATE INDEX IF NOT EXISTS idx_merchant_paysafe_settlements_status
    ON public.merchant_paysafe_settlements(status, settled_at DESC);

ALTER TABLE public.merchant_paysafe_settlements ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS merchant_paysafe_settlements_service_role
    ON public.merchant_paysafe_settlements;
CREATE POLICY merchant_paysafe_settlements_service_role
    ON public.merchant_paysafe_settlements
    FOR ALL TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION public.settle_merchant_paysafe_v1(
    p_reference_id TEXT,
    p_actor_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_now TIMESTAMP WITH TIME ZONE := NOW();
    v_agreement public.escrow_agreements%ROWTYPE;
    v_tx public.transactions%ROWTYPE;
    v_merchant public.merchants%ROWTYPE;
    v_escrow_vault public.platform_vaults%ROWTYPE;
    v_merchant_wallet public.merchant_wallets%ROWTYPE;
    v_service_revenue_vault public.platform_vaults%ROWTYPE;
    v_tax_reserve_vault public.platform_vaults%ROWTYPE;
    v_settlement_config_id UUID;
    v_fee_snapshot JSONB;
    v_fee_config_id UUID;
    v_gross NUMERIC;
    v_service_fee NUMERIC;
    v_tax NUMERIC;
    v_total_fee NUMERIC;
    v_net NUMERIC;
    v_next_escrow_balance NUMERIC;
    v_next_merchant_balance NUMERIC;
    v_next_service_revenue_balance NUMERIC;
    v_next_tax_reserve_balance NUMERIC;
    v_append_key TEXT;
    v_existing public.merchant_paysafe_settlements%ROWTYPE;
BEGIN
    IF NULLIF(BTRIM(COALESCE(p_reference_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'PAYSAFE_REFERENCE_REQUIRED';
    END IF;

    SELECT ea.* INTO v_agreement
    FROM public.escrow_agreements ea
    WHERE ea.reference_id = p_reference_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_NOT_FOUND';
    END IF;

    IF v_agreement.merchant_id IS NULL THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_CONTEXT_REQUIRED';
    END IF;

    IF p_actor_id <> v_agreement.sender_id THEN
        RAISE EXCEPTION 'PAYSAFE_ACTOR_UNAUTHORIZED';
    END IF;

    SELECT * INTO v_existing
    FROM public.merchant_paysafe_settlements
    WHERE escrow_agreement_id = v_agreement.id;

    IF FOUND THEN
        RETURN jsonb_build_object(
            'referenceId', p_reference_id,
            'transactionId', v_existing.transaction_id,
            'settlementId', v_existing.id,
            'merchantId', v_existing.merchant_id,
            'status', v_existing.status,
            'grossAmount', v_existing.gross_amount,
            'feeAmount', v_existing.fee_amount,
            'taxAmount', v_existing.tax_amount,
            'netAmount', v_existing.net_amount,
            'currency', v_existing.currency,
            'idempotent', TRUE
        );
    END IF;

    IF v_agreement.status <> 'HELD' THEN
        RAISE EXCEPTION 'PAYSAFE_STATE_INVALID: cannot settle merchant escrow in state %', v_agreement.status;
    END IF;

    SELECT t.* INTO v_tx
    FROM public.transactions t
    WHERE t.id = v_agreement.transaction_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_TRANSACTION_NOT_FOUND';
    END IF;

    SELECT m.* INTO v_merchant
    FROM public.merchants m
    WHERE m.id = v_agreement.merchant_id
      AND LOWER(COALESCE(m.status, '')) = 'active'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_NOT_ACTIVE';
    END IF;

    IF v_merchant.owner_user_id IS NULL
       OR v_merchant.owner_user_id <> v_agreement.receiver_id THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_RECIPIENT_MISMATCH';
    END IF;

    SELECT mw.* INTO v_merchant_wallet
    FROM public.merchant_wallets mw
    WHERE mw.merchant_id = v_merchant.id
      AND LOWER(COALESCE(mw.status, 'active')) = 'active'
      AND LOWER(COALESCE(mw.wallet_type, 'operating')) IN ('settlement', 'operating')
      AND UPPER(COALESCE(mw.currency, 'TZS')) = UPPER(v_agreement.currency)
    ORDER BY
      CASE WHEN LOWER(COALESCE(mw.wallet_type, '')) = 'settlement' THEN 0 ELSE 1 END,
      mw.is_primary DESC,
      mw.created_at
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_SETTLEMENT_WALLET_UNAVAILABLE';
    END IF;

    SELECT pv.* INTO v_escrow_vault
    FROM public.platform_vaults pv
    WHERE pv.id = v_agreement.escrow_vault_id
      AND pv.user_id = v_agreement.sender_id
      AND pv.vault_role = 'INTERNAL_TRANSFER'
      AND NOT COALESCE(pv.is_locked, FALSE)
      AND LOWER(COALESCE(pv.status, 'active')) NOT IN ('locked', 'frozen', 'blocked', 'suspended')
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_VAULT_UNAVAILABLE';
    END IF;

    IF UPPER(COALESCE(v_escrow_vault.currency, 'TZS')) <> UPPER(v_agreement.currency) THEN
        RAISE EXCEPTION 'PAYSAFE_CURRENCY_MISMATCH';
    END IF;

    v_fee_snapshot := COALESCE(
        v_agreement.metadata->'merchant_fee_snapshot',
        v_tx.metadata->'merchant_fee_snapshot'
    );
    IF v_fee_snapshot IS NULL OR jsonb_typeof(v_fee_snapshot) <> 'object' THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_FEE_SNAPSHOT_REQUIRED';
    END IF;

    v_gross := ROUND(v_agreement.amount::NUMERIC, 2);
    v_service_fee := ROUND(COALESCE(NULLIF(v_fee_snapshot->>'serviceFee', '')::NUMERIC, 0), 2);
    v_tax := ROUND((
        COALESCE(NULLIF(v_fee_snapshot->>'taxAmount', '')::NUMERIC, 0)
        + COALESCE(NULLIF(v_fee_snapshot->>'govFeeAmount', '')::NUMERIC, 0)
        + COALESCE(NULLIF(v_fee_snapshot->>'stampDutyFixed', '')::NUMERIC, 0)
    )::NUMERIC, 2);
    v_total_fee := ROUND(COALESCE(NULLIF(v_fee_snapshot->>'totalFee', '')::NUMERIC, 0), 2);
    v_net := ROUND(COALESCE(NULLIF(v_fee_snapshot->>'netAmount', '')::NUMERIC, 0), 2);
    v_fee_config_id := NULLIF(v_fee_snapshot->>'configId', '')::UUID;

    IF UPPER(COALESCE(v_fee_snapshot->>'currency', '')) <> UPPER(v_agreement.currency)
       OR v_gross <= 0
       OR v_service_fee < 0
       OR v_tax < 0
       OR v_total_fee < 0
       OR v_net <= 0
       OR ABS(v_total_fee - (v_service_fee + v_tax)) > 0.01
       OR ABS(v_gross - (v_total_fee + v_net)) > 0.01 THEN
        RAISE EXCEPTION 'PAYSAFE_MERCHANT_FEE_SNAPSHOT_INVALID';
    END IF;

    IF COALESCE(v_escrow_vault.balance, 0) < v_gross THEN
        RAISE EXCEPTION 'PAYSAFE_ESCROW_BALANCE_INSUFFICIENT';
    END IF;

    IF v_service_fee > 0 THEN
        SELECT pv.* INTO v_service_revenue_vault
        FROM public.system_settlement_accounts ssa
        JOIN public.platform_vaults pv ON pv.id = ssa.vault_id
        WHERE ssa.role = 'SERVICE_REVENUE'
          AND ssa.currency = UPPER(v_agreement.currency)
          AND ssa.status = 'ACTIVE'
          AND UPPER(COALESCE(pv.currency, '')) = UPPER(v_agreement.currency)
          AND NOT COALESCE(pv.is_locked, FALSE)
          AND LOWER(COALESCE(pv.status, 'active')) = 'active'
        FOR UPDATE OF pv;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'PAYSAFE_SERVICE_REVENUE_ACCOUNT_UNAVAILABLE:%', UPPER(v_agreement.currency);
        END IF;
    END IF;

    IF v_tax > 0 THEN
        SELECT pv.* INTO v_tax_reserve_vault
        FROM public.system_settlement_accounts ssa
        JOIN public.platform_vaults pv ON pv.id = ssa.vault_id
        WHERE ssa.role = 'TAX_RESERVE'
          AND ssa.currency = UPPER(v_agreement.currency)
          AND ssa.status = 'ACTIVE'
          AND UPPER(COALESCE(pv.currency, '')) = UPPER(v_agreement.currency)
          AND NOT COALESCE(pv.is_locked, FALSE)
          AND LOWER(COALESCE(pv.status, 'active')) = 'active'
        FOR UPDATE OF pv;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'PAYSAFE_TAX_RESERVE_ACCOUNT_UNAVAILABLE:%', UPPER(v_agreement.currency);
        END IF;
    END IF;

    v_append_key := 'paysafe:' || v_agreement.id::TEXT || ':merchant_settlement:v1';
    INSERT INTO public.ledger_append_markers (
        transaction_id,
        append_key,
        append_phase,
        metadata
    ) VALUES (
        v_tx.id,
        v_append_key,
        'PAYSAFE_MERCHANT_SETTLEMENT',
        jsonb_build_object(
            'merchant_id', v_merchant.id,
            'merchant_wallet_id', v_merchant_wallet.id,
            'actor_id', p_actor_id,
            'reference_id', p_reference_id
        )
    );

    v_next_escrow_balance := ROUND((COALESCE(v_escrow_vault.balance, 0) - v_gross)::NUMERIC, 2);
    v_next_merchant_balance := ROUND((COALESCE(v_merchant_wallet.balance, 0) + v_net)::NUMERIC, 2);

    UPDATE public.platform_vaults
    SET balance = v_next_escrow_balance, updated_at = v_now
    WHERE id = v_escrow_vault.id;

    UPDATE public.merchant_wallets
    SET balance = v_next_merchant_balance, updated_at = v_now
    WHERE id = v_merchant_wallet.id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description, currency
    ) VALUES
        (
            v_tx.id, v_agreement.sender_id, v_escrow_vault.id, 'DEBIT',
            v_gross::TEXT, v_next_escrow_balance::TEXT,
            'PaySafe merchant settlement debit: ' || p_reference_id,
            UPPER(v_agreement.currency)
        ),
        (
            v_tx.id, v_merchant.owner_user_id, v_merchant_wallet.id, 'CREDIT',
            v_net::TEXT, v_next_merchant_balance::TEXT,
            'PaySafe merchant net settlement: ' || p_reference_id,
            UPPER(v_agreement.currency)
        );

    IF v_service_fee > 0 THEN
        v_next_service_revenue_balance := ROUND((COALESCE(v_service_revenue_vault.balance, 0) + v_service_fee)::NUMERIC, 2);
        UPDATE public.platform_vaults SET balance = v_next_service_revenue_balance, updated_at = v_now WHERE id = v_service_revenue_vault.id;
        INSERT INTO public.financial_ledger (transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description, currency)
        VALUES (v_tx.id, v_service_revenue_vault.user_id, v_service_revenue_vault.id, 'CREDIT', v_service_fee::TEXT, v_next_service_revenue_balance::TEXT, 'PaySafe merchant service revenue: ' || p_reference_id, UPPER(v_agreement.currency));
    END IF;

    IF v_tax > 0 THEN
        v_next_tax_reserve_balance := ROUND((COALESCE(v_tax_reserve_vault.balance, 0) + v_tax)::NUMERIC, 2);
        UPDATE public.platform_vaults SET balance = v_next_tax_reserve_balance, updated_at = v_now WHERE id = v_tax_reserve_vault.id;
        INSERT INTO public.financial_ledger (transaction_id, user_id, wallet_id, entry_type, amount, balance_after, description, currency)
        VALUES (v_tx.id, v_tax_reserve_vault.user_id, v_tax_reserve_vault.id, 'CREDIT', v_tax::TEXT, v_next_tax_reserve_balance::TEXT, 'PaySafe merchant statutory tax reserve: ' || p_reference_id, UPPER(v_agreement.currency));
    END IF;

    INSERT INTO public.merchant_paysafe_settlements (
        escrow_agreement_id,
        transaction_id,
        merchant_id,
        owner_user_id,
        merchant_wallet_id,
        fee_collector_wallet_id,
        service_revenue_vault_id,
        tax_reserve_vault_id,
        fee_config_id,
        gross_amount,
        fee_amount,
        tax_amount,
        net_amount,
        currency,
        status,
        settled_at,
        metadata
    ) VALUES (
        v_agreement.id,
        v_tx.id,
        v_merchant.id,
        v_merchant.owner_user_id,
        v_merchant_wallet.id,
        NULL,
        CASE WHEN v_service_fee > 0 THEN v_service_revenue_vault.id ELSE NULL END,
        CASE WHEN v_tax > 0 THEN v_tax_reserve_vault.id ELSE NULL END,
        v_fee_config_id,
        v_gross,
        v_service_fee,
        v_tax,
        v_net,
        UPPER(v_agreement.currency),
        'SETTLED',
        v_now,
        jsonb_build_object(
            'reference_id', p_reference_id,
            'fee_snapshot', v_fee_snapshot,
            'service_revenue_vault_id', CASE WHEN v_service_fee > 0 THEN v_service_revenue_vault.id ELSE NULL END,
            'tax_reserve_vault_id', CASE WHEN v_tax > 0 THEN v_tax_reserve_vault.id ELSE NULL END,
            'settled_by', p_actor_id
        )
    )
    RETURNING * INTO v_existing;

    INSERT INTO public.merchant_transactions (
        transaction_id,
        merchant_id,
        owner_user_id,
        merchant_wallet_id,
        customer_user_id,
        direction,
        amount,
        currency,
        status,
        service_type,
        metadata
    ) VALUES (
        v_tx.id,
        v_merchant.id,
        v_merchant.owner_user_id,
        v_merchant_wallet.id,
        v_agreement.sender_id,
        'inbound',
        v_gross,
        UPPER(v_agreement.currency),
        'completed',
        'paysafe',
        jsonb_build_object(
            'reference_id', p_reference_id,
            'settlement_id', v_existing.id,
            'gross_amount', v_gross,
            'fee_amount', v_service_fee,
            'tax_amount', v_tax,
            'net_amount', v_net
        )
    )
    ON CONFLICT (transaction_id) DO UPDATE
    SET
        merchant_wallet_id = EXCLUDED.merchant_wallet_id,
        status = 'completed',
        amount = EXCLUDED.amount,
        currency = EXCLUDED.currency,
        metadata = COALESCE(merchant_transactions.metadata, '{}'::jsonb)
            || EXCLUDED.metadata,
        updated_at = v_now;

    SELECT ms.id INTO v_settlement_config_id
    FROM public.merchant_settlements ms
    WHERE ms.merchant_id = v_merchant.id;

    INSERT INTO public.settlement_lifecycle (
        transaction_id,
        merchant_settlement_id,
        lifecycle_key,
        settlement_batch_id,
        rail,
        direction,
        operation_type,
        currency,
        gross_amount,
        fee_amount,
        tax_amount,
        net_amount,
        stage,
        status,
        initiated_at,
        provider_confirmed_at,
        settled_at,
        metadata
    ) VALUES (
        v_tx.id,
        v_settlement_config_id,
        'merchant-paysafe:' || v_agreement.id::TEXT,
        'PAYSAFE-' || TO_CHAR(v_now, 'YYYYMMDD'),
        'WALLET',
        'INBOUND',
        'PAYSAFE_MERCHANT_SETTLEMENT',
        UPPER(v_agreement.currency),
        v_gross,
        v_service_fee,
        v_tax,
        v_net,
        'SETTLED',
        'COMPLETED',
        COALESCE(v_tx.created_at, v_now),
        v_now,
        v_now,
        jsonb_build_object(
            'merchant_id', v_merchant.id,
            'escrow_agreement_id', v_agreement.id,
            'merchant_paysafe_settlement_id', v_existing.id,
            'fee_snapshot', v_fee_snapshot
        )
    )
    ON CONFLICT (lifecycle_key) DO NOTHING;

    UPDATE public.escrow_agreements
    SET
        status = 'RELEASED',
        released_at = v_now,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'last_action', 'MERCHANT_SETTLEMENT',
            'last_actor_id', p_actor_id,
            'last_action_at', v_now,
            'merchant_wallet_id', v_merchant_wallet.id,
            'merchant_paysafe_settlement_id', v_existing.id,
            'merchant_fee_snapshot', v_fee_snapshot
        ),
        updated_at = v_now
    WHERE id = v_agreement.id;

    UPDATE public.transactions
    SET
        status = 'completed',
        status_notes = 'PaySafe merchant settlement completed.',
        settlement_status = 'SETTLED',
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
            'escrow_status', 'RELEASED',
            'merchant_settlement_id', v_existing.id,
            'merchant_wallet_id', v_merchant_wallet.id,
            'gross_amount', v_gross,
            'fee_amount', v_service_fee,
            'tax_amount', v_tax,
            'net_amount', v_net,
            'settled_at', v_now
        ),
        updated_at = v_now
    WHERE id = v_tx.id;

    INSERT INTO public.transaction_events (
        transaction_id, old_state, new_state, actor, metadata
    ) VALUES (
        v_tx.id,
        v_tx.status,
        'completed',
        p_actor_id::TEXT,
        jsonb_build_object(
            'paysafe_action', 'MERCHANT_SETTLEMENT',
            'merchant_id', v_merchant.id,
            'settlement_id', v_existing.id
        )
    );

    RETURN jsonb_build_object(
        'referenceId', p_reference_id,
        'transactionId', v_tx.id,
        'settlementId', v_existing.id,
        'merchantId', v_merchant.id,
        'merchantWalletId', v_merchant_wallet.id,
        'status', 'SETTLED',
        'grossAmount', v_gross,
        'feeAmount', v_service_fee,
        'taxAmount', v_tax,
        'netAmount', v_net,
        'currency', UPPER(v_agreement.currency),
        'idempotent', FALSE
    );
EXCEPTION
    WHEN unique_violation THEN
        SELECT * INTO v_existing
        FROM public.merchant_paysafe_settlements
        WHERE escrow_agreement_id = v_agreement.id;

        IF FOUND THEN
            RETURN jsonb_build_object(
                'referenceId', p_reference_id,
                'transactionId', v_existing.transaction_id,
                'settlementId', v_existing.id,
                'merchantId', v_existing.merchant_id,
                'status', v_existing.status,
                'grossAmount', v_existing.gross_amount,
                'feeAmount', v_existing.fee_amount,
                'taxAmount', v_existing.tax_amount,
                'netAmount', v_existing.net_amount,
                'currency', v_existing.currency,
                'idempotent', TRUE
            );
        END IF;
        RAISE;
END;
$$;

REVOKE ALL ON FUNCTION public.settle_merchant_paysafe_v1(TEXT, UUID) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.settle_merchant_paysafe_v1(TEXT, UUID) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.settle_merchant_paysafe_v1(TEXT, UUID) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.settle_merchant_paysafe_v1(TEXT, UUID) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260618_merchant_paysafe_settlement.sql

-- BEGIN SYNCED MIGRATION: 20260618_gateway_intent_challenge_store.sql
-- Durable ORBI Pay Gateway intent, challenge, and result-event outbox.
-- Authorization evidence must be verified by ORBI Core before challenges are consumed.

CREATE TABLE IF NOT EXISTS public.gateway_payment_intents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    intent_id TEXT NOT NULL UNIQUE,
    service_code TEXT NOT NULL,
    reference TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    customer_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    merchant_id UUID REFERENCES public.merchants(id) ON DELETE SET NULL,
    amount NUMERIC NOT NULL DEFAULT 0 CHECK (amount >= 0),
    currency TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN (
            'RECEIVED',
            'REQUIRES_ACTION',
            'AUTHORIZED',
            'PROCESSING',
            'COMPLETED',
            'FAILED',
            'CANCELLED',
            'EXPIRED'
        )),
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    authorized_at TIMESTAMP WITH TIME ZONE,
    processing_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    cancelled_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.gateway_payment_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id TEXT NOT NULL UNIQUE,
    intent_id UUID NOT NULL REFERENCES public.gateway_payment_intents(id) ON DELETE CASCADE,
    customer_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    challenge_type TEXT NOT NULL
        CHECK (challenge_type IN ('PIN', 'OTP', 'PASSKEY', 'BIOMETRIC', '3DS')),
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    rejected_at TIMESTAMP WITH TIME ZONE,
    consumed_at TIMESTAMP WITH TIME ZONE,
    authorization_method TEXT,
    authorization_reference TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(intent_id, challenge_type)
);

CREATE TABLE IF NOT EXISTS public.gateway_payment_event_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_key TEXT NOT NULL UNIQUE,
    intent_id UUID NOT NULL REFERENCES public.gateway_payment_intents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT 'SERVICE_PAYMENT_RESULT',
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'DELIVERING', 'DELIVERED', 'FAILED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_error TEXT,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gateway_payment_intents_status
    ON public.gateway_payment_intents(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_intents_customer
    ON public.gateway_payment_intents(customer_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_challenges_pending
    ON public.gateway_payment_challenges(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_event_outbox_pending
    ON public.gateway_payment_event_outbox(status, next_attempt_at);

ALTER TABLE public.gateway_payment_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gateway_payment_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gateway_payment_event_outbox ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS gateway_payment_intents_service_role
    ON public.gateway_payment_intents;
CREATE POLICY gateway_payment_intents_service_role
    ON public.gateway_payment_intents
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS gateway_payment_challenges_service_role
    ON public.gateway_payment_challenges;
CREATE POLICY gateway_payment_challenges_service_role
    ON public.gateway_payment_challenges
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS gateway_payment_event_outbox_service_role
    ON public.gateway_payment_event_outbox;
CREATE POLICY gateway_payment_event_outbox_service_role
    ON public.gateway_payment_event_outbox
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION public.persist_gateway_payment_intent_v1(
    p_intent_id TEXT,
    p_service_code TEXT,
    p_reference TEXT,
    p_operation TEXT,
    p_request_hash TEXT,
    p_customer_user_id UUID,
    p_merchant_id UUID,
    p_amount NUMERIC,
    p_currency TEXT,
    p_status TEXT,
    p_request_payload JSONB,
    p_response_payload JSONB,
    p_challenge_id TEXT DEFAULT NULL,
    p_challenge_type TEXT DEFAULT NULL,
    p_challenge_expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    p_challenge_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_intent public.gateway_payment_intents%ROWTYPE;
    v_status TEXT := UPPER(BTRIM(COALESCE(p_status, '')));
    v_event_key TEXT;
BEGIN
    IF NULLIF(BTRIM(COALESCE(p_intent_id, '')), '') IS NULL
       OR NULLIF(BTRIM(COALESCE(p_request_hash, '')), '') IS NULL THEN
        RAISE EXCEPTION 'GATEWAY_INTENT_IDEMPOTENCY_REQUIRED';
    END IF;

    SELECT * INTO v_intent
    FROM public.gateway_payment_intents
    WHERE intent_id = p_intent_id
    FOR UPDATE;

    IF FOUND THEN
        IF v_intent.request_hash <> p_request_hash THEN
            RAISE EXCEPTION 'GATEWAY_INTENT_REPLAY_MISMATCH';
        END IF;
        SELECT event_key INTO v_event_key
        FROM public.gateway_payment_event_outbox
        WHERE intent_id = v_intent.id
        ORDER BY created_at DESC
        LIMIT 1;
        RETURN jsonb_build_object(
            'intentId', v_intent.intent_id,
            'status', v_intent.status,
            'response', v_intent.response_payload,
            'outboxEventKey', v_event_key,
            'replayed', TRUE
        );
    END IF;

    IF v_status NOT IN ('REQUIRES_ACTION', 'FAILED', 'PENDING', 'PROCESSING', 'COMPLETED') THEN
        RAISE EXCEPTION 'GATEWAY_INTENT_STATUS_INVALID';
    END IF;

    INSERT INTO public.gateway_payment_intents (
        intent_id,
        service_code,
        reference,
        operation,
        request_hash,
        customer_user_id,
        merchant_id,
        amount,
        currency,
        status,
        request_payload,
        response_payload,
        expires_at,
        failed_at,
        completed_at,
        metadata
    ) VALUES (
        p_intent_id,
        p_service_code,
        p_reference,
        UPPER(p_operation),
        p_request_hash,
        p_customer_user_id,
        p_merchant_id,
        ROUND(COALESCE(p_amount, 0)::NUMERIC, 2),
        UPPER(p_currency),
        CASE v_status
            WHEN 'REQUIRES_ACTION' THEN 'REQUIRES_ACTION'
            WHEN 'FAILED' THEN 'FAILED'
            WHEN 'COMPLETED' THEN 'COMPLETED'
            WHEN 'PROCESSING' THEN 'PROCESSING'
            ELSE 'RECEIVED'
        END,
        COALESCE(p_request_payload, '{}'::jsonb),
        COALESCE(p_response_payload, '{}'::jsonb),
        p_challenge_expires_at,
        CASE WHEN v_status = 'FAILED' THEN NOW() ELSE NULL END,
        CASE WHEN v_status = 'COMPLETED' THEN NOW() ELSE NULL END,
        jsonb_build_object('persisted_by', 'persist_gateway_payment_intent_v1')
    )
    RETURNING * INTO v_intent;

    IF v_status = 'REQUIRES_ACTION' THEN
        IF p_customer_user_id IS NULL
           OR NULLIF(BTRIM(COALESCE(p_challenge_id, '')), '') IS NULL
           OR NULLIF(BTRIM(COALESCE(p_challenge_type, '')), '') IS NULL
           OR p_challenge_expires_at IS NULL THEN
            RAISE EXCEPTION 'GATEWAY_CHALLENGE_DETAILS_REQUIRED';
        END IF;

        INSERT INTO public.gateway_payment_challenges (
            challenge_id,
            intent_id,
            customer_user_id,
            challenge_type,
            status,
            expires_at,
            metadata
        ) VALUES (
            p_challenge_id,
            v_intent.id,
            p_customer_user_id,
            UPPER(p_challenge_type),
            'PENDING',
            p_challenge_expires_at,
            COALESCE(p_challenge_metadata, '{}'::jsonb)
        );
    END IF;

    v_event_key := 'service-payment-result:' || p_intent_id || ':' || LOWER(v_status);
    INSERT INTO public.gateway_payment_event_outbox (
        event_key,
        intent_id,
        payload,
        status
    ) VALUES (
        v_event_key,
        v_intent.id,
        COALESCE(p_response_payload, '{}'::jsonb),
        'PENDING'
    );

    RETURN jsonb_build_object(
        'intentId', v_intent.intent_id,
        'status', v_intent.status,
        'response', v_intent.response_payload,
        'outboxEventKey', v_event_key,
        'replayed', FALSE
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.record_gateway_payment_event_delivery_v1(
    p_event_key TEXT,
    p_delivered BOOLEAN,
    p_error TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE public.gateway_payment_event_outbox
    SET
        status = CASE WHEN p_delivered THEN 'DELIVERED' ELSE 'FAILED' END,
        attempt_count = attempt_count + 1,
        delivered_at = CASE WHEN p_delivered THEN NOW() ELSE delivered_at END,
        next_attempt_at = CASE
            WHEN p_delivered THEN next_attempt_at
            ELSE NOW() + (LEAST(POWER(2, attempt_count + 1), 60)::TEXT || ' minutes')::INTERVAL
        END,
        last_error = CASE WHEN p_delivered THEN NULL ELSE LEFT(COALESCE(p_error, 'DELIVERY_FAILED'), 1000) END,
        updated_at = NOW()
    WHERE event_key = p_event_key;
END;
$$;

REVOKE ALL ON FUNCTION public.persist_gateway_payment_intent_v1(
    TEXT, TEXT, TEXT, TEXT, TEXT, UUID, UUID, NUMERIC, TEXT, TEXT,
    JSONB, JSONB, TEXT, TEXT, TIMESTAMP WITH TIME ZONE, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.record_gateway_payment_event_delivery_v1(TEXT, BOOLEAN, TEXT)
    FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.persist_gateway_payment_intent_v1(TEXT, TEXT, TEXT, TEXT, TEXT, UUID, UUID, NUMERIC, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TIMESTAMP WITH TIME ZONE, JSONB) FROM anon';
        EXECUTE 'REVOKE ALL ON FUNCTION public.record_gateway_payment_event_delivery_v1(TEXT, BOOLEAN, TEXT) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.persist_gateway_payment_intent_v1(TEXT, TEXT, TEXT, TEXT, TEXT, UUID, UUID, NUMERIC, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TIMESTAMP WITH TIME ZONE, JSONB) FROM authenticated';
        EXECUTE 'REVOKE ALL ON FUNCTION public.record_gateway_payment_event_delivery_v1(TEXT, BOOLEAN, TEXT) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.persist_gateway_payment_intent_v1(TEXT, TEXT, TEXT, TEXT, TEXT, UUID, UUID, NUMERIC, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TIMESTAMP WITH TIME ZONE, JSONB) TO service_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.record_gateway_payment_event_delivery_v1(TEXT, BOOLEAN, TEXT) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260618_gateway_intent_challenge_store.sql

-- BEGIN SYNCED MIGRATION: 20260618_shared_pot_hardening.sql
-- Atomic Shared Pot lifecycle hardening.
-- Financial and membership mutations are service-role-only and database authoritative.

ALTER TABLE public.shared_pots
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE public.shared_pots
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS governance_model TEXT NOT NULL DEFAULT 'OWNER_CONTROLLED',
    ADD COLUMN IF NOT EXISTS withdrawal_policy TEXT NOT NULL DEFAULT 'OWNER_OR_MANAGER',
    ADD COLUMN IF NOT EXISTS min_withdrawal_approvals INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS withdrawal_limit_amount NUMERIC,
    ADD COLUMN IF NOT EXISTS maturity_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS require_withdrawal_reason BOOLEAN NOT NULL DEFAULT false;

DO $$
BEGIN
    ALTER TABLE public.shared_pots
        DROP CONSTRAINT IF EXISTS shared_pots_governance_model_check,
        ADD CONSTRAINT shared_pots_governance_model_check
            CHECK (governance_model IN ('OWNER_CONTROLLED', 'MEMBER_APPROVAL', 'ORG_APPROVAL'));
    ALTER TABLE public.shared_pots
        DROP CONSTRAINT IF EXISTS shared_pots_withdrawal_policy_check,
        ADD CONSTRAINT shared_pots_withdrawal_policy_check
            CHECK (withdrawal_policy IN ('OWNER_ONLY', 'OWNER_OR_MANAGER', 'APPROVAL_REQUIRED'));
    ALTER TABLE public.shared_pots
        DROP CONSTRAINT IF EXISTS shared_pots_min_withdrawal_approvals_check,
        ADD CONSTRAINT shared_pots_min_withdrawal_approvals_check
            CHECK (min_withdrawal_approvals >= 1 AND min_withdrawal_approvals <= 10);
END $$;

UPDATE public.shared_pots
SET
    governance_model = CASE
        WHEN access_model = 'ORG' THEN 'ORG_APPROVAL'
        ELSE 'OWNER_CONTROLLED'
    END,
    withdrawal_policy = CASE
        WHEN access_model = 'ORG' THEN 'APPROVAL_REQUIRED'
        WHEN access_model = 'PRIVATE' THEN 'OWNER_ONLY'
        ELSE 'OWNER_OR_MANAGER'
    END,
    min_withdrawal_approvals = CASE
        WHEN access_model = 'ORG' THEN GREATEST(min_withdrawal_approvals, 2)
        ELSE min_withdrawal_approvals
    END
WHERE withdrawal_policy = 'APPROVAL_REQUIRED'
   OR governance_model = 'MEMBER_APPROVAL';

CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_pots_owner_idempotency
    ON public.shared_pots(owner_user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

ALTER TABLE public.shared_pot_invitations
    ADD COLUMN IF NOT EXISTS response_idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_pot_invitation_response_idempotency
    ON public.shared_pot_invitations(invitee_user_id, response_idempotency_key)
    WHERE response_idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_pot_withdrawal_request_idempotency
    ON public.shared_pot_withdrawal_requests(requester_user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_shared_pot_withdrawal_requests_pot
    ON public.shared_pot_withdrawal_requests(pot_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_withdrawal_requests_requester
    ON public.shared_pot_withdrawal_requests(requester_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_delete_requests_pot
    ON public.shared_pot_delete_requests(pot_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shared_pot_delete_requests_due
    ON public.shared_pot_delete_requests(status, scheduled_archive_at);

ALTER TABLE public.shared_pots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shared_pot_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shared_pot_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shared_pot_withdrawal_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shared_pot_delete_requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS shared_pots_service_role ON public.shared_pots;
CREATE POLICY shared_pots_service_role ON public.shared_pots
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS shared_pot_members_service_role ON public.shared_pot_members;
CREATE POLICY shared_pot_members_service_role ON public.shared_pot_members
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS shared_pot_invitations_service_role ON public.shared_pot_invitations;
CREATE POLICY shared_pot_invitations_service_role ON public.shared_pot_invitations
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS shared_pot_withdrawal_requests_service_role ON public.shared_pot_withdrawal_requests;
CREATE POLICY shared_pot_withdrawal_requests_service_role ON public.shared_pot_withdrawal_requests
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS shared_pot_delete_requests_service_role ON public.shared_pot_delete_requests;
CREATE POLICY shared_pot_delete_requests_service_role ON public.shared_pot_delete_requests
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP FUNCTION IF EXISTS public.shared_pot_contribute_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
);
DROP FUNCTION IF EXISTS public.shared_pot_withdraw_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB
);

CREATE OR REPLACE FUNCTION public.create_shared_pot_v1(
    p_actor_user_id UUID,
    p_name TEXT,
    p_purpose TEXT DEFAULT NULL,
    p_currency TEXT DEFAULT 'TZS',
    p_target_amount NUMERIC DEFAULT 0,
    p_access_model TEXT DEFAULT 'INVITE',
    p_idempotency_key TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_actor_user_id);
    v_pot public.shared_pots%ROWTYPE;
    v_currency TEXT := UPPER(BTRIM(COALESCE(p_currency, 'TZS')));
    v_access_model TEXT := UPPER(BTRIM(COALESCE(p_access_model, 'INVITE')));
    v_key TEXT := NULLIF(BTRIM(COALESCE(p_idempotency_key, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_actor_user_id) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_INVALID';
    END IF;
    IF NULLIF(BTRIM(COALESCE(p_name, '')), '') IS NULL THEN
        RAISE EXCEPTION 'SHARED_POT_NAME_REQUIRED';
    END IF;
    IF COALESCE(p_target_amount, 0) < 0 THEN
        RAISE EXCEPTION 'SHARED_POT_TARGET_INVALID';
    END IF;
    IF v_access_model NOT IN ('INVITE', 'PRIVATE', 'ORG') THEN
        RAISE EXCEPTION 'SHARED_POT_ACCESS_MODEL_INVALID';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.users
        WHERE id = v_actor AND LOWER(COALESCE(account_status, '')) = 'active'
    ) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_NOT_ACTIVE';
    END IF;

    IF v_key IS NOT NULL THEN
        SELECT * INTO v_pot
        FROM public.shared_pots
        WHERE owner_user_id = v_actor AND idempotency_key = v_key
        FOR UPDATE;

        IF FOUND THEN
            IF v_pot.name <> BTRIM(p_name)
               OR UPPER(COALESCE(v_pot.currency, '')) <> v_currency
               OR COALESCE(v_pot.target_amount, 0) <> COALESCE(p_target_amount, 0) THEN
                RAISE EXCEPTION 'SHARED_POT_CREATE_REPLAY_MISMATCH';
            END IF;
            RETURN jsonb_build_object('pot', to_jsonb(v_pot), 'idempotent', TRUE);
        END IF;
    END IF;

    INSERT INTO public.shared_pots (
        owner_user_id, name, purpose, currency, target_amount, current_amount,
        status, access_model, idempotency_key, metadata
    ) VALUES (
        v_actor,
        BTRIM(p_name),
        NULLIF(BTRIM(COALESCE(p_purpose, '')), ''),
        v_currency,
        COALESCE(p_target_amount, 0),
        0,
        'ACTIVE',
        v_access_model,
        v_key,
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object('created_by', v_actor, 'created_atomically', TRUE)
    )
    RETURNING * INTO v_pot;

    INSERT INTO public.shared_pot_members (
        pot_id, user_id, role, status, contributed_amount, metadata
    ) VALUES (
        v_pot.id, v_actor, 'OWNER', 'ACTIVE', 0,
        jsonb_build_object('owner_membership', TRUE, 'created_atomically', TRUE)
    );

    RETURN jsonb_build_object('pot', to_jsonb(v_pot), 'idempotent', FALSE);
END;
$$;

CREATE OR REPLACE FUNCTION public.respond_shared_pot_invitation_v1(
    p_actor_user_id UUID,
    p_invitation_id UUID,
    p_action TEXT,
    p_idempotency_key TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_actor_user_id);
    v_action TEXT := UPPER(BTRIM(COALESCE(p_action, '')));
    v_key TEXT := NULLIF(BTRIM(COALESCE(p_idempotency_key, '')), '');
    v_invite public.shared_pot_invitations%ROWTYPE;
    v_member public.shared_pot_members%ROWTYPE;
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_actor_user_id) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_INVALID';
    END IF;
    IF v_action NOT IN ('ACCEPT', 'REJECT') THEN
        RAISE EXCEPTION 'SHARED_POT_INVITE_ACTION_INVALID';
    END IF;

    SELECT * INTO v_invite
    FROM public.shared_pot_invitations
    WHERE id = p_invitation_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SHARED_POT_INVITE_NOT_FOUND';
    END IF;
    IF v_invite.invitee_user_id <> v_actor THEN
        RAISE EXCEPTION 'SHARED_POT_INVITE_ACCESS_DENIED';
    END IF;

    IF v_invite.status IN ('ACCEPTED', 'REJECTED')
       AND ((v_action = 'ACCEPT' AND v_invite.status = 'ACCEPTED')
         OR (v_action = 'REJECT' AND v_invite.status = 'REJECTED')) THEN
        SELECT * INTO v_member
        FROM public.shared_pot_members
        WHERE pot_id = v_invite.pot_id AND user_id = v_actor;
        RETURN jsonb_build_object(
            'invitation', to_jsonb(v_invite),
            'member', CASE WHEN v_member.id IS NULL THEN NULL ELSE to_jsonb(v_member) END,
            'idempotent', TRUE
        );
    END IF;

    IF v_invite.status <> 'PENDING' THEN
        RAISE EXCEPTION 'SHARED_POT_INVITE_NOT_PENDING';
    END IF;
    IF v_invite.expires_at IS NOT NULL AND v_invite.expires_at <= NOW() THEN
        UPDATE public.shared_pot_invitations
        SET status = 'EXPIRED', responded_at = NOW(), updated_at = NOW()
        WHERE id = v_invite.id
        RETURNING * INTO v_invite;
        RAISE EXCEPTION 'SHARED_POT_INVITE_EXPIRED';
    END IF;

    IF v_action = 'ACCEPT' THEN
        INSERT INTO public.shared_pot_members (
            pot_id, user_id, role, status, contributed_amount, metadata
        ) VALUES (
            v_invite.pot_id,
            v_actor,
            v_invite.role,
            'ACTIVE',
            0,
            jsonb_build_object(
                'joined_via_invitation', v_invite.id,
                'invited_by', v_invite.inviter_user_id,
                'created_atomically', TRUE
            )
        )
        ON CONFLICT (pot_id, user_id) DO UPDATE
        SET
            role = EXCLUDED.role,
            status = 'ACTIVE',
            metadata = COALESCE(public.shared_pot_members.metadata, '{}'::jsonb)
                || EXCLUDED.metadata
        RETURNING * INTO v_member;
    END IF;

    UPDATE public.shared_pot_invitations
    SET
        status = CASE WHEN v_action = 'ACCEPT' THEN 'ACCEPTED' ELSE 'REJECTED' END,
        response_idempotency_key = v_key,
        responded_at = NOW(),
        updated_at = NOW()
    WHERE id = v_invite.id
    RETURNING * INTO v_invite;

    RETURN jsonb_build_object(
        'invitation', to_jsonb(v_invite),
        'member', CASE WHEN v_member.id IS NULL THEN NULL ELSE to_jsonb(v_member) END,
        'idempotent', FALSE
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.shared_pot_contribute_v1(
    p_user_id UUID,
    p_pot_id UUID,
    p_source_wallet_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_reference_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_user_id);
    v_pot public.shared_pots%ROWTYPE;
    v_member public.shared_pot_members%ROWTYPE;
    v_source_wallet public.wallets%ROWTYPE;
    v_source_vault public.platform_vaults%ROWTYPE;
    v_existing public.transactions%ROWTYPE;
    v_source_table TEXT;
    v_source_currency TEXT;
    v_source_balance NUMERIC;
    v_source_balance_after NUMERIC;
    v_pot_balance_after NUMERIC;
    v_tx_id UUID := gen_random_uuid();
    v_reference_id TEXT := NULLIF(BTRIM(COALESCE(p_reference_id, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_user_id) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_INVALID';
    END IF;
    IF p_amount IS NULL OR p_amount <= 0 THEN
        RAISE EXCEPTION 'INVALID_AMOUNT';
    END IF;
    IF v_reference_id IS NULL THEN
        RAISE EXCEPTION 'SHARED_POT_IDEMPOTENCY_REQUIRED';
    END IF;

    SELECT * INTO v_pot
    FROM public.shared_pots
    WHERE id = p_pot_id
    FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_POT_NOT_FOUND'; END IF;
    IF v_pot.status <> 'ACTIVE' THEN RAISE EXCEPTION 'SHARED_POT_NOT_ACTIVE'; END IF;

    SELECT * INTO v_member
    FROM public.shared_pot_members
    WHERE pot_id = p_pot_id AND user_id = v_actor AND status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND OR v_member.role NOT IN ('OWNER', 'MANAGER', 'CONTRIBUTOR') THEN
        RAISE EXCEPTION 'SHARED_POT_CONTRIBUTION_DENIED';
    END IF;

    SELECT * INTO v_existing
    FROM public.transactions
    WHERE reference_id = v_reference_id
    FOR UPDATE;
    IF FOUND THEN
        IF v_existing.user_id <> v_actor
           OR v_existing.wallet_id <> p_source_wallet_id
           OR v_existing.amount::NUMERIC <> p_amount
           OR v_existing.allocation_source <> 'SHARED_POT_CONTRIBUTION'
           OR v_existing.metadata->>'shared_pot_id' <> p_pot_id::TEXT THEN
            RAISE EXCEPTION 'SHARED_POT_REPLAY_MISMATCH';
        END IF;
        RETURN jsonb_build_object(
            'transaction_id', v_existing.id,
            'reference_id', v_reference_id,
            'pot_balance_after', v_pot.current_amount,
            'idempotent', TRUE
        );
    END IF;

    SELECT * INTO v_source_vault
    FROM public.platform_vaults
    WHERE id = p_source_wallet_id AND user_id = v_actor
    FOR UPDATE;
    IF FOUND THEN
        IF COALESCE(v_source_vault.is_locked, FALSE)
           OR LOWER(COALESCE(v_source_vault.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'SOURCE_WALLET_UNAVAILABLE';
        END IF;
        v_source_table := 'platform_vaults';
        v_source_balance := COALESCE(v_source_vault.balance, 0);
        v_source_currency := UPPER(COALESCE(v_source_vault.currency, 'TZS'));
    ELSE
        SELECT * INTO v_source_wallet
        FROM public.wallets
        WHERE id = p_source_wallet_id AND user_id = v_actor
        FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'NO_OPERATING_WALLET'; END IF;
        IF COALESCE(v_source_wallet.is_locked, FALSE)
           OR LOWER(COALESCE(v_source_wallet.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'SOURCE_WALLET_UNAVAILABLE';
        END IF;
        v_source_table := 'wallets';
        v_source_balance := COALESCE(v_source_wallet.balance, 0);
        v_source_currency := UPPER(COALESCE(v_source_wallet.currency, 'TZS'));
    END IF;

    IF v_source_currency <> UPPER(COALESCE(v_pot.currency, 'TZS'))
       OR UPPER(BTRIM(COALESCE(p_currency, v_pot.currency, 'TZS'))) <> UPPER(COALESCE(v_pot.currency, 'TZS')) THEN
        RAISE EXCEPTION 'SHARED_POT_CURRENCY_MISMATCH';
    END IF;
    IF v_source_balance < p_amount THEN RAISE EXCEPTION 'INSUFFICIENT_FUNDS'; END IF;

    v_source_balance_after := v_source_balance - p_amount;
    v_pot_balance_after := COALESCE(v_pot.current_amount, 0) + p_amount;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description,
        type, status, date, wealth_impact_type, protection_state, allocation_source, metadata
    ) VALUES (
        v_tx_id, v_reference_id, v_actor, p_source_wallet_id, p_amount::TEXT,
        UPPER(v_pot.currency),
        COALESCE(NULLIF(BTRIM(COALESCE(p_description, '')), ''), 'Shared pot contribution'),
        'internal_transfer', 'completed', CURRENT_DATE, 'GROWING', 'OPEN',
        'SHARED_POT_CONTRIBUTION',
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object('shared_pot_id', p_pot_id, 'actor_user_id', v_actor)
    );

    IF v_source_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_source_balance_after, updated_at = NOW()
        WHERE id = p_source_wallet_id AND user_id = v_actor;
    ELSE
        UPDATE public.platform_vaults SET balance = v_source_balance_after, updated_at = NOW()
        WHERE id = p_source_wallet_id AND user_id = v_actor;
    END IF;

    UPDATE public.shared_pots
    SET current_amount = v_pot_balance_after, updated_at = NOW()
    WHERE id = p_pot_id;

    UPDATE public.shared_pot_members
    SET contributed_amount = COALESCE(contributed_amount, 0) + p_amount
    WHERE id = v_member.id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, shared_pot_id, bucket_type,
        entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (
        v_tx_id, v_actor, p_source_wallet_id, p_pot_id, 'OPERATING',
        'DEBIT', 'DEBIT', p_amount::TEXT, v_source_balance_after::TEXT,
        'Shared pot contribution debit: ' || v_pot.name
    ),
    (
        v_tx_id, v_actor, p_source_wallet_id, p_pot_id, 'GROWING',
        'CREDIT', 'CREDIT', p_amount::TEXT, v_pot_balance_after::TEXT,
        'Shared pot contribution credit: ' || v_pot.name
    );

    RETURN jsonb_build_object(
        'transaction_id', v_tx_id,
        'reference_id', v_reference_id,
        'source_balance_after', v_source_balance_after,
        'pot_balance_after', v_pot_balance_after,
        'source_table', v_source_table,
        'idempotent', FALSE
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.shared_pot_withdraw_v1(
    p_user_id UUID,
    p_pot_id UUID,
    p_target_wallet_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_reference_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_user_id);
    v_pot public.shared_pots%ROWTYPE;
    v_member public.shared_pot_members%ROWTYPE;
    v_target_wallet public.wallets%ROWTYPE;
    v_target_vault public.platform_vaults%ROWTYPE;
    v_existing public.transactions%ROWTYPE;
    v_target_table TEXT;
    v_target_currency TEXT;
    v_target_balance NUMERIC;
    v_target_balance_after NUMERIC;
    v_pot_balance_after NUMERIC;
    v_tx_id UUID := gen_random_uuid();
    v_reference_id TEXT := NULLIF(BTRIM(COALESCE(p_reference_id, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_user_id) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_INVALID';
    END IF;
    IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_reference_id IS NULL THEN RAISE EXCEPTION 'SHARED_POT_IDEMPOTENCY_REQUIRED'; END IF;

    SELECT * INTO v_pot
    FROM public.shared_pots
    WHERE id = p_pot_id
    FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_POT_NOT_FOUND'; END IF;
    IF v_pot.status <> 'ACTIVE' THEN RAISE EXCEPTION 'SHARED_POT_NOT_ACTIVE'; END IF;

    SELECT * INTO v_member
    FROM public.shared_pot_members
    WHERE pot_id = p_pot_id AND user_id = v_actor AND status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND OR v_member.role NOT IN ('OWNER', 'MANAGER') THEN
        RAISE EXCEPTION 'SHARED_POT_WITHDRAW_DENIED';
    END IF;

    SELECT * INTO v_existing
    FROM public.transactions
    WHERE reference_id = v_reference_id
    FOR UPDATE;
    IF FOUND THEN
        IF v_existing.user_id <> v_actor
           OR v_existing.wallet_id <> p_target_wallet_id
           OR v_existing.amount::NUMERIC <> p_amount
           OR v_existing.allocation_source <> 'SHARED_POT_WITHDRAWAL'
           OR v_existing.metadata->>'shared_pot_id' <> p_pot_id::TEXT THEN
            RAISE EXCEPTION 'SHARED_POT_REPLAY_MISMATCH';
        END IF;
        RETURN jsonb_build_object(
            'transaction_id', v_existing.id,
            'reference_id', v_reference_id,
            'pot_balance_after', v_pot.current_amount,
            'idempotent', TRUE
        );
    END IF;

    IF COALESCE(v_pot.current_amount, 0) < p_amount THEN
        RAISE EXCEPTION 'INSUFFICIENT_POT_FUNDS';
    END IF;

    SELECT * INTO v_target_vault
    FROM public.platform_vaults
    WHERE id = p_target_wallet_id AND user_id = v_actor
    FOR UPDATE;
    IF FOUND THEN
        IF COALESCE(v_target_vault.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_vault.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        v_target_table := 'platform_vaults';
        v_target_balance := COALESCE(v_target_vault.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_vault.currency, 'TZS'));
    ELSE
        SELECT * INTO v_target_wallet
        FROM public.wallets
        WHERE id = p_target_wallet_id AND user_id = v_actor
        FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'NO_OPERATING_WALLET'; END IF;
        IF COALESCE(v_target_wallet.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_wallet.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        v_target_table := 'wallets';
        v_target_balance := COALESCE(v_target_wallet.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_wallet.currency, 'TZS'));
    END IF;

    IF v_target_currency <> UPPER(COALESCE(v_pot.currency, 'TZS'))
       OR UPPER(BTRIM(COALESCE(p_currency, v_pot.currency, 'TZS'))) <> UPPER(COALESCE(v_pot.currency, 'TZS')) THEN
        RAISE EXCEPTION 'SHARED_POT_CURRENCY_MISMATCH';
    END IF;

    v_target_balance_after := v_target_balance + p_amount;
    v_pot_balance_after := COALESCE(v_pot.current_amount, 0) - p_amount;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description,
        type, status, date, wealth_impact_type, protection_state, allocation_source, metadata
    ) VALUES (
        v_tx_id, v_reference_id, v_actor, p_target_wallet_id, p_amount::TEXT,
        UPPER(v_pot.currency),
        COALESCE(NULLIF(BTRIM(COALESCE(p_description, '')), ''), 'Shared pot withdrawal'),
        'internal_transfer', 'completed', CURRENT_DATE, 'GROWING', 'OPEN',
        'SHARED_POT_WITHDRAWAL',
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object('shared_pot_id', p_pot_id, 'actor_user_id', v_actor)
    );

    IF v_target_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    ELSE
        UPDATE public.platform_vaults SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    END IF;

    UPDATE public.shared_pots
    SET current_amount = v_pot_balance_after, updated_at = NOW()
    WHERE id = p_pot_id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, shared_pot_id, bucket_type,
        entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (
        v_tx_id, v_actor, p_target_wallet_id, p_pot_id, 'GROWING',
        'DEBIT', 'DEBIT', p_amount::TEXT, v_pot_balance_after::TEXT,
        'Shared pot withdrawal debit: ' || v_pot.name
    ),
    (
        v_tx_id, v_actor, p_target_wallet_id, p_pot_id, 'OPERATING',
        'CREDIT', 'CREDIT', p_amount::TEXT, v_target_balance_after::TEXT,
        'Shared pot withdrawal credit: ' || v_pot.name
    );

    RETURN jsonb_build_object(
        'transaction_id', v_tx_id,
        'reference_id', v_reference_id,
        'target_balance_after', v_target_balance_after,
        'pot_balance_after', v_pot_balance_after,
        'target_table', v_target_table,
        'idempotent', FALSE
    );
END;
$$;

REVOKE ALL ON FUNCTION public.create_shared_pot_v1(
    UUID, TEXT, TEXT, TEXT, NUMERIC, TEXT, TEXT, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_shared_pot_invitation_v1(UUID, UUID, TEXT, TEXT)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION public.shared_pot_contribute_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.create_shared_pot_v1(UUID, TEXT, TEXT, TEXT, NUMERIC, TEXT, TEXT, JSONB) FROM anon';
        EXECUTE 'REVOKE ALL ON FUNCTION public.respond_shared_pot_invitation_v1(UUID, UUID, TEXT, TEXT) FROM anon';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_contribute_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM anon';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.create_shared_pot_v1(UUID, TEXT, TEXT, TEXT, NUMERIC, TEXT, TEXT, JSONB) FROM authenticated';
        EXECUTE 'REVOKE ALL ON FUNCTION public.respond_shared_pot_invitation_v1(UUID, UUID, TEXT, TEXT) FROM authenticated';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_contribute_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM authenticated';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_shared_pot_v1(UUID, TEXT, TEXT, TEXT, NUMERIC, TEXT, TEXT, JSONB) TO service_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.respond_shared_pot_invitation_v1(UUID, UUID, TEXT, TEXT) TO service_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.shared_pot_contribute_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) TO service_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260618_shared_pot_hardening.sql

-- END 20260618 SHARED FINANCE AND PAYSAFE HARDENING SYNC

-- BEGIN SYNCED MIGRATION: 20260715_shared_pot_withdraw_staged_operating.sql
-- Enforces Fungu -> PaySafe/Internal Transfer staging -> Operating wallet credit.
-- This keeps shared-pot withdrawals auditable without treating them as external income.

CREATE OR REPLACE FUNCTION public.shared_pot_withdraw_v1(
    p_user_id UUID,
    p_pot_id UUID,
    p_target_wallet_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_reference_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_user_id);
    v_pot public.shared_pots%ROWTYPE;
    v_member public.shared_pot_members%ROWTYPE;
    v_target_wallet public.wallets%ROWTYPE;
    v_target_vault public.platform_vaults%ROWTYPE;
    v_staging_vault public.platform_vaults%ROWTYPE;
    v_existing public.transactions%ROWTYPE;
    v_target_table TEXT;
    v_target_role TEXT;
    v_target_currency TEXT;
    v_target_balance NUMERIC;
    v_target_balance_after NUMERIC;
    v_staging_balance NUMERIC;
    v_staging_balance_after_hold NUMERIC;
    v_staging_balance_after_release NUMERIC;
    v_pot_balance_after NUMERIC;
    v_tx_id UUID := gen_random_uuid();
    v_reference_id TEXT := NULLIF(BTRIM(COALESCE(p_reference_id, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_user_id) THEN
        RAISE EXCEPTION 'SHARED_POT_ACTOR_INVALID';
    END IF;
    IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_reference_id IS NULL THEN RAISE EXCEPTION 'SHARED_POT_IDEMPOTENCY_REQUIRED'; END IF;

    SELECT * INTO v_pot
    FROM public.shared_pots
    WHERE id = p_pot_id
    FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_POT_NOT_FOUND'; END IF;
    IF v_pot.status <> 'ACTIVE' THEN RAISE EXCEPTION 'SHARED_POT_NOT_ACTIVE'; END IF;

    SELECT * INTO v_member
    FROM public.shared_pot_members
    WHERE pot_id = p_pot_id AND user_id = v_actor AND status = 'ACTIVE'
    FOR UPDATE;
    IF NOT FOUND OR v_member.role NOT IN ('OWNER', 'MANAGER', 'CONTRIBUTOR') THEN
        RAISE EXCEPTION 'SHARED_POT_WITHDRAW_DENIED';
    END IF;

    SELECT * INTO v_existing
    FROM public.transactions
    WHERE reference_id = v_reference_id
    FOR UPDATE;
    IF FOUND THEN
        IF v_existing.user_id <> v_actor
           OR v_existing.wallet_id <> p_target_wallet_id
           OR v_existing.amount::NUMERIC <> p_amount
           OR v_existing.allocation_source <> 'SHARED_POT_WITHDRAWAL'
           OR v_existing.metadata->>'shared_pot_id' <> p_pot_id::TEXT THEN
            RAISE EXCEPTION 'SHARED_POT_REPLAY_MISMATCH';
        END IF;
        RETURN jsonb_build_object(
            'transaction_id', v_existing.id,
            'reference_id', v_reference_id,
            'pot_balance_after', v_pot.current_amount,
            'idempotent', TRUE
        );
    END IF;

    IF COALESCE(v_pot.current_amount, 0) < p_amount THEN
        RAISE EXCEPTION 'INSUFFICIENT_POT_FUNDS';
    END IF;

    SELECT * INTO v_staging_vault
    FROM public.platform_vaults
    WHERE user_id = v_actor
      AND vault_role = 'INTERNAL_TRANSFER'
      AND LOWER(COALESCE(status, 'active')) = 'active'
      AND COALESCE(is_locked, FALSE) IS FALSE
    ORDER BY created_at ASC NULLS LAST
    LIMIT 1
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SHARED_POT_STAGING_VAULT_UNAVAILABLE';
    END IF;

    SELECT * INTO v_target_vault
    FROM public.platform_vaults
    WHERE id = p_target_wallet_id AND user_id = v_actor
    FOR UPDATE;
    IF FOUND THEN
        IF COALESCE(v_target_vault.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_vault.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        IF v_target_vault.vault_role <> 'OPERATING' THEN
            RAISE EXCEPTION 'SHARED_POT_TARGET_MUST_BE_OPERATING';
        END IF;
        v_target_table := 'platform_vaults';
        v_target_role := v_target_vault.vault_role;
        v_target_balance := COALESCE(v_target_vault.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_vault.currency, 'TZS'));
    ELSE
        SELECT * INTO v_target_wallet
        FROM public.wallets
        WHERE id = p_target_wallet_id AND user_id = v_actor
        FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'NO_OPERATING_WALLET'; END IF;
        IF COALESCE(v_target_wallet.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_wallet.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        IF UPPER(COALESCE(v_target_wallet.type, '')) <> 'OPERATING' THEN
            RAISE EXCEPTION 'SHARED_POT_TARGET_MUST_BE_OPERATING';
        END IF;
        v_target_table := 'wallets';
        v_target_role := v_target_wallet.type;
        v_target_balance := COALESCE(v_target_wallet.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_wallet.currency, 'TZS'));
    END IF;

    IF UPPER(COALESCE(v_staging_vault.currency, 'TZS')) <> UPPER(COALESCE(v_pot.currency, 'TZS'))
       OR v_target_currency <> UPPER(COALESCE(v_pot.currency, 'TZS'))
       OR UPPER(BTRIM(COALESCE(p_currency, v_pot.currency, 'TZS'))) <> UPPER(COALESCE(v_pot.currency, 'TZS')) THEN
        RAISE EXCEPTION 'SHARED_POT_CURRENCY_MISMATCH';
    END IF;

    v_staging_balance := COALESCE(v_staging_vault.balance, 0);
    v_staging_balance_after_hold := v_staging_balance + p_amount;
    v_staging_balance_after_release := v_staging_balance;
    v_target_balance_after := v_target_balance + p_amount;
    v_pot_balance_after := COALESCE(v_pot.current_amount, 0) - p_amount;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description,
        type, status, date, wealth_impact_type, protection_state, allocation_source, metadata
    ) VALUES (
        v_tx_id, v_reference_id, v_actor, p_target_wallet_id, p_amount::TEXT,
        UPPER(v_pot.currency),
        COALESCE(NULLIF(BTRIM(COALESCE(p_description, '')), ''), 'Shared pot withdrawal'),
        'internal_transfer', 'completed', CURRENT_DATE, 'GROWING', 'OPEN',
        'SHARED_POT_WITHDRAWAL',
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object(
                'shared_pot_id', p_pot_id,
                'actor_user_id', v_actor,
                'shared_pot_withdrawal_flow', 'POT_TO_PAYSAFE_TO_OPERATING',
                'staging_vault_id', v_staging_vault.id,
                'staging_vault_role', v_staging_vault.vault_role,
                'target_table', v_target_table,
                'target_wallet_role', v_target_role,
                'movement_family', 'INTERNAL_SS',
                'movement_code', 'SS_SHARED_POT_WITHDRAWAL'
            )
    );

    UPDATE public.platform_vaults
    SET balance = v_staging_balance_after_release, updated_at = NOW()
    WHERE id = v_staging_vault.id AND user_id = v_actor;

    IF v_target_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    ELSE
        UPDATE public.platform_vaults SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    END IF;

    UPDATE public.shared_pots
    SET current_amount = v_pot_balance_after, updated_at = NOW()
    WHERE id = p_pot_id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, shared_pot_id, bucket_type,
        entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (
        v_tx_id, v_actor, v_staging_vault.id, p_pot_id, 'GROWING',
        'DEBIT', 'DEBIT', p_amount::TEXT, v_pot_balance_after::TEXT,
        'Shared pot withdrawal debit: ' || v_pot.name
    ),
    (
        v_tx_id, v_actor, v_staging_vault.id, p_pot_id, 'INTERNAL_TRANSFER',
        'CREDIT', 'CREDIT', p_amount::TEXT, v_staging_balance_after_hold::TEXT,
        'Shared pot withdrawal staging hold: ' || v_pot.name
    ),
    (
        v_tx_id, v_actor, v_staging_vault.id, p_pot_id, 'INTERNAL_TRANSFER',
        'DEBIT', 'DEBIT', p_amount::TEXT, v_staging_balance_after_release::TEXT,
        'Shared pot withdrawal staging release: ' || v_pot.name
    ),
    (
        v_tx_id, v_actor, p_target_wallet_id, p_pot_id, 'OPERATING',
        'CREDIT', 'CREDIT', p_amount::TEXT, v_target_balance_after::TEXT,
        'Shared pot withdrawal operating credit: ' || v_pot.name
    );

    RETURN jsonb_build_object(
        'transaction_id', v_tx_id,
        'reference_id', v_reference_id,
        'target_balance_after', v_target_balance_after,
        'staging_balance_after', v_staging_balance_after_release,
        'pot_balance_after', v_pot_balance_after,
        'target_table', v_target_table,
        'staging_vault_id', v_staging_vault.id,
        'flow', 'POT_TO_PAYSAFE_TO_OPERATING',
        'idempotent', FALSE
    );
END;
$$;

REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.shared_pot_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260715_shared_pot_withdraw_staged_operating.sql

-- BEGIN SYNCED MIGRATION: 20260716_shared_budget_funded_ledger.sql
-- Mezani is a funded budget reserve. Create stays free; Allocate moves money
-- from Operating to the Mezani reserve, and Spend/Withdraw consumes that reserve.

ALTER TABLE public.shared_budgets
    ADD COLUMN IF NOT EXISTS funded_amount NUMERIC DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_allocate_enabled BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS auto_allocate_mode TEXT DEFAULT 'MANUAL',
    ADD COLUMN IF NOT EXISTS auto_allocate_amount NUMERIC DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_allocate_threshold NUMERIC DEFAULT 0;

UPDATE public.shared_budgets
   SET funded_amount = COALESCE(funded_amount, 0),
       auto_allocate_enabled = COALESCE(auto_allocate_enabled, FALSE),
       auto_allocate_mode = COALESCE(NULLIF(auto_allocate_mode, ''), 'MANUAL'),
       auto_allocate_amount = COALESCE(auto_allocate_amount, 0),
       auto_allocate_threshold = COALESCE(auto_allocate_threshold, 0)
 WHERE funded_amount IS NULL
    OR auto_allocate_enabled IS NULL
    OR auto_allocate_mode IS NULL
    OR auto_allocate_amount IS NULL
    OR auto_allocate_threshold IS NULL;

DROP FUNCTION IF EXISTS public.shared_budget_allocate_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
);
DROP FUNCTION IF EXISTS public.shared_budget_withdraw_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
);

CREATE OR REPLACE FUNCTION public.shared_budget_allocate_v1(
    p_user_id UUID,
    p_budget_id UUID,
    p_source_wallet_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_reference_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_user_id);
    v_budget public.shared_budgets%ROWTYPE;
    v_member public.shared_budget_members%ROWTYPE;
    v_source_wallet public.wallets%ROWTYPE;
    v_source_vault public.platform_vaults%ROWTYPE;
    v_existing public.transactions%ROWTYPE;
    v_source_table TEXT;
    v_source_currency TEXT;
    v_source_balance NUMERIC;
    v_source_balance_after NUMERIC;
    v_budget_funded_after NUMERIC;
    v_budget_available_after NUMERIC;
    v_tx_id UUID := gen_random_uuid();
    v_reference_id TEXT := NULLIF(BTRIM(COALESCE(p_reference_id, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_user_id) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_INVALID';
    END IF;
    IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_reference_id IS NULL THEN RAISE EXCEPTION 'SHARED_BUDGET_IDEMPOTENCY_REQUIRED'; END IF;

    SELECT * INTO v_budget FROM public.shared_budgets WHERE id = p_budget_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_BUDGET_NOT_FOUND'; END IF;
    IF v_budget.status <> 'ACTIVE' THEN RAISE EXCEPTION 'SHARED_BUDGET_NOT_ACTIVE'; END IF;

    SELECT * INTO v_member
      FROM public.shared_budget_members
     WHERE budget_id = p_budget_id AND user_id = v_actor AND status = 'ACTIVE'
     FOR UPDATE;
    IF NOT FOUND OR v_member.role NOT IN ('OWNER', 'MANAGER') THEN
        RAISE EXCEPTION 'SHARED_BUDGET_ALLOCATE_DENIED';
    END IF;

    SELECT * INTO v_existing FROM public.transactions WHERE reference_id = v_reference_id FOR UPDATE;
    IF FOUND THEN
        IF v_existing.user_id <> v_actor
           OR v_existing.wallet_id <> p_source_wallet_id
           OR v_existing.amount::NUMERIC <> p_amount
           OR v_existing.allocation_source <> 'SHARED_BUDGET_ALLOCATION'
           OR v_existing.metadata->>'shared_budget_id' <> p_budget_id::TEXT THEN
            RAISE EXCEPTION 'SHARED_BUDGET_REPLAY_MISMATCH';
        END IF;
        RETURN jsonb_build_object(
            'transaction_id', v_existing.id,
            'reference_id', v_reference_id,
            'budget_funded_after', v_budget.funded_amount,
            'budget_available_after', GREATEST(0, COALESCE(v_budget.funded_amount, 0) - COALESCE(v_budget.spent_amount, 0)),
            'idempotent', TRUE
        );
    END IF;

    SELECT * INTO v_source_vault
      FROM public.platform_vaults
     WHERE id = p_source_wallet_id AND user_id = v_actor AND vault_role = 'OPERATING'
     FOR UPDATE;
    IF FOUND THEN
        IF COALESCE(v_source_vault.is_locked, FALSE)
           OR LOWER(COALESCE(v_source_vault.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'SOURCE_WALLET_UNAVAILABLE';
        END IF;
        v_source_table := 'platform_vaults';
        v_source_balance := COALESCE(v_source_vault.balance, 0);
        v_source_currency := UPPER(COALESCE(v_source_vault.currency, 'TZS'));
    ELSE
        SELECT * INTO v_source_wallet
          FROM public.wallets
         WHERE id = p_source_wallet_id AND user_id = v_actor AND UPPER(COALESCE(type, '')) = 'OPERATING'
         FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'NO_OPERATING_WALLET'; END IF;
        IF COALESCE(v_source_wallet.is_locked, FALSE)
           OR LOWER(COALESCE(v_source_wallet.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'SOURCE_WALLET_UNAVAILABLE';
        END IF;
        v_source_table := 'wallets';
        v_source_balance := COALESCE(v_source_wallet.balance, 0);
        v_source_currency := UPPER(COALESCE(v_source_wallet.currency, 'TZS'));
    END IF;

    IF v_source_currency <> UPPER(COALESCE(v_budget.currency, 'TZS'))
       OR UPPER(BTRIM(COALESCE(p_currency, v_budget.currency, 'TZS'))) <> UPPER(COALESCE(v_budget.currency, 'TZS')) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_CURRENCY_MISMATCH';
    END IF;
    IF COALESCE(v_budget.funded_amount, 0) + p_amount > COALESCE(v_budget.budget_limit, 0) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_ALLOCATION_LIMIT_EXCEEDED';
    END IF;
    IF v_source_balance < p_amount THEN RAISE EXCEPTION 'INSUFFICIENT_FUNDS'; END IF;

    v_source_balance_after := v_source_balance - p_amount;
    v_budget_funded_after := COALESCE(v_budget.funded_amount, 0) + p_amount;
    v_budget_available_after := GREATEST(0, v_budget_funded_after - COALESCE(v_budget.spent_amount, 0));

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, amount, currency, description,
        type, status, date, wealth_impact_type, protection_state, allocation_source,
        shared_budget_id, metadata
    ) VALUES (
        v_tx_id, v_reference_id, v_actor, p_source_wallet_id, p_amount::TEXT,
        UPPER(v_budget.currency),
        COALESCE(NULLIF(BTRIM(COALESCE(p_description, '')), ''), 'Mezani allocation'),
        'internal_transfer', 'completed', CURRENT_DATE, 'PLANNED', 'OPEN',
        'SHARED_BUDGET_ALLOCATION',
        p_budget_id,
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object('shared_budget_id', p_budget_id, 'actor_user_id', v_actor)
    );

    IF v_source_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_source_balance_after, updated_at = NOW()
        WHERE id = p_source_wallet_id AND user_id = v_actor;
    ELSE
        UPDATE public.platform_vaults SET balance = v_source_balance_after, updated_at = NOW()
        WHERE id = p_source_wallet_id AND user_id = v_actor;
    END IF;

    UPDATE public.shared_budgets SET funded_amount = v_budget_funded_after, updated_at = NOW()
    WHERE id = p_budget_id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, shared_budget_id, bucket_type,
        entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (v_tx_id, v_actor, p_source_wallet_id, p_budget_id, 'OPERATING',
     'DEBIT', 'DEBIT', p_amount::TEXT, v_source_balance_after::TEXT,
     'Mezani allocation debit: ' || v_budget.name),
    (v_tx_id, v_actor, NULL, p_budget_id, 'BUDGET',
     'CREDIT', 'CREDIT', p_amount::TEXT, v_budget_available_after::TEXT,
     'Mezani allocation credit: ' || v_budget.name);

    RETURN jsonb_build_object(
        'transaction_id', v_tx_id,
        'reference_id', v_reference_id,
        'source_balance_after', v_source_balance_after,
        'budget_funded_after', v_budget_funded_after,
        'budget_available_after', v_budget_available_after,
        'source_table', v_source_table,
        'idempotent', FALSE
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.shared_budget_withdraw_v1(
    p_user_id UUID,
    p_budget_id UUID,
    p_target_wallet_id UUID,
    p_amount NUMERIC,
    p_currency TEXT DEFAULT 'TZS',
    p_description TEXT DEFAULT NULL,
    p_reference_id TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor UUID := COALESCE(auth.uid(), p_user_id);
    v_budget public.shared_budgets%ROWTYPE;
    v_member public.shared_budget_members%ROWTYPE;
    v_target_wallet public.wallets%ROWTYPE;
    v_target_vault public.platform_vaults%ROWTYPE;
    v_existing public.transactions%ROWTYPE;
    v_target_table TEXT;
    v_target_currency TEXT;
    v_target_balance NUMERIC;
    v_target_balance_after NUMERIC;
    v_budget_spent_after NUMERIC;
    v_budget_available_after NUMERIC;
    v_tx_id UUID := gen_random_uuid();
    v_reference_id TEXT := NULLIF(BTRIM(COALESCE(p_reference_id, '')), '');
BEGIN
    IF v_actor IS NULL OR (auth.uid() IS NOT NULL AND auth.uid() <> p_user_id) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_ACTOR_INVALID';
    END IF;
    IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'INVALID_AMOUNT'; END IF;
    IF v_reference_id IS NULL THEN RAISE EXCEPTION 'SHARED_BUDGET_IDEMPOTENCY_REQUIRED'; END IF;

    SELECT * INTO v_budget FROM public.shared_budgets WHERE id = p_budget_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_BUDGET_NOT_FOUND'; END IF;
    IF v_budget.status <> 'ACTIVE' THEN RAISE EXCEPTION 'SHARED_BUDGET_NOT_ACTIVE'; END IF;

    SELECT * INTO v_member
      FROM public.shared_budget_members
     WHERE budget_id = p_budget_id AND user_id = v_actor AND status = 'ACTIVE'
     FOR UPDATE;
    IF NOT FOUND OR v_member.role NOT IN ('OWNER', 'MANAGER', 'SPENDER') THEN
        RAISE EXCEPTION 'SHARED_BUDGET_SPEND_DENIED';
    END IF;

    SELECT * INTO v_existing FROM public.transactions WHERE reference_id = v_reference_id FOR UPDATE;
    IF FOUND THEN
        IF v_existing.user_id <> v_actor
           OR v_existing.wallet_id <> p_target_wallet_id
           OR v_existing.amount::NUMERIC <> p_amount
           OR v_existing.allocation_source <> 'SHARED_BUDGET_WITHDRAWAL'
           OR v_existing.metadata->>'shared_budget_id' <> p_budget_id::TEXT THEN
            RAISE EXCEPTION 'SHARED_BUDGET_REPLAY_MISMATCH';
        END IF;
        RETURN jsonb_build_object(
            'transaction_id', v_existing.id,
            'reference_id', v_reference_id,
            'budget_spent_after', v_budget.spent_amount,
            'budget_available_after', GREATEST(0, COALESCE(v_budget.funded_amount, 0) - COALESCE(v_budget.spent_amount, 0)),
            'idempotent', TRUE
        );
    END IF;

    IF COALESCE(v_budget.funded_amount, 0) - COALESCE(v_budget.spent_amount, 0) < p_amount THEN
        RAISE EXCEPTION 'SHARED_BUDGET_FUNDS_REQUIRED';
    END IF;
    IF v_member.member_limit IS NOT NULL
       AND COALESCE(v_member.spent_amount, 0) + p_amount > COALESCE(v_member.member_limit, 0) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED';
    END IF;

    SELECT * INTO v_target_vault
      FROM public.platform_vaults
     WHERE id = p_target_wallet_id AND user_id = v_actor AND vault_role = 'OPERATING'
     FOR UPDATE;
    IF FOUND THEN
        IF COALESCE(v_target_vault.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_vault.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        v_target_table := 'platform_vaults';
        v_target_balance := COALESCE(v_target_vault.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_vault.currency, 'TZS'));
    ELSE
        SELECT * INTO v_target_wallet
          FROM public.wallets
         WHERE id = p_target_wallet_id AND user_id = v_actor AND UPPER(COALESCE(type, '')) = 'OPERATING'
         FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION 'NO_OPERATING_WALLET'; END IF;
        IF COALESCE(v_target_wallet.is_locked, FALSE)
           OR LOWER(COALESCE(v_target_wallet.status, 'active')) <> 'active' THEN
            RAISE EXCEPTION 'TARGET_WALLET_UNAVAILABLE';
        END IF;
        v_target_table := 'wallets';
        v_target_balance := COALESCE(v_target_wallet.balance, 0);
        v_target_currency := UPPER(COALESCE(v_target_wallet.currency, 'TZS'));
    END IF;

    IF v_target_currency <> UPPER(COALESCE(v_budget.currency, 'TZS'))
       OR UPPER(BTRIM(COALESCE(p_currency, v_budget.currency, 'TZS'))) <> UPPER(COALESCE(v_budget.currency, 'TZS')) THEN
        RAISE EXCEPTION 'SHARED_BUDGET_CURRENCY_MISMATCH';
    END IF;

    v_target_balance_after := v_target_balance + p_amount;
    v_budget_spent_after := COALESCE(v_budget.spent_amount, 0) + p_amount;
    v_budget_available_after := GREATEST(0, COALESCE(v_budget.funded_amount, 0) - v_budget_spent_after);

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, to_wallet_id, amount, currency, description,
        type, status, date, wealth_impact_type, protection_state, allocation_source,
        shared_budget_id, metadata
    ) VALUES (
        v_tx_id, v_reference_id, v_actor, p_target_wallet_id, p_target_wallet_id,
        p_amount::TEXT, UPPER(v_budget.currency),
        COALESCE(NULLIF(BTRIM(COALESCE(p_description, '')), ''), 'Mezani withdrawal'),
        'internal_transfer', 'completed', CURRENT_DATE, 'PLANNED', 'OPEN',
        'SHARED_BUDGET_WITHDRAWAL',
        p_budget_id,
        COALESCE(p_metadata, '{}'::jsonb)
            || jsonb_build_object('shared_budget_id', p_budget_id, 'actor_user_id', v_actor)
    );

    IF v_target_table = 'wallets' THEN
        UPDATE public.wallets SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    ELSE
        UPDATE public.platform_vaults SET balance = v_target_balance_after, updated_at = NOW()
        WHERE id = p_target_wallet_id AND user_id = v_actor;
    END IF;

    UPDATE public.shared_budgets SET spent_amount = v_budget_spent_after, updated_at = NOW()
    WHERE id = p_budget_id;
    UPDATE public.shared_budget_members SET spent_amount = COALESCE(spent_amount, 0) + p_amount, updated_at = NOW()
    WHERE id = v_member.id;

    INSERT INTO public.financial_ledger (
        transaction_id, user_id, wallet_id, shared_budget_id, bucket_type,
        entry_side, entry_type, amount, balance_after, description
    ) VALUES
    (v_tx_id, v_actor, NULL, p_budget_id, 'BUDGET',
     'DEBIT', 'DEBIT', p_amount::TEXT, v_budget_available_after::TEXT,
     'Mezani withdrawal debit: ' || v_budget.name),
    (v_tx_id, v_actor, p_target_wallet_id, p_budget_id, 'OPERATING',
     'CREDIT', 'CREDIT', p_amount::TEXT, v_target_balance_after::TEXT,
     'Mezani withdrawal credit: ' || v_budget.name);

    RETURN jsonb_build_object(
        'transaction_id', v_tx_id,
        'reference_id', v_reference_id,
        'target_balance_after', v_target_balance_after,
        'budget_spent_after', v_budget_spent_after,
        'budget_available_after', v_budget_available_after,
        'target_table', v_target_table,
        'idempotent', FALSE
    );
END;
$$;

REVOKE ALL ON FUNCTION public.shared_budget_allocate_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.shared_budget_withdraw_v1(
    UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_budget_allocate_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM anon';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_budget_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_budget_allocate_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM authenticated';
        EXECUTE 'REVOKE ALL ON FUNCTION public.shared_budget_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.shared_budget_allocate_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) TO service_role';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.shared_budget_withdraw_v1(UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, JSONB) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260716_shared_budget_funded_ledger.sql

-- BEGIN SYNCED MIGRATION: 20260720_payment_profiles.sql
-- ORBI payment profiles for external merchant/platform infrastructure.
-- Merchants store profile references; Core keeps consent and financial identity linkage.

CREATE TABLE IF NOT EXISTS public.payment_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id TEXT NOT NULL UNIQUE,
    service_code TEXT NOT NULL,
    external_customer_id TEXT,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    customer_id TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    consent_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_by_worker_id TEXT,
    idempotency_key TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CHECK (array_length(scopes, 1) IS NOT NULL AND array_length(scopes, 1) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_profiles_service_idempotency
    ON public.payment_profiles(service_code, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_profiles_service_external_customer
    ON public.payment_profiles(service_code, external_customer_id)
    WHERE external_customer_id IS NOT NULL AND status <> 'revoked';

CREATE INDEX IF NOT EXISTS idx_payment_profiles_user
    ON public.payment_profiles(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_profiles_service_status
    ON public.payment_profiles(service_code, status, updated_at DESC);

ALTER TABLE public.payment_profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS payment_profiles_service_role
    ON public.payment_profiles;
CREATE POLICY payment_profiles_service_role
    ON public.payment_profiles
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS payment_profiles_user_read_own
    ON public.payment_profiles;
CREATE POLICY payment_profiles_user_read_own
    ON public.payment_profiles
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id);

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260720_payment_profiles.sql

-- BEGIN SYNCED MIGRATION: 20260723_pay_gateway_developer_secret_vault.sql
-- Official Pay Gateway developer secret vault.
-- Stores fingerprints only. Raw API keys and webhook secrets must never be persisted.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.pay_gateway_developer_services (
  service_code TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  legal_name TEXT,
  business_type TEXT,
  country_code TEXT,
  contact_email TEXT,
  contact_phone TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  environments TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  scopes_granted TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  scopes_pending TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  redirect_urls TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  webhook_urls TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  external_developer_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT pay_gateway_developer_services_status_check
    CHECK (status IN ('draft', 'active', 'suspended', 'revoked'))
);

CREATE TABLE IF NOT EXISTS public.pay_gateway_developer_api_keys (
  key_id TEXT PRIMARY KEY,
  service_code TEXT NOT NULL REFERENCES public.pay_gateway_developer_services(service_code) ON DELETE CASCADE,
  environment TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  encrypted_secret JSONB,
  status TEXT NOT NULL DEFAULT 'active',
  issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
  revoked_at TIMESTAMP WITH TIME ZONE,
  issued_by TEXT,
  revoked_by TEXT,
  rotation_reason TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT pay_gateway_developer_api_keys_environment_check
    CHECK (environment IN ('sandbox', 'live')),
  CONSTRAINT pay_gateway_developer_api_keys_status_check
    CHECK (status IN ('active', 'revoked', 'expired')),
  CONSTRAINT pay_gateway_developer_api_keys_fingerprint_unique
    UNIQUE (fingerprint)
);

CREATE TABLE IF NOT EXISTS public.pay_gateway_developer_webhook_secrets (
  secret_id TEXT PRIMARY KEY,
  service_code TEXT NOT NULL REFERENCES public.pay_gateway_developer_services(service_code) ON DELETE CASCADE,
  environment TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
  revoked_at TIMESTAMP WITH TIME ZONE,
  issued_by TEXT,
  revoked_by TEXT,
  rotation_reason TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT pay_gateway_developer_webhook_secrets_environment_check
    CHECK (environment IN ('sandbox', 'live')),
  CONSTRAINT pay_gateway_developer_webhook_secrets_status_check
    CHECK (status IN ('active', 'revoked', 'expired')),
  CONSTRAINT pay_gateway_developer_webhook_secrets_fingerprint_unique
    UNIQUE (fingerprint)
);

CREATE TABLE IF NOT EXISTS public.pay_gateway_developer_secret_events (
  event_id TEXT PRIMARY KEY,
  service_code TEXT REFERENCES public.pay_gateway_developer_services(service_code) ON DELETE SET NULL,
  environment TEXT,
  event_type TEXT NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  target_type TEXT,
  target_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  CONSTRAINT pay_gateway_developer_secret_events_environment_check
    CHECK (environment IS NULL OR environment IN ('sandbox', 'live'))
);

CREATE INDEX IF NOT EXISTS pay_gateway_developer_api_keys_lookup_idx
  ON public.pay_gateway_developer_api_keys (fingerprint, status, environment);

CREATE INDEX IF NOT EXISTS pay_gateway_developer_api_keys_service_idx
  ON public.pay_gateway_developer_api_keys (service_code, environment, status);

CREATE INDEX IF NOT EXISTS pay_gateway_developer_webhook_secrets_lookup_idx
  ON public.pay_gateway_developer_webhook_secrets (fingerprint, status, environment);

CREATE INDEX IF NOT EXISTS pay_gateway_developer_secret_events_service_idx
  ON public.pay_gateway_developer_secret_events (service_code, occurred_at DESC);

COMMENT ON TABLE public.pay_gateway_developer_api_keys IS
  'Developer API key vault. Stores fingerprints only; raw keys are displayed once and never persisted.';

COMMENT ON TABLE public.pay_gateway_developer_webhook_secrets IS
  'Developer webhook secret vault. Stores fingerprints and encrypted signing secrets. Raw webhook secrets are never stored in plaintext.';

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260723_pay_gateway_developer_secret_vault.sql

-- BEGIN SYNCED MIGRATION: 20260731_pay_gateway_portal_usernames.sql
-- Pay Gateway Developer Portal usernames.
-- Every developer/operator/admin portal identity must have a unique username.

CREATE TABLE IF NOT EXISTS public.pay_gateway_portal_users (
  user_id TEXT PRIMARY KEY,
  username TEXT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('developer', 'operator', 'admin')),
  permissions TEXT[] NOT NULL DEFAULT '{}',
  live_access BOOLEAN NOT NULL DEFAULT FALSE,
  service_codes TEXT[] NOT NULL DEFAULT '{}',
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 210000,
  totp_secret TEXT,
  mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

ALTER TABLE public.pay_gateway_portal_users
  ADD COLUMN IF NOT EXISTS username TEXT;

UPDATE public.pay_gateway_portal_users
SET username =
  LOWER(REGEXP_REPLACE(SPLIT_PART(email, '@', 1), '[^a-zA-Z0-9_-]+', '_', 'g'))
  || '_'
  || SUBSTR(MD5(email), 1, 8)
WHERE username IS NULL OR TRIM(username) = '';

ALTER TABLE public.pay_gateway_portal_users
  ALTER COLUMN username SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS pay_gateway_portal_users_username_unique_idx
  ON public.pay_gateway_portal_users (LOWER(username));

COMMENT ON COLUMN public.pay_gateway_portal_users.username IS
  'Unique developer portal username used as a stable public-facing handle. Email remains private login identity.';

-- Enterprise late-table read indexes.
-- These tables are introduced after the main index section, so keep their
-- critical read indexes here after all late sync tables exist.
CREATE INDEX IF NOT EXISTS idx_passkeys_user_created_mobile ON public.passkeys(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_risk_logs_user_created_mobile ON public.ai_risk_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_financial_events_stream_mobile ON public.financial_events(aggregate_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ent_idempotency_keys_client_status_mobile ON public.ent_idempotency_keys(client_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbox_events_type_status_mobile ON public.outbox_events(event_type, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_checks_user_score_mobile ON public.fraud_checks(user_id, risk_score DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_card_transactions_user_status_created_mobile ON public.card_transactions(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_card_tokens_user_status_mobile ON public.card_tokens(user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_merchant_paysafe_settlements_owner_status_mobile ON public.merchant_paysafe_settlements(owner_user_id, status, settled_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_intents_merchant_status_mobile ON public.gateway_payment_intents(merchant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_intents_reference_mobile ON public.gateway_payment_intents(reference);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_challenges_intent_status_mobile ON public.gateway_payment_challenges(intent_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_payment_event_outbox_intent_status_mobile ON public.gateway_payment_event_outbox(intent_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payment_profiles_service_user_status_mobile ON public.payment_profiles(service_code, user_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pay_gateway_dev_services_status_mobile ON public.pay_gateway_developer_services(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pay_gateway_dev_api_keys_status_mobile ON public.pay_gateway_developer_api_keys(service_code, status, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_pay_gateway_dev_webhook_secrets_status_mobile ON public.pay_gateway_developer_webhook_secrets(service_code, status, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_pay_gateway_portal_users_role_enabled_mobile ON public.pay_gateway_portal_users(role, enabled, updated_at DESC);

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260731_pay_gateway_portal_usernames.sql

-- BEGIN SYNCED MIGRATION: 20260910_atomic_treasury_approval.sql
-- Serializes treasury approvals and grants the execution claim exactly once.
CREATE TABLE IF NOT EXISTS public.treasury_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES public.treasury_policies(id) ON DELETE RESTRICT,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL,
    policy_snapshot JSONB NOT NULL,
    changed_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    change_reason TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_policy_one_active_currency
    ON public.treasury_policies(organization_id, UPPER(currency)) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_treasury_policy_versions_policy
    ON public.treasury_policy_versions(policy_id, version DESC);

ALTER TABLE public.treasury_policy_versions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS treasury_policy_versions_service_role ON public.treasury_policy_versions;
CREATE POLICY treasury_policy_versions_service_role ON public.treasury_policy_versions
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION public.upsert_treasury_policy_v1(
    p_actor_id UUID, p_organization_id UUID, p_currency TEXT, p_name TEXT,
    p_description TEXT, p_min_approvals INTEGER, p_max_amount_per_tx NUMERIC,
    p_daily_limit NUMERIC, p_change_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    v_actor public.users%ROWTYPE;
    v_policy public.treasury_policies%ROWTYPE;
    v_policy_id UUID;
    v_version INTEGER;
    v_eligible_approvers INTEGER;
    v_currency TEXT := UPPER(BTRIM(COALESCE(p_currency, '')));
BEGIN
    IF v_currency !~ '^[A-Z]{3}$' THEN RAISE EXCEPTION 'TREASURY_POLICY_CURRENCY_INVALID'; END IF;
    IF NULLIF(BTRIM(COALESCE(p_name, '')), '') IS NULL THEN RAISE EXCEPTION 'TREASURY_POLICY_NAME_REQUIRED'; END IF;
    IF NULLIF(BTRIM(COALESCE(p_change_reason, '')), '') IS NULL OR LENGTH(BTRIM(p_change_reason)) < 5 THEN
        RAISE EXCEPTION 'TREASURY_POLICY_CHANGE_REASON_REQUIRED';
    END IF;
    IF p_min_approvals IS NULL OR p_min_approvals < 2 THEN RAISE EXCEPTION 'TREASURY_POLICY_QUORUM_TOO_LOW'; END IF;
    IF p_max_amount_per_tx IS NOT NULL AND p_max_amount_per_tx <= 0 THEN RAISE EXCEPTION 'TREASURY_POLICY_TX_LIMIT_INVALID'; END IF;
    IF p_daily_limit IS NOT NULL AND p_daily_limit <= 0 THEN RAISE EXCEPTION 'TREASURY_POLICY_DAILY_LIMIT_INVALID'; END IF;
    IF p_daily_limit IS NOT NULL AND p_max_amount_per_tx IS NOT NULL AND p_daily_limit < p_max_amount_per_tx THEN
        RAISE EXCEPTION 'TREASURY_POLICY_LIMIT_ORDER_INVALID';
    END IF;

    SELECT * INTO v_actor FROM public.users WHERE id = p_actor_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_actor.account_status, '')) <> 'ACTIVE'
       OR v_actor.organization_id IS DISTINCT FROM p_organization_id
       OR UPPER(COALESCE(v_actor.org_role, '')) <> 'ADMIN' THEN
        RAISE EXCEPTION 'TREASURY_POLICY_ADMIN_REQUIRED';
    END IF;

    SELECT COUNT(*) INTO v_eligible_approvers
      FROM public.treasury_approvers ta JOIN public.users u ON u.id=ta.user_id
     WHERE ta.organization_id=p_organization_id AND ta.status='ACTIVE'
       AND UPPER(COALESCE(u.account_status,''))='ACTIVE'
       AND UPPER(COALESCE(u.org_role,'')) IN ('ADMIN','FINANCE');
    IF p_min_approvals > v_eligible_approvers THEN RAISE EXCEPTION 'TREASURY_POLICY_QUORUM_UNAVAILABLE'; END IF;

    SELECT * INTO v_policy FROM public.treasury_policies
     WHERE organization_id = p_organization_id AND UPPER(currency) = v_currency AND is_active = TRUE
     FOR UPDATE;
    IF FOUND THEN
        v_policy_id := v_policy.id;
        SELECT COALESCE(MAX(version), 0) + 1 INTO v_version FROM public.treasury_policy_versions WHERE policy_id = v_policy_id;
        UPDATE public.treasury_policies SET name=BTRIM(p_name), description=NULLIF(BTRIM(COALESCE(p_description,'')),''),
            min_approvals=p_min_approvals, max_amount_per_tx=p_max_amount_per_tx,
            daily_limit=p_daily_limit, updated_at=NOW() WHERE id=v_policy_id;
        INSERT INTO public.treasury_policy_versions(policy_id, organization_id, version, policy_snapshot, changed_by, change_reason)
        SELECT id, organization_id, v_version, to_jsonb(treasury_policies.*), p_actor_id, BTRIM(p_change_reason)
          FROM public.treasury_policies WHERE id=v_policy_id;
    ELSE
        INSERT INTO public.treasury_policies(organization_id,name,description,min_approvals,max_amount_per_tx,daily_limit,currency,is_active)
        VALUES(p_organization_id,BTRIM(p_name),NULLIF(BTRIM(COALESCE(p_description,'')),''),p_min_approvals,p_max_amount_per_tx,p_daily_limit,v_currency,TRUE)
        RETURNING id INTO v_policy_id;
        v_version := 1;
        INSERT INTO public.treasury_policy_versions(policy_id,organization_id,version,policy_snapshot,changed_by,change_reason)
        SELECT id, organization_id, 1, to_jsonb(treasury_policies.*), p_actor_id, BTRIM(p_change_reason)
          FROM public.treasury_policies WHERE id=v_policy_id;
    END IF;
    RETURN jsonb_build_object('policy_id',v_policy_id,'version',v_version,'eligible_approvers',v_eligible_approvers);
END;
$$;

REVOKE ALL ON FUNCTION public.upsert_treasury_policy_v1(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, NUMERIC, NUMERIC, TEXT) FROM PUBLIC;
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='anon') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.upsert_treasury_policy_v1(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, NUMERIC, NUMERIC, TEXT) FROM anon'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.upsert_treasury_policy_v1(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, NUMERIC, NUMERIC, TEXT) FROM authenticated'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.upsert_treasury_policy_v1(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, NUMERIC, NUMERIC, TEXT) TO service_role'; END IF;
END $$;

ALTER TABLE public.goals
    ADD COLUMN IF NOT EXISTS auto_sweep_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS sweep_threshold NUMERIC NOT NULL DEFAULT 0;

DO $$
BEGIN
    ALTER TABLE public.goals DROP CONSTRAINT IF EXISTS goals_sweep_threshold_nonnegative;
    ALTER TABLE public.goals ADD CONSTRAINT goals_sweep_threshold_nonnegative CHECK (sweep_threshold >= 0);
END $$;

CREATE OR REPLACE FUNCTION public.request_treasury_withdrawal_v1(
    p_transaction_id UUID,
    p_user_id UUID,
    p_goal_id UUID,
    p_destination_wallet_id UUID,
    p_amount NUMERIC,
    p_encrypted_amount TEXT,
    p_encrypted_description TEXT,
    p_reason TEXT,
    p_reference_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_goal public.goals%ROWTYPE;
    v_user public.users%ROWTYPE;
    v_destination public.wallets%ROWTYPE;
    v_policy public.treasury_policies%ROWTYPE;
    v_destination_owner public.users%ROWTYPE;
    v_approvals_required INTEGER := 2;
    v_daily_used NUMERIC := 0;
BEGIN
    IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'TREASURY_AMOUNT_INVALID'; END IF;
    IF NULLIF(BTRIM(COALESCE(p_reason, '')), '') IS NULL OR LENGTH(BTRIM(p_reason)) < 5 THEN
        RAISE EXCEPTION 'TREASURY_REASON_REQUIRED';
    END IF;
    IF NULLIF(BTRIM(COALESCE(p_encrypted_amount, '')), '') IS NULL
       OR NULLIF(BTRIM(COALESCE(p_encrypted_description, '')), '') IS NULL
       OR NULLIF(BTRIM(COALESCE(p_reference_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'TREASURY_PROTECTED_FIELDS_REQUIRED';
    END IF;

    SELECT * INTO v_goal FROM public.goals WHERE id = p_goal_id FOR UPDATE;
    IF NOT FOUND OR NOT COALESCE(v_goal.is_corporate, FALSE)
       OR UPPER(COALESCE(v_goal.status, '')) <> 'ACTIVE'
       OR v_goal.organization_id IS NULL THEN
        RAISE EXCEPTION 'TREASURY_GOAL_UNAVAILABLE';
    END IF;
    IF COALESCE(v_goal.current, 0) < p_amount THEN RAISE EXCEPTION 'TREASURY_INSUFFICIENT_FUNDS'; END IF;

    SELECT * INTO v_user FROM public.users WHERE id = p_user_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_user.account_status, '')) <> 'ACTIVE'
       OR v_user.organization_id IS DISTINCT FROM v_goal.organization_id THEN
        RAISE EXCEPTION 'TREASURY_REQUESTER_ACCESS_DENIED';
    END IF;

    SELECT * INTO v_destination FROM public.wallets WHERE id = p_destination_wallet_id FOR UPDATE;
    IF NOT FOUND OR COALESCE(v_destination.is_locked, FALSE)
       OR LOWER(COALESCE(v_destination.status, '')) <> 'active'
       OR UPPER(COALESCE(v_destination.currency, '')) <> UPPER(COALESCE(v_goal.currency, '')) THEN
        RAISE EXCEPTION 'TREASURY_DESTINATION_UNAVAILABLE';
    END IF;
    SELECT * INTO v_destination_owner FROM public.users WHERE id = v_destination.user_id;
    IF NOT FOUND OR UPPER(COALESCE(v_destination_owner.account_status, '')) <> 'ACTIVE'
       OR v_destination_owner.organization_id IS DISTINCT FROM v_goal.organization_id THEN
        RAISE EXCEPTION 'TREASURY_DESTINATION_ACCESS_DENIED';
    END IF;

    SELECT * INTO v_policy FROM public.treasury_policies
     WHERE organization_id = v_goal.organization_id AND is_active = TRUE
       AND UPPER(COALESCE(currency, '')) = UPPER(COALESCE(v_goal.currency, ''))
     ORDER BY updated_at DESC, id LIMIT 1;
    IF FOUND THEN
        v_approvals_required := GREATEST(2, COALESCE(v_policy.min_approvals, 2));
        IF v_policy.max_amount_per_tx IS NOT NULL AND p_amount > v_policy.max_amount_per_tx THEN
            RAISE EXCEPTION 'TREASURY_PER_TRANSACTION_LIMIT_EXCEEDED';
        END IF;
        IF v_policy.daily_limit IS NOT NULL THEN
            SELECT COALESCE(SUM(CASE WHEN COALESCE(t.metadata->>'amount_plain', '') ~ '^[0-9]+(\.[0-9]+)?$'
                THEN (t.metadata->>'amount_plain')::NUMERIC ELSE 0 END), 0)
              INTO v_daily_used FROM public.transactions t
             WHERE t.metadata->>'organization_id' = v_goal.organization_id::TEXT
               AND COALESCE(t.metadata->>'is_treasury_withdrawal', 'false') = 'true'
               AND t.created_at >= date_trunc('day', NOW())
               AND t.status NOT IN ('failed', 'cancelled', 'reversed');
            IF v_daily_used + p_amount > v_policy.daily_limit THEN RAISE EXCEPTION 'TREASURY_DAILY_LIMIT_EXCEEDED'; END IF;
        END IF;
    END IF;

    INSERT INTO public.transactions (
        id, reference_id, user_id, wallet_id, to_wallet_id, amount, description,
        currency, type, status, metadata
    ) VALUES (
        p_transaction_id, BTRIM(p_reference_id), p_user_id, p_goal_id, p_destination_wallet_id,
        p_encrypted_amount, p_encrypted_description, UPPER(v_goal.currency), 'transfer', 'held_for_review',
        jsonb_build_object('is_treasury_withdrawal', TRUE, 'goal_id', p_goal_id,
            'organization_id', v_goal.organization_id, 'reason', BTRIM(p_reason),
            'amount_plain', p_amount, 'approvals_required', v_approvals_required,
            'approvals_received', 0, 'approved_by', '[]'::JSONB)
    );
    RETURN jsonb_build_object('transaction_id', p_transaction_id, 'organization_id', v_goal.organization_id, 'approvals_required', v_approvals_required);
END;
$$;

REVOKE ALL ON FUNCTION public.request_treasury_withdrawal_v1(UUID, UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.request_treasury_withdrawal_v1(UUID, UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, TEXT) FROM anon'; END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN EXECUTE 'REVOKE ALL ON FUNCTION public.request_treasury_withdrawal_v1(UUID, UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, TEXT) FROM authenticated'; END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN EXECUTE 'GRANT EXECUTE ON FUNCTION public.request_treasury_withdrawal_v1(UUID, UUID, UUID, UUID, NUMERIC, TEXT, TEXT, TEXT, TEXT) TO service_role'; END IF;
END $$;

CREATE OR REPLACE FUNCTION public.approve_treasury_withdrawal_v1(
    p_admin_id UUID,
    p_transaction_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_goal public.goals%ROWTYPE;
    v_admin public.users%ROWTYPE;
    v_metadata JSONB;
    v_approved_by JSONB;
    v_approvals_received INTEGER;
    v_approvals_required INTEGER;
    v_fully_approved BOOLEAN;
    v_execution_token UUID;
BEGIN
    IF p_admin_id IS NULL OR p_transaction_id IS NULL THEN
        RAISE EXCEPTION 'TREASURY_APPROVAL_IDENTITY_REQUIRED';
    END IF;

    SELECT * INTO v_tx
      FROM public.transactions
     WHERE id = p_transaction_id
     FOR UPDATE;

    IF NOT FOUND
       OR LOWER(COALESCE(v_tx.status, '')) <> 'held_for_review'
       OR COALESCE(v_tx.metadata->>'is_treasury_withdrawal', 'false') <> 'true' THEN
        RAISE EXCEPTION 'TREASURY_WITHDRAWAL_NOT_APPROVABLE';
    END IF;

    IF v_tx.user_id = p_admin_id THEN
        RAISE EXCEPTION 'TREASURY_MAKER_CHECKER_VIOLATION';
    END IF;

    SELECT * INTO v_goal
      FROM public.goals
     WHERE id = NULLIF(v_tx.metadata->>'goal_id', '')::UUID
     FOR UPDATE;

    IF NOT FOUND OR NOT COALESCE(v_goal.is_corporate, FALSE) OR v_goal.organization_id IS NULL THEN
        RAISE EXCEPTION 'TREASURY_CORPORATE_GOAL_NOT_FOUND';
    END IF;

    SELECT * INTO v_admin
      FROM public.users
     WHERE id = p_admin_id
     FOR UPDATE;

    IF NOT FOUND
       OR UPPER(COALESCE(v_admin.account_status, '')) <> 'ACTIVE'
       OR v_admin.organization_id IS DISTINCT FROM v_goal.organization_id
       OR UPPER(COALESCE(v_admin.org_role, '')) NOT IN ('ADMIN', 'FINANCE')
       OR NOT EXISTS (SELECT 1 FROM public.treasury_approvers ta WHERE ta.organization_id=v_goal.organization_id AND ta.user_id=p_admin_id AND ta.status='ACTIVE') THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_ACCESS_DENIED';
    END IF;

    v_metadata := COALESCE(v_tx.metadata, '{}'::JSONB);
    v_approved_by := CASE
        WHEN jsonb_typeof(v_metadata->'approved_by') = 'array' THEN v_metadata->'approved_by'
        ELSE '[]'::JSONB
    END;

    IF v_approved_by ? p_admin_id::TEXT THEN
        RAISE EXCEPTION 'TREASURY_APPROVAL_ALREADY_RECORDED';
    END IF;

    v_approved_by := v_approved_by || jsonb_build_array(p_admin_id::TEXT);
    v_approvals_received := jsonb_array_length(v_approved_by);
    v_approvals_required := CASE
        WHEN COALESCE(v_metadata->>'approvals_required', '') ~ '^[0-9]+$'
            THEN GREATEST(2, (v_metadata->>'approvals_required')::INTEGER)
        ELSE 2
    END;
    v_fully_approved := v_approvals_received >= v_approvals_required;

    v_metadata := v_metadata || jsonb_build_object(
        'approved_by', v_approved_by,
        'approvals_received', v_approvals_received,
        'approvals_required', v_approvals_required,
        'last_approved_at', NOW(),
        'last_approved_by', p_admin_id::TEXT
    );

    IF v_fully_approved THEN
        v_execution_token := gen_random_uuid();
        v_metadata := v_metadata || jsonb_build_object(
            'execution_state', 'CLAIMED',
            'execution_claimed_at', NOW(),
            'execution_claimed_by', p_admin_id::TEXT,
            'execution_token', v_execution_token::TEXT,
            'execution_lease_until', NOW() + INTERVAL '2 minutes',
            'execution_attempts', 1
        );
    END IF;

    UPDATE public.transactions
       SET metadata = v_metadata,
           status = CASE WHEN v_fully_approved THEN 'processing' ELSE status END,
           status_notes = CASE
               WHEN v_fully_approved THEN 'Treasury approval quorum reached; execution claimed'
               ELSE status_notes
           END,
           updated_at = NOW()
     WHERE id = p_transaction_id;

    RETURN jsonb_build_object(
        'transaction_id', p_transaction_id,
        'fully_approved', v_fully_approved,
        'should_execute', v_fully_approved,
        'execution_token', CASE WHEN v_execution_token IS NULL THEN NULL ELSE v_execution_token::TEXT END,
        'approvals_received', v_approvals_received,
        'approvals_required', v_approvals_required
    );
END;
$$;

REVOKE ALL ON FUNCTION public.approve_treasury_withdrawal_v1(UUID, UUID) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.approve_treasury_withdrawal_v1(UUID, UUID) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.approve_treasury_withdrawal_v1(UUID, UUID) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.approve_treasury_withdrawal_v1(UUID, UUID) TO service_role';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.claim_treasury_withdrawal_execution_v1(
    p_transaction_id UUID,
    p_worker_id TEXT,
    p_lease_seconds INTEGER DEFAULT 120
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_tx public.transactions%ROWTYPE;
    v_metadata JSONB;
    v_lease_until TIMESTAMP WITH TIME ZONE;
    v_execution_token UUID;
    v_attempts INTEGER;
BEGIN
    IF p_transaction_id IS NULL OR NULLIF(BTRIM(COALESCE(p_worker_id, '')), '') IS NULL THEN
        RAISE EXCEPTION 'TREASURY_EXECUTION_WORKER_REQUIRED';
    END IF;
    IF p_lease_seconds < 30 OR p_lease_seconds > 900 THEN
        RAISE EXCEPTION 'TREASURY_EXECUTION_LEASE_INVALID';
    END IF;

    SELECT * INTO v_tx FROM public.transactions
     WHERE id = p_transaction_id FOR UPDATE;
    IF NOT FOUND
       OR LOWER(COALESCE(v_tx.status, '')) <> 'processing'
       OR COALESCE(v_tx.metadata->>'is_treasury_withdrawal', 'false') <> 'true'
       OR COALESCE(v_tx.metadata->>'execution_state', '') NOT IN ('CLAIMED', 'RETRYABLE') THEN
        RETURN jsonb_build_object('claimed', FALSE, 'reason', 'NOT_RECOVERABLE');
    END IF;

    v_metadata := COALESCE(v_tx.metadata, '{}'::JSONB);
    BEGIN
        v_lease_until := NULLIF(v_metadata->>'execution_lease_until', '')::TIMESTAMP WITH TIME ZONE;
    EXCEPTION WHEN invalid_datetime_format THEN
        v_lease_until := NULL;
    END;
    IF v_lease_until IS NOT NULL AND v_lease_until > NOW() THEN
        RETURN jsonb_build_object('claimed', FALSE, 'reason', 'LEASE_ACTIVE', 'lease_until', v_lease_until);
    END IF;

    v_attempts := CASE WHEN COALESCE(v_metadata->>'execution_attempts', '') ~ '^[0-9]+$'
        THEN (v_metadata->>'execution_attempts')::INTEGER ELSE 0 END;
    v_execution_token := gen_random_uuid();
    v_metadata := v_metadata || jsonb_build_object(
        'execution_state', 'CLAIMED',
        'execution_claimed_at', NOW(),
        'execution_claimed_by', BTRIM(p_worker_id),
        'execution_token', v_execution_token::TEXT,
        'execution_lease_until', NOW() + make_interval(secs => p_lease_seconds),
        'execution_attempts', v_attempts + 1
    );
    UPDATE public.transactions SET metadata = v_metadata,
        status_notes = 'Treasury execution recovery lease claimed', updated_at = NOW()
     WHERE id = p_transaction_id;
    RETURN jsonb_build_object('claimed', TRUE, 'transaction_id', p_transaction_id,
        'execution_token', v_execution_token::TEXT, 'lease_until', v_metadata->>'execution_lease_until');
END;
$$;

REVOKE ALL ON FUNCTION public.claim_treasury_withdrawal_execution_v1(UUID, TEXT, INTEGER) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.claim_treasury_withdrawal_execution_v1(UUID, TEXT, INTEGER) FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON FUNCTION public.claim_treasury_withdrawal_execution_v1(UUID, TEXT, INTEGER) FROM authenticated';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.claim_treasury_withdrawal_execution_v1(UUID, TEXT, INTEGER) TO service_role';
    END IF;
END $$;

NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260910_atomic_treasury_approval.sql

-- BEGIN SYNCED MIGRATION: 20260911_treasury_approver_lifecycle.sql
ALTER TABLE public.treasury_approvers
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS assigned_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();

DO $$
BEGIN
    ALTER TABLE public.treasury_approvers DROP CONSTRAINT IF EXISTS treasury_approvers_status_check;
    ALTER TABLE public.treasury_approvers ADD CONSTRAINT treasury_approvers_status_check
        CHECK (status IN ('ACTIVE', 'REMOVED'));
END $$;

INSERT INTO public.treasury_approvers(organization_id, user_id, role, status)
SELECT organization_id, id, UPPER(org_role), 'ACTIVE'
FROM public.users
WHERE organization_id IS NOT NULL
  AND UPPER(COALESCE(account_status, '')) = 'ACTIVE'
  AND UPPER(COALESCE(org_role, '')) IN ('ADMIN', 'FINANCE')
ON CONFLICT (organization_id, user_id) DO UPDATE
SET role = EXCLUDED.role, status = 'ACTIVE', updated_at = NOW();

CREATE TABLE IF NOT EXISTS public.treasury_approver_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (action IN ('ADD', 'REMOVE')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
    reason TEXT NOT NULL,
    review_reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_approver_change_pending
    ON public.treasury_approver_change_requests(organization_id, target_user_id)
    WHERE status = 'PENDING';
ALTER TABLE public.treasury_approver_change_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS treasury_approver_change_service_role ON public.treasury_approver_change_requests;
CREATE POLICY treasury_approver_change_service_role ON public.treasury_approver_change_requests
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION public.request_treasury_approver_change_v1(
    p_actor_id UUID, p_organization_id UUID, p_target_user_id UUID,
    p_action TEXT, p_reason TEXT
) RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_actor public.users%ROWTYPE; v_target public.users%ROWTYPE; v_id UUID;
BEGIN
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
    IF NOT FOUND OR UPPER(COALESCE(v_actor.account_status,'')) <> 'ACTIVE'
       OR v_actor.organization_id IS DISTINCT FROM p_organization_id
       OR UPPER(COALESCE(v_actor.org_role,'')) <> 'ADMIN' THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_ADMIN_REQUIRED';
    END IF;
    SELECT * INTO v_target FROM public.users WHERE id=p_target_user_id;
    IF NOT FOUND OR UPPER(COALESCE(v_target.account_status,'')) <> 'ACTIVE'
       OR v_target.organization_id IS DISTINCT FROM p_organization_id
       OR UPPER(COALESCE(v_target.org_role,'')) NOT IN ('ADMIN','FINANCE') THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_TARGET_INELIGIBLE';
    END IF;
    IF UPPER(COALESCE(p_action,'')) NOT IN ('ADD','REMOVE') THEN RAISE EXCEPTION 'TREASURY_APPROVER_ACTION_INVALID'; END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,''))) < 5 THEN RAISE EXCEPTION 'TREASURY_APPROVER_REASON_REQUIRED'; END IF;
    IF UPPER(p_action)='ADD' AND EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=p_organization_id AND user_id=p_target_user_id AND status='ACTIVE') THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_ALREADY_ACTIVE';
    END IF;
    IF UPPER(p_action)='REMOVE' AND NOT EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=p_organization_id AND user_id=p_target_user_id AND status='ACTIVE') THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_NOT_ACTIVE';
    END IF;
    INSERT INTO public.treasury_approver_change_requests(organization_id,target_user_id,requested_by,action,reason)
    VALUES(p_organization_id,p_target_user_id,p_actor_id,UPPER(p_action),BTRIM(p_reason)) RETURNING id INTO v_id;
    RETURN v_id;
END; $$;

CREATE OR REPLACE FUNCTION public.respond_treasury_approver_change_v1(
    p_reviewer_id UUID, p_request_id UUID, p_decision TEXT, p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_request public.treasury_approver_change_requests%ROWTYPE; v_reviewer public.users%ROWTYPE;
v_active_count INTEGER; v_required_count INTEGER;
BEGIN
    SELECT * INTO v_request FROM public.treasury_approver_change_requests WHERE id=p_request_id FOR UPDATE;
    IF NOT FOUND OR v_request.status <> 'PENDING' THEN RAISE EXCEPTION 'TREASURY_APPROVER_REQUEST_NOT_PENDING'; END IF;
    IF v_request.expires_at <= NOW() THEN
        UPDATE public.treasury_approver_change_requests SET status='EXPIRED',updated_at=NOW() WHERE id=p_request_id;
        RAISE EXCEPTION 'TREASURY_APPROVER_REQUEST_EXPIRED';
    END IF;
    SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_reviewer.account_status,'')) <> 'ACTIVE'
       OR v_reviewer.organization_id IS DISTINCT FROM v_request.organization_id
       OR UPPER(COALESCE(v_reviewer.org_role,'')) <> 'ADMIN'
       OR p_reviewer_id=v_request.requested_by
       OR p_reviewer_id=v_request.target_user_id
       OR NOT EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=v_request.organization_id AND user_id=p_reviewer_id AND status='ACTIVE') THEN
        RAISE EXCEPTION 'TREASURY_APPROVER_REVIEWER_REQUIRED';
    END IF;
    IF UPPER(COALESCE(p_decision,'')) NOT IN ('APPROVE','REJECT') THEN RAISE EXCEPTION 'TREASURY_APPROVER_DECISION_INVALID'; END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,''))) < 5 THEN RAISE EXCEPTION 'TREASURY_APPROVER_REVIEW_REASON_REQUIRED'; END IF;
    IF UPPER(p_decision)='APPROVE' AND v_request.action='REMOVE' THEN
        SELECT COUNT(*) INTO v_active_count FROM public.treasury_approvers WHERE organization_id=v_request.organization_id AND status='ACTIVE';
        SELECT COALESCE(MAX(min_approvals),2) INTO v_required_count FROM public.treasury_policies WHERE organization_id=v_request.organization_id AND is_active=TRUE;
        IF v_active_count-1 < v_required_count THEN RAISE EXCEPTION 'TREASURY_APPROVER_REMOVAL_BREAKS_QUORUM'; END IF;
    END IF;
    IF UPPER(p_decision)='APPROVE' THEN
        IF v_request.action='ADD' THEN
            INSERT INTO public.treasury_approvers(organization_id,user_id,role,status,assigned_by,updated_at)
            SELECT v_request.organization_id,v_request.target_user_id,UPPER(org_role),'ACTIVE',p_reviewer_id,NOW()
            FROM public.users WHERE id=v_request.target_user_id
            ON CONFLICT(organization_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='ACTIVE',assigned_by=p_reviewer_id,updated_at=NOW();
        ELSE
            UPDATE public.treasury_approvers SET status='REMOVED',updated_at=NOW()
            WHERE organization_id=v_request.organization_id AND user_id=v_request.target_user_id;
        END IF;
    END IF;
    UPDATE public.treasury_approver_change_requests SET status=CASE WHEN UPPER(p_decision)='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,
        reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
    RETURN jsonb_build_object('request_id',p_request_id,'status',CASE WHEN UPPER(p_decision)='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END);
END; $$;

REVOKE ALL ON FUNCTION public.request_treasury_approver_change_v1(UUID, UUID, UUID, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_treasury_approver_change_v1(UUID, UUID, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_treasury_approver_change_v1(UUID, UUID, UUID, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_treasury_approver_change_v1(UUID, UUID, TEXT, TEXT) TO service_role;
NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260911_treasury_approver_lifecycle.sql
-- BEGIN SYNCED MIGRATION: 20260912_organization_invitation_lifecycle.sql
CREATE TABLE IF NOT EXISTS public.organization_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    invited_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('MEMBER','MANAGER','ACCOUNTANT')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ACCEPTED','DECLINED','EXPIRED','CANCELLED')),
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '72 hours'),
    responded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_invitation_pending
    ON public.organization_invitations(organization_id,target_user_id) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_organization_invitation_target
    ON public.organization_invitations(target_user_id,status,created_at DESC);
ALTER TABLE public.organization_invitations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_invitations_service_role ON public.organization_invitations;
CREATE POLICY organization_invitations_service_role ON public.organization_invitations
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

CREATE OR REPLACE FUNCTION public.request_organization_invitation_v1(
    p_actor_id UUID, p_organization_id UUID, p_target_user_id UUID, p_role TEXT, p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_actor public.users%ROWTYPE; v_target public.users%ROWTYPE; v_id UUID; v_role TEXT:=UPPER(BTRIM(COALESCE(p_role,'')));
BEGIN
    SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_actor.account_status,'')) <> 'ACTIVE'
       OR v_actor.organization_id IS DISTINCT FROM p_organization_id
       OR UPPER(COALESCE(v_actor.org_role,'')) <> 'ADMIN' THEN
        RAISE EXCEPTION 'ORGANIZATION_INVITATION_ADMIN_REQUIRED';
    END IF;
    SELECT * INTO v_target FROM public.users WHERE id=p_target_user_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_target.account_status,'')) <> 'ACTIVE' THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_TARGET_INELIGIBLE'; END IF;
    IF v_target.organization_id IS NOT NULL THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_TARGET_ALREADY_ASSIGNED'; END IF;
    IF p_actor_id=p_target_user_id THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_SELF_DENIED'; END IF;
    IF v_role NOT IN ('MEMBER','MANAGER','ACCOUNTANT') THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_PRIVILEGED_ROLE_DENIED'; END IF;
    IF LENGTH(BTRIM(COALESCE(p_reason,''))) < 5 THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_REASON_REQUIRED'; END IF;
    UPDATE public.organization_invitations SET status='EXPIRED',updated_at=NOW()
     WHERE organization_id=p_organization_id AND target_user_id=p_target_user_id AND status='PENDING' AND expires_at<=NOW();
    INSERT INTO public.organization_invitations(organization_id,target_user_id,invited_by,role,reason)
    VALUES(p_organization_id,p_target_user_id,p_actor_id,v_role,BTRIM(p_reason)) RETURNING id INTO v_id;
    RETURN jsonb_build_object('invitation_id',v_id,'status','PENDING','expires_in_hours',72);
END; $$;

CREATE OR REPLACE FUNCTION public.respond_organization_invitation_v1(
    p_actor_id UUID, p_invitation_id UUID, p_decision TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_invite public.organization_invitations%ROWTYPE; v_target public.users%ROWTYPE; v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
    SELECT * INTO v_invite FROM public.organization_invitations WHERE id=p_invitation_id FOR UPDATE;
    IF NOT FOUND OR v_invite.status <> 'PENDING' THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_NOT_PENDING'; END IF;
    IF p_actor_id IS DISTINCT FROM v_invite.target_user_id THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_TARGET_REQUIRED'; END IF;
    IF v_invite.expires_at<=NOW() THEN
        UPDATE public.organization_invitations SET status='EXPIRED',responded_at=NOW(),updated_at=NOW() WHERE id=p_invitation_id;
        RETURN jsonb_build_object('invitation_id',p_invitation_id,'status','EXPIRED');
    END IF;
    IF v_decision NOT IN ('ACCEPT','DECLINE') THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_DECISION_INVALID'; END IF;
    SELECT * INTO v_target FROM public.users WHERE id=p_actor_id FOR UPDATE;
    IF NOT FOUND OR UPPER(COALESCE(v_target.account_status,'')) <> 'ACTIVE' THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_TARGET_INELIGIBLE'; END IF;
    IF v_decision='ACCEPT' THEN
        IF v_target.organization_id IS NOT NULL THEN RAISE EXCEPTION 'ORGANIZATION_INVITATION_TARGET_ALREADY_ASSIGNED'; END IF;
        UPDATE public.users SET organization_id=v_invite.organization_id,org_role=v_invite.role WHERE id=p_actor_id;
    END IF;
    UPDATE public.organization_invitations
       SET status=CASE WHEN v_decision='ACCEPT' THEN 'ACCEPTED' ELSE 'DECLINED' END, responded_at=NOW(),updated_at=NOW()
     WHERE id=p_invitation_id;
    RETURN jsonb_build_object('invitation_id',p_invitation_id,'status',CASE WHEN v_decision='ACCEPT' THEN 'ACCEPTED' ELSE 'DECLINED' END,
        'organization_id',v_invite.organization_id,'role',v_invite.role);
END; $$;

REVOKE ALL ON FUNCTION public.request_organization_invitation_v1(UUID,UUID,UUID,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_invitation_v1(UUID,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_organization_invitation_v1(UUID,UUID,UUID,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_invitation_v1(UUID,UUID,TEXT) TO service_role;
NOTIFY pgrst, 'reload schema';
-- END SYNCED MIGRATION: 20260912_organization_invitation_lifecycle.sql
-- BEGIN SYNCED MIGRATION: 20260913_organization_member_change_lifecycle.sql
ALTER TABLE public.organizations
    ADD COLUMN IF NOT EXISTS creator_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS primary_admin_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS public.organization_member_change_requests (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
 target_user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT, requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT, action TEXT NOT NULL CHECK(action IN ('CHANGE_ROLE','REMOVE_MEMBER')),
 from_role TEXT NOT NULL, to_role TEXT, status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED')),
 reason TEXT NOT NULL, review_reason TEXT, expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),
 reviewed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_member_change_pending ON public.organization_member_change_requests(organization_id,target_user_id) WHERE status='PENDING';
ALTER TABLE public.organization_member_change_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_member_change_service_role ON public.organization_member_change_requests;
CREATE POLICY organization_member_change_service_role ON public.organization_member_change_requests FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);

CREATE OR REPLACE FUNCTION public.request_organization_member_change_v1(
 p_actor_id UUID,p_organization_id UUID,p_target_user_id UUID,p_action TEXT,p_to_role TEXT,p_reason TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_actor public.users%ROWTYPE; v_target public.users%ROWTYPE; v_org public.organizations%ROWTYPE; v_action TEXT:=UPPER(BTRIM(COALESCE(p_action,''))); v_role TEXT:=UPPER(BTRIM(COALESCE(p_to_role,''))); v_id UUID;
BEGIN
 SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id FOR UPDATE;
 IF NOT FOUND OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' OR v_actor.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_actor.org_role,''))<>'ADMIN' THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_ADMIN_REQUIRED'; END IF;
 SELECT * INTO v_target FROM public.users WHERE id=p_target_user_id FOR UPDATE;
 IF NOT FOUND OR v_target.organization_id IS DISTINCT FROM p_organization_id OR UPPER(COALESCE(v_target.account_status,''))<>'ACTIVE' THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_TARGET_NOT_FOUND'; END IF;
 SELECT * INTO v_org FROM public.organizations WHERE id=p_organization_id FOR UPDATE;
 IF p_actor_id=p_target_user_id THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_SELF_DENIED'; END IF;
 IF v_org.primary_admin_user_id=p_target_user_id OR UPPER(COALESCE(v_target.org_role,'')) IN ('ADMIN','SIGNATORY') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_PRIVILEGED_TARGET'; END IF;
 IF EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=p_organization_id AND user_id=p_target_user_id AND status='ACTIVE') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_TREASURY_TARGET'; END IF;
 IF v_action NOT IN ('CHANGE_ROLE','REMOVE_MEMBER') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_ACTION_INVALID'; END IF;
 IF v_action='CHANGE_ROLE' AND v_role NOT IN ('MEMBER','MANAGER','ACCOUNTANT') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_ROLE_INVALID'; END IF;
 IF v_action='CHANGE_ROLE' AND v_role=UPPER(COALESCE(v_target.org_role,'')) THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_NOOP'; END IF;
 IF LENGTH(BTRIM(COALESCE(p_reason,'')))<5 THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_REASON_REQUIRED'; END IF;
 UPDATE public.organization_member_change_requests SET status='EXPIRED',updated_at=NOW() WHERE organization_id=p_organization_id AND target_user_id=p_target_user_id AND status='PENDING' AND expires_at<=NOW();
 INSERT INTO public.organization_member_change_requests(organization_id,target_user_id,requested_by,action,from_role,to_role,reason)
 VALUES(p_organization_id,p_target_user_id,p_actor_id,v_action,UPPER(v_target.org_role),CASE WHEN v_action='CHANGE_ROLE' THEN v_role ELSE NULL END,BTRIM(p_reason)) RETURNING id INTO v_id;
 RETURN v_id;
END; $$;

CREATE OR REPLACE FUNCTION public.respond_organization_member_change_v1(
 p_reviewer_id UUID,p_request_id UUID,p_decision TEXT,p_reason TEXT
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_request public.organization_member_change_requests%ROWTYPE; v_reviewer public.users%ROWTYPE; v_target public.users%ROWTYPE; v_org public.organizations%ROWTYPE; v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
 SELECT * INTO v_request FROM public.organization_member_change_requests WHERE id=p_request_id FOR UPDATE;
 IF NOT FOUND OR v_request.status<>'PENDING' THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_NOT_PENDING'; END IF;
 IF v_request.expires_at<=NOW() THEN UPDATE public.organization_member_change_requests SET status='EXPIRED',reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id; RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED'); END IF;
 SELECT * INTO v_reviewer FROM public.users WHERE id=p_reviewer_id FOR UPDATE;
 IF NOT FOUND OR UPPER(COALESCE(v_reviewer.account_status,''))<>'ACTIVE' OR v_reviewer.organization_id IS DISTINCT FROM v_request.organization_id OR UPPER(COALESCE(v_reviewer.org_role,''))<>'ADMIN' OR p_reviewer_id IN (v_request.requested_by,v_request.target_user_id) THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_REVIEWER_REQUIRED'; END IF;
 IF v_decision NOT IN ('APPROVE','REJECT') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_DECISION_INVALID'; END IF;
 IF LENGTH(BTRIM(COALESCE(p_reason,'')))<5 THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_REVIEW_REASON_REQUIRED'; END IF;
 IF v_decision='APPROVE' THEN
  SELECT * INTO v_target FROM public.users WHERE id=v_request.target_user_id FOR UPDATE;
  SELECT * INTO v_org FROM public.organizations WHERE id=v_request.organization_id FOR UPDATE;
  IF NOT FOUND OR v_target.organization_id IS DISTINCT FROM v_request.organization_id THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_TARGET_NOT_FOUND'; END IF;
  IF v_org.primary_admin_user_id=v_target.id OR UPPER(COALESCE(v_target.org_role,'')) IN ('ADMIN','SIGNATORY') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_PRIVILEGED_TARGET'; END IF;
  IF EXISTS(SELECT 1 FROM public.treasury_approvers WHERE organization_id=v_request.organization_id AND user_id=v_target.id AND status='ACTIVE') THEN RAISE EXCEPTION 'ORGANIZATION_MEMBER_CHANGE_TREASURY_TARGET'; END IF;
  IF v_request.action='CHANGE_ROLE' THEN UPDATE public.users SET org_role=v_request.to_role WHERE id=v_target.id; ELSE UPDATE public.users SET organization_id=NULL,org_role=NULL WHERE id=v_target.id; END IF;
 END IF;
 UPDATE public.organization_member_change_requests SET status=CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
 RETURN jsonb_build_object('request_id',p_request_id,'status',CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,'action',v_request.action);
END; $$;
REVOKE ALL ON FUNCTION public.request_organization_member_change_v1(UUID,UUID,UUID,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.respond_organization_member_change_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_organization_member_change_v1(UUID,UUID,UUID,TEXT,TEXT,TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.respond_organization_member_change_v1(UUID,UUID,TEXT,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260913_organization_member_change_lifecycle.sql

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

-- BEGIN SYNCED MIGRATION: 20260919_scheduled_treasury_operations.sql
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_frequency TEXT NOT NULL DEFAULT 'DAILY' CHECK(sweep_frequency IN ('DAILY','WEEKLY','MONTHLY'));
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_timezone TEXT NOT NULL DEFAULT 'Africa/Dar_es_Salaam';
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_next_run_at TIMESTAMPTZ;
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_window_minutes INTEGER NOT NULL DEFAULT 60 CHECK(sweep_window_minutes BETWEEN 5 AND 1440);
ALTER TABLE public.goals ADD COLUMN IF NOT EXISTS sweep_schedule_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS public.treasury_schedule_change_requests(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,goal_id UUID NOT NULL REFERENCES public.goals(id) ON DELETE CASCADE,
 requested_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,reviewed_by UUID REFERENCES public.users(id) ON DELETE RESTRICT,
 enabled BOOLEAN NOT NULL,threshold NUMERIC NOT NULL CHECK(threshold>=0),frequency TEXT NOT NULL CHECK(frequency IN ('DAILY','WEEKLY','MONTHLY')),timezone TEXT NOT NULL,next_run_at TIMESTAMPTZ NOT NULL,window_minutes INTEGER NOT NULL CHECK(window_minutes BETWEEN 5 AND 1440),reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED')),review_reason TEXT,expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_schedule_change_open ON public.treasury_schedule_change_requests(goal_id) WHERE status='PENDING';
CREATE TABLE IF NOT EXISTS public.treasury_schedule_executions(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,goal_id UUID NOT NULL REFERENCES public.goals(id) ON DELETE CASCADE,schedule_version INTEGER NOT NULL,scheduled_for TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL DEFAULT 'CLAIMED' CHECK(status IN ('CLAIMED','COMPLETED','SKIPPED','FAILED')),worker_id TEXT NOT NULL,lease_until TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL DEFAULT 1,last_error TEXT,transaction_id UUID REFERENCES public.transactions(id) ON DELETE SET NULL,claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),finished_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(goal_id,schedule_version,scheduled_for)
);
ALTER TABLE public.treasury_schedule_change_requests ENABLE ROW LEVEL SECURITY;ALTER TABLE public.treasury_schedule_executions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS treasury_schedule_change_service ON public.treasury_schedule_change_requests;
DROP POLICY IF EXISTS treasury_schedule_execution_service ON public.treasury_schedule_executions;
CREATE POLICY treasury_schedule_change_service ON public.treasury_schedule_change_requests FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
CREATE POLICY treasury_schedule_execution_service ON public.treasury_schedule_executions FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON TABLE public.treasury_schedule_change_requests,public.treasury_schedule_executions FROM anon,authenticated;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.treasury_schedule_change_requests,public.treasury_schedule_executions TO service_role;

CREATE OR REPLACE FUNCTION public.request_treasury_schedule_change_v1(p_actor_id UUID,p_goal_id UUID,p_enabled BOOLEAN,p_threshold NUMERIC,p_frequency TEXT,p_timezone TEXT,p_next_run_at TIMESTAMPTZ,p_window_minutes INTEGER,p_reason TEXT)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_goal public.goals%ROWTYPE;v_actor public.users%ROWTYPE;v_id UUID;v_tz TEXT:=BTRIM(COALESCE(p_timezone,''));v_frequency TEXT:=UPPER(BTRIM(COALESCE(p_frequency,'')));
BEGIN
 SELECT * INTO v_goal FROM public.goals WHERE id=p_goal_id FOR UPDATE;SELECT * INTO v_actor FROM public.users WHERE id=p_actor_id;
 IF v_goal.id IS NULL OR v_goal.organization_id IS NULL OR v_goal.is_corporate<>TRUE THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_CORPORATE_GOAL_REQUIRED';END IF;
 IF v_actor.organization_id IS DISTINCT FROM v_goal.organization_id OR UPPER(COALESCE(v_actor.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_actor.org_role,'')) NOT IN ('ADMIN','SIGNATORY') THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REQUESTER_DENIED';END IF;
 IF p_threshold<0 OR v_frequency NOT IN ('DAILY','WEEKLY','MONTHLY') OR p_next_run_at<=NOW() OR p_window_minutes NOT BETWEEN 5 AND 1440 OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 OR NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_tz) THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_INVALID';END IF;
 UPDATE public.treasury_schedule_change_requests SET status='EXPIRED',updated_at=NOW() WHERE goal_id=p_goal_id AND status='PENDING' AND expires_at<=NOW();
 INSERT INTO public.treasury_schedule_change_requests(organization_id,goal_id,requested_by,enabled,threshold,frequency,timezone,next_run_at,window_minutes,reason) VALUES(v_goal.organization_id,p_goal_id,p_actor_id,p_enabled,p_threshold,v_frequency,v_tz,p_next_run_at,p_window_minutes,BTRIM(p_reason)) RETURNING id INTO v_id;RETURN v_id;
END$$;

CREATE OR REPLACE FUNCTION public.respond_treasury_schedule_change_v1(p_reviewer_id UUID,p_request_id UUID,p_decision TEXT,p_reason TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_r public.treasury_schedule_change_requests%ROWTYPE;v_u public.users%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(COALESCE(p_decision,'')));
BEGIN
 SELECT * INTO v_r FROM public.treasury_schedule_change_requests WHERE id=p_request_id FOR UPDATE;IF NOT FOUND OR v_r.status<>'PENDING' THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REQUEST_NOT_OPEN';END IF;
 IF v_r.expires_at<=NOW() THEN UPDATE public.treasury_schedule_change_requests SET status='EXPIRED',updated_at=NOW() WHERE id=p_request_id;RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED');END IF;
 SELECT * INTO v_u FROM public.users WHERE id=p_reviewer_id;IF v_u.organization_id IS DISTINCT FROM v_r.organization_id OR UPPER(COALESCE(v_u.account_status,''))<>'ACTIVE' OR UPPER(COALESCE(v_u.org_role,'')) NOT IN ('ADMIN','SIGNATORY') OR p_reviewer_id=v_r.requested_by THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_MAKER_CHECKER_REQUIRED';END IF;
 IF v_decision NOT IN ('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_REVIEW_INVALID';END IF;
 IF v_decision='APPROVE' THEN UPDATE public.goals SET auto_sweep_enabled=v_r.enabled,sweep_threshold=v_r.threshold,sweep_frequency=v_r.frequency,sweep_timezone=v_r.timezone,sweep_next_run_at=v_r.next_run_at,sweep_window_minutes=v_r.window_minutes,sweep_schedule_version=sweep_schedule_version+1,updated_at=NOW() WHERE id=v_r.goal_id;END IF;
 UPDATE public.treasury_schedule_change_requests SET status=CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;
 RETURN jsonb_build_object('request_id',p_request_id,'status',CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,'goal_id',v_r.goal_id,'organization_id',v_r.organization_id);
END$$;

CREATE OR REPLACE FUNCTION public.claim_due_treasury_sweeps_v1(p_worker_id TEXT,p_limit INTEGER DEFAULT 25,p_lease_seconds INTEGER DEFAULT 120)
RETURNS SETOF public.treasury_schedule_executions LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_goal public.goals%ROWTYPE;v_run TIMESTAMPTZ;v_exec public.treasury_schedule_executions%ROWTYPE;
BEGIN
 IF LENGTH(BTRIM(COALESCE(p_worker_id,'')))<3 OR p_limit NOT BETWEEN 1 AND 100 OR p_lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_WORKER_INVALID';END IF;
 FOR v_goal IN SELECT * FROM public.goals WHERE is_corporate=TRUE AND status='ACTIVE' AND auto_sweep_enabled=TRUE AND sweep_next_run_at<=NOW() ORDER BY sweep_next_run_at FOR UPDATE SKIP LOCKED LIMIT p_limit LOOP
  v_run:=v_goal.sweep_next_run_at;
  INSERT INTO public.treasury_schedule_executions(organization_id,goal_id,schedule_version,scheduled_for,status,worker_id,lease_until,finished_at,last_error) VALUES(v_goal.organization_id,v_goal.id,v_goal.sweep_schedule_version,v_run,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN 'SKIPPED' ELSE 'CLAIMED' END,BTRIM(p_worker_id),NOW()+(p_lease_seconds||' seconds')::INTERVAL,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN NOW() ELSE NULL END,CASE WHEN v_run<NOW()-(v_goal.sweep_window_minutes||' minutes')::INTERVAL THEN 'MISSED_EXECUTION_WINDOW' ELSE NULL END) ON CONFLICT(goal_id,schedule_version,scheduled_for) DO NOTHING RETURNING * INTO v_exec;
  UPDATE public.goals SET sweep_next_run_at=(CASE v_goal.sweep_frequency WHEN 'DAILY' THEN (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '1 day' WHEN 'WEEKLY' THEN (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '7 days' ELSE (v_run AT TIME ZONE v_goal.sweep_timezone)+INTERVAL '1 month' END) AT TIME ZONE v_goal.sweep_timezone,updated_at=NOW() WHERE id=v_goal.id;
  IF v_exec.id IS NOT NULL AND v_exec.status='CLAIMED' THEN RETURN NEXT v_exec;END IF;
 END LOOP;RETURN;
END$$;

CREATE OR REPLACE FUNCTION public.reclaim_treasury_schedule_executions_v1(p_worker_id TEXT,p_limit INTEGER DEFAULT 25,p_lease_seconds INTEGER DEFAULT 120)
RETURNS SETOF public.treasury_schedule_executions LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF LENGTH(BTRIM(COALESCE(p_worker_id,'')))<3 OR p_limit NOT BETWEEN 1 AND 100 OR p_lease_seconds NOT BETWEEN 30 AND 900 THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_WORKER_INVALID';END IF;
 RETURN QUERY WITH candidates AS (SELECT id FROM public.treasury_schedule_executions WHERE status='CLAIMED' AND lease_until<=NOW() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT p_limit)
 UPDATE public.treasury_schedule_executions e SET worker_id=BTRIM(p_worker_id),lease_until=NOW()+(p_lease_seconds||' seconds')::INTERVAL,attempts=e.attempts+1,updated_at=NOW() FROM candidates c WHERE e.id=c.id RETURNING e.*;
END$$;

CREATE OR REPLACE FUNCTION public.finish_treasury_schedule_execution_v1(p_execution_id UUID,p_worker_id TEXT,p_status TEXT,p_transaction_id UUID DEFAULT NULL,p_error TEXT DEFAULT NULL)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 IF UPPER(p_status) NOT IN ('COMPLETED','SKIPPED','FAILED') THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_FINISH_INVALID';END IF;
 UPDATE public.treasury_schedule_executions SET status=UPPER(p_status),transaction_id=p_transaction_id,last_error=LEFT(p_error,1000),finished_at=NOW(),updated_at=NOW() WHERE id=p_execution_id AND worker_id=p_worker_id AND status='CLAIMED';IF NOT FOUND THEN RAISE EXCEPTION 'TREASURY_SCHEDULE_CLAIM_REQUIRED';END IF;
END$$;

REVOKE ALL ON FUNCTION public.request_treasury_schedule_change_v1(UUID,UUID,BOOLEAN,NUMERIC,TEXT,TEXT,TIMESTAMPTZ,INTEGER,TEXT) FROM PUBLIC;REVOKE ALL ON FUNCTION public.respond_treasury_schedule_change_v1(UUID,UUID,TEXT,TEXT) FROM PUBLIC;REVOKE ALL ON FUNCTION public.claim_due_treasury_sweeps_v1(TEXT,INTEGER,INTEGER) FROM PUBLIC;REVOKE ALL ON FUNCTION public.reclaim_treasury_schedule_executions_v1(TEXT,INTEGER,INTEGER) FROM PUBLIC;REVOKE ALL ON FUNCTION public.finish_treasury_schedule_execution_v1(UUID,TEXT,TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_treasury_schedule_change_v1(UUID,UUID,BOOLEAN,NUMERIC,TEXT,TEXT,TIMESTAMPTZ,INTEGER,TEXT) TO service_role;GRANT EXECUTE ON FUNCTION public.respond_treasury_schedule_change_v1(UUID,UUID,TEXT,TEXT) TO service_role;GRANT EXECUTE ON FUNCTION public.claim_due_treasury_sweeps_v1(TEXT,INTEGER,INTEGER) TO service_role;GRANT EXECUTE ON FUNCTION public.reclaim_treasury_schedule_executions_v1(TEXT,INTEGER,INTEGER) TO service_role;GRANT EXECUTE ON FUNCTION public.finish_treasury_schedule_execution_v1(UUID,TEXT,TEXT,UUID,TEXT) TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260919_scheduled_treasury_operations.sql



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

-- BEGIN SYNCED MIGRATION: 20260922_financial_exception_workflow.sql
CREATE TABLE IF NOT EXISTS public.financial_exception_cases(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),source_type TEXT NOT NULL CHECK(source_type IN('RECONCILIATION','TRANSACTION','SETTLEMENT','PROVIDER','TREASURY','MERCHANT','AGENT')),source_id TEXT NOT NULL,
 organization_id UUID REFERENCES public.organizations(id) ON DELETE RESTRICT,severity TEXT NOT NULL CHECK(severity IN('LOW','MEDIUM','HIGH','CRITICAL')),category TEXT NOT NULL,title TEXT NOT NULL,details JSONB NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN('OPEN','ASSIGNED','PENDING_APPROVAL','RESOLVED','REJECTED','ESCALATED')),assigned_to TEXT,assigned_by TEXT,assigned_at TIMESTAMPTZ,
 sla_due_at TIMESTAMPTZ NOT NULL,escalated_at TIMESTAMPTZ,resolution_request_id UUID,resolved_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(source_type,source_id,category)
);
CREATE TABLE IF NOT EXISTS public.financial_exception_resolution_requests(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),case_id UUID NOT NULL REFERENCES public.financial_exception_cases(id) ON DELETE RESTRICT,requested_by TEXT NOT NULL,reviewed_by TEXT,
 disposition TEXT NOT NULL CHECK(disposition IN('FALSE_POSITIVE','RECONCILED','REVERSED','REPAIRED','ACCEPTED_RISK','REFERRED')),summary TEXT NOT NULL,evidence JSONB NOT NULL,
 status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','APPROVED','REJECTED','EXPIRED')),review_reason TEXT,expires_at TIMESTAMPTZ NOT NULL DEFAULT(NOW()+INTERVAL '24 hours'),reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fin_exception_open_resolution ON public.financial_exception_resolution_requests(case_id) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_fin_exception_queue ON public.financial_exception_cases(status,severity,sla_due_at);
ALTER TABLE public.financial_exception_cases ENABLE ROW LEVEL SECURITY;ALTER TABLE public.financial_exception_resolution_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_exception_cases_service ON public.financial_exception_cases;DROP POLICY IF EXISTS financial_exception_resolutions_service ON public.financial_exception_resolution_requests;
CREATE POLICY financial_exception_cases_service ON public.financial_exception_cases FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);CREATE POLICY financial_exception_resolutions_service ON public.financial_exception_resolution_requests FOR ALL TO service_role USING(TRUE) WITH CHECK(TRUE);
REVOKE ALL ON public.financial_exception_cases,public.financial_exception_resolution_requests FROM anon,authenticated;GRANT SELECT,INSERT ON public.financial_exception_cases,public.financial_exception_resolution_requests TO service_role;

CREATE OR REPLACE FUNCTION public.open_financial_exception_v1(p_source_type TEXT,p_source_id TEXT,p_organization_id UUID,p_severity TEXT,p_category TEXT,p_title TEXT,p_details JSONB)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_id UUID;v_severity TEXT:=UPPER(BTRIM(p_severity));v_source TEXT:=UPPER(BTRIM(p_source_type));
BEGIN IF v_source NOT IN('RECONCILIATION','TRANSACTION','SETTLEMENT','PROVIDER','TREASURY','MERCHANT','AGENT') OR v_severity NOT IN('LOW','MEDIUM','HIGH','CRITICAL') OR LENGTH(BTRIM(COALESCE(p_source_id,'')))<1 OR LENGTH(BTRIM(COALESCE(p_category,'')))<3 OR LENGTH(BTRIM(COALESCE(p_title,'')))<5 THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_INVALID';END IF;
 INSERT INTO public.financial_exception_cases(source_type,source_id,organization_id,severity,category,title,details,sla_due_at) VALUES(v_source,BTRIM(p_source_id),p_organization_id,v_severity,UPPER(BTRIM(p_category)),BTRIM(p_title),COALESCE(p_details,'{}'),NOW()+CASE v_severity WHEN 'CRITICAL' THEN INTERVAL '15 minutes' WHEN 'HIGH' THEN INTERVAL '2 hours' WHEN 'MEDIUM' THEN INTERVAL '8 hours' ELSE INTERVAL '24 hours' END) ON CONFLICT(source_type,source_id,category) DO UPDATE SET details=financial_exception_cases.details||EXCLUDED.details,severity=CASE WHEN array_position(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'],EXCLUDED.severity)>array_position(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'],financial_exception_cases.severity) THEN EXCLUDED.severity ELSE financial_exception_cases.severity END,updated_at=NOW() RETURNING id INTO v_id;RETURN v_id;END$$;
CREATE OR REPLACE FUNCTION public.assign_financial_exception_v1(p_actor_id TEXT,p_case_id UUID,p_assignee_id TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_case public.financial_exception_cases%ROWTYPE;BEGIN IF NOT public.audit_export_officer_v1(p_actor_id) OR NOT public.audit_export_officer_v1(p_assignee_id) THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_ASSIGNMENT_DENIED';END IF;SELECT * INTO v_case FROM public.financial_exception_cases WHERE id=p_case_id FOR UPDATE;IF NOT FOUND OR v_case.status IN('RESOLVED','REJECTED') THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_NOT_ASSIGNABLE';END IF;UPDATE public.financial_exception_cases SET assigned_to=p_assignee_id,assigned_by=p_actor_id,assigned_at=NOW(),status='ASSIGNED',updated_at=NOW() WHERE id=p_case_id;RETURN jsonb_build_object('case_id',p_case_id,'status','ASSIGNED','assigned_to',p_assignee_id);END$$;
CREATE OR REPLACE FUNCTION public.request_financial_exception_resolution_v1(p_actor_id TEXT,p_case_id UUID,p_disposition TEXT,p_summary TEXT,p_evidence JSONB)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_case public.financial_exception_cases%ROWTYPE;v_id UUID;BEGIN SELECT * INTO v_case FROM public.financial_exception_cases WHERE id=p_case_id FOR UPDATE;IF NOT FOUND OR v_case.status NOT IN('ASSIGNED','ESCALATED') OR v_case.assigned_to<>p_actor_id OR NOT public.audit_export_officer_v1(p_actor_id) THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_RESOLUTION_DENIED';END IF;IF UPPER(p_disposition) NOT IN('FALSE_POSITIVE','RECONCILED','REVERSED','REPAIRED','ACCEPTED_RISK','REFERRED') OR LENGTH(BTRIM(COALESCE(p_summary,'')))<10 OR COALESCE(jsonb_object_length(p_evidence),0)=0 THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_EVIDENCE_REQUIRED';END IF;UPDATE public.financial_exception_resolution_requests SET status='EXPIRED',updated_at=NOW() WHERE case_id=p_case_id AND status='PENDING' AND expires_at<=NOW();INSERT INTO public.financial_exception_resolution_requests(case_id,requested_by,disposition,summary,evidence) VALUES(p_case_id,p_actor_id,UPPER(p_disposition),BTRIM(p_summary),p_evidence) RETURNING id INTO v_id;UPDATE public.financial_exception_cases SET status='PENDING_APPROVAL',resolution_request_id=v_id,updated_at=NOW() WHERE id=p_case_id;RETURN v_id;END$$;
CREATE OR REPLACE FUNCTION public.respond_financial_exception_resolution_v1(p_reviewer_id TEXT,p_request_id UUID,p_decision TEXT,p_reason TEXT)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_r public.financial_exception_resolution_requests%ROWTYPE;v_decision TEXT:=UPPER(BTRIM(p_decision));BEGIN SELECT * INTO v_r FROM public.financial_exception_resolution_requests WHERE id=p_request_id FOR UPDATE;IF NOT FOUND OR v_r.status<>'PENDING' THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_RESOLUTION_NOT_OPEN';END IF;IF v_r.expires_at<=NOW() THEN UPDATE public.financial_exception_resolution_requests SET status='EXPIRED',updated_at=NOW() WHERE id=p_request_id;UPDATE public.financial_exception_cases SET status='ASSIGNED',resolution_request_id=NULL,updated_at=NOW() WHERE id=v_r.case_id;RETURN jsonb_build_object('request_id',p_request_id,'status','EXPIRED');END IF;IF NOT public.audit_export_officer_v1(p_reviewer_id) OR p_reviewer_id=v_r.requested_by THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_MAKER_CHECKER_REQUIRED';END IF;IF v_decision NOT IN('APPROVE','REJECT') OR LENGTH(BTRIM(COALESCE(p_reason,'')))<10 THEN RAISE EXCEPTION 'FINANCIAL_EXCEPTION_REVIEW_INVALID';END IF;UPDATE public.financial_exception_resolution_requests SET status=CASE WHEN v_decision='APPROVE' THEN 'APPROVED' ELSE 'REJECTED' END,reviewed_by=p_reviewer_id,review_reason=BTRIM(p_reason),reviewed_at=NOW(),updated_at=NOW() WHERE id=p_request_id;UPDATE public.financial_exception_cases SET status=CASE WHEN v_decision='APPROVE' THEN 'RESOLVED' ELSE 'REJECTED' END,resolved_at=CASE WHEN v_decision='APPROVE' THEN NOW() ELSE NULL END,updated_at=NOW() WHERE id=v_r.case_id;RETURN jsonb_build_object('request_id',p_request_id,'case_id',v_r.case_id,'status',CASE WHEN v_decision='APPROVE' THEN 'RESOLVED' ELSE 'REJECTED' END);END$$;
CREATE OR REPLACE FUNCTION public.escalate_overdue_financial_exceptions_v1() RETURNS SETOF public.financial_exception_cases LANGUAGE sql SECURITY DEFINER SET search_path=public AS $$UPDATE public.financial_exception_cases SET status='ESCALATED',escalated_at=NOW(),updated_at=NOW() WHERE status IN('OPEN','ASSIGNED') AND sla_due_at<=NOW() RETURNING *$$;
REVOKE ALL ON FUNCTION public.open_financial_exception_v1(TEXT,TEXT,UUID,TEXT,TEXT,TEXT,JSONB),public.assign_financial_exception_v1(TEXT,UUID,TEXT),public.request_financial_exception_resolution_v1(TEXT,UUID,TEXT,TEXT,JSONB),public.respond_financial_exception_resolution_v1(TEXT,UUID,TEXT,TEXT),public.escalate_overdue_financial_exceptions_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.open_financial_exception_v1(TEXT,TEXT,UUID,TEXT,TEXT,TEXT,JSONB),public.assign_financial_exception_v1(TEXT,UUID,TEXT),public.request_financial_exception_resolution_v1(TEXT,UUID,TEXT,TEXT,JSONB),public.respond_financial_exception_resolution_v1(TEXT,UUID,TEXT,TEXT),public.escalate_overdue_financial_exceptions_v1() TO service_role;
NOTIFY pgrst,'reload schema';
-- END SYNCED MIGRATION: 20260922_financial_exception_workflow.sql

-- BEGIN SYNCED MIGRATION: 20260923_external_api_access_guard.sql
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
-- END SYNCED MIGRATION: 20260923_external_api_access_guard.sql

-- BEGIN SYNCED MIGRATION: 20260924_sandbox_payment_isolation.sql
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
-- END SYNCED MIGRATION: 20260924_sandbox_payment_isolation.sql

-- 20260925 company settlement account registry
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
