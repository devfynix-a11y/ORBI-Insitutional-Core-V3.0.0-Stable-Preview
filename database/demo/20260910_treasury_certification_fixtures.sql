\set ON_ERROR_STOP on

DO $$
BEGIN
    IF current_database() <> 'orbi_treasury_certification' THEN
        RAISE EXCEPTION 'DISPOSABLE_DATABASE_REQUIRED: refusing treasury certification fixtures on %', current_database();
    END IF;
END $$;

INSERT INTO auth.users (id, email, encrypted_password, email_confirmed_at)
VALUES
    ('00000000-0000-0000-0000-000000000014', 'treasury-maker@cert.invalid', 'disabled', NOW()),
    ('00000000-0000-0000-0000-000000000015', 'treasury-admin1@cert.invalid', 'disabled', NOW()),
    ('00000000-0000-0000-0000-000000000016', 'treasury-admin2@cert.invalid', 'disabled', NOW()),
    ('00000000-0000-0000-0000-000000000017', 'treasury-cross-admin@cert.invalid', 'disabled', NOW()),
    ('00000000-0000-0000-0000-000000000022', 'organization-invitee@cert.invalid', 'disabled', NOW()),
    ('00000000-0000-0000-0000-000000000023', 'leadership-target@cert.invalid', 'disabled', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organizations (id, name, base_currency, status, metadata)
VALUES
    ('00000000-0000-0000-0000-000000000018', 'Disposable Treasury Certification', 'TZS', 'ACTIVE', '{"integration_test":true}'),
    ('00000000-0000-0000-0000-000000000021', 'Disposable Cross Organization', 'TZS', 'ACTIVE', '{"integration_test":true}')
ON CONFLICT (id) DO UPDATE SET status = 'ACTIVE';

UPDATE public.organizations SET primary_admin_user_id='00000000-0000-0000-0000-000000000015'
WHERE id='00000000-0000-0000-0000-000000000018';

UPDATE public.users SET
    account_status = 'ACTIVE', organization_id = '00000000-0000-0000-0000-000000000018', org_role = 'ADMIN'
WHERE id = '00000000-0000-0000-0000-000000000014';
UPDATE public.users SET
    account_status = 'ACTIVE', organization_id = '00000000-0000-0000-0000-000000000018', org_role = 'ADMIN'
WHERE id IN ('00000000-0000-0000-0000-000000000015', '00000000-0000-0000-0000-000000000016');
UPDATE public.users SET
    account_status = 'ACTIVE', organization_id = '00000000-0000-0000-0000-000000000021', org_role = 'ADMIN', role = 'SUPER_ADMIN'
WHERE id = '00000000-0000-0000-0000-000000000017';
UPDATE public.users SET
    account_status = 'ACTIVE', organization_id = NULL, org_role = NULL
WHERE id = '00000000-0000-0000-0000-000000000022';
UPDATE public.users SET
    account_status = 'ACTIVE', organization_id = '00000000-0000-0000-0000-000000000018', org_role = 'MEMBER'
WHERE id = '00000000-0000-0000-0000-000000000023';

INSERT INTO public.treasury_approvers(organization_id,user_id,role,status)
VALUES
 ('00000000-0000-0000-0000-000000000018','00000000-0000-0000-0000-000000000015','ADMIN','ACTIVE'),
 ('00000000-0000-0000-0000-000000000018','00000000-0000-0000-0000-000000000016','ADMIN','ACTIVE'),
 ('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000017','ADMIN','ACTIVE')
ON CONFLICT(organization_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='ACTIVE',updated_at=NOW();

INSERT INTO public.goals (
    id, user_id, name, target, current, target_amount, current_amount,
    organization_id, is_corporate, status
) VALUES (
    '00000000-0000-0000-0000-000000000019',
    '00000000-0000-0000-0000-000000000014',
    'Disposable Treasury Goal', 100000, 10000, 100000, 10000,
    '00000000-0000-0000-0000-000000000018', TRUE, 'ACTIVE'
)
ON CONFLICT (id) DO UPDATE SET current = 10000, current_amount = 10000, status = 'ACTIVE';

INSERT INTO public.wallets (id, user_id, name, balance, currency, type, status, metadata)
VALUES (
    '00000000-0000-0000-0000-000000000020',
    '00000000-0000-0000-0000-000000000014',
    'Disposable Treasury Destination', 5000, 'TZS', 'operating', 'active', '{"integration_test":true}'
)
ON CONFLICT (id) DO UPDATE SET balance = 5000, status = 'active';
