-- Enforce exact wallet denomination and balance each currency in atomic postings.
ALTER TABLE public.financial_ledger ADD COLUMN IF NOT EXISTS currency TEXT;

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
