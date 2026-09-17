-- Card fees resolve only to an exact active SERVICE_REVENUE account in the card currency.
-- The legacy parameter is retained for API compatibility and must equal that exact vault.
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
