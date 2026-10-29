--ban
UPDATE public.stax_accounts
SET
    is_banned = TRUE,
    ban_reason = '利用規約違反',
    banned_at = NOW()
WHERE user_id = '対象ユーザーID';

--remove ban
UPDATE public.stax_accounts
SET
    is_banned = FALSE,
    ban_reason = NULL,
    banned_at = NULL
WHERE user_id = '対象ユーザーID';

--password reset
SELECT public.stax_admin_reset_password(
    '変更対象のユーザーID',
    '新しいパスワード'
);

--list
SELECT
    user_id AS "ID",
    display_name AS "Display Name",
    is_banned AS "BAN",
    ban_reason AS "BAN Reason",
    banned_at AS "Banned At",
    password_reset_required AS "Password Reset Required",
    created_at AS "Created At"
FROM public.stax_accounts
ORDER BY created_at DESC;
