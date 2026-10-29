
import { createClient } from "npm:@supabase/supabase-js@2";
import bcrypt from "npm:bcryptjs@2.4.3";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

const env = (name: string) => {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
};

const db = () =>
  createClient(
    env("SUPABASE_URL"),
    env("SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false, autoRefreshToken: false } },
  );

const validUserId = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_]{3,20}$/.test(value);

const validPassword = (value: unknown): value is string =>
  typeof value === "string" && value.length >= 8 && value.length <= 128;

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createSession(
  supabase: ReturnType<typeof db>,
  accountId: string,
) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(tokenBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const { error } = await supabase.from("stax_sessions").insert({
    token_hash: tokenHash,
    account_id: accountId,
    expires_at: expiresAt.toISOString(),
  });

  if (error) throw error;
  return { token, expires_at: expiresAt.toISOString() };
}

async function getSession(
  supabase: ReturnType<typeof db>,
  request: Request,
) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7).trim()
    : "";

  if (!token || token.length > 512) return null;

  const tokenHash = await sha256(token);
  const { data, error } = await supabase
    .from("stax_sessions")
    .select(
      "account_id, expires_at, stax_accounts!inner(id,user_id,display_name,avatar_url,bio,is_private,is_banned)",
    )
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();

  if (error || !data) return null;

  const account = Array.isArray(data.stax_accounts)
    ? data.stax_accounts[0]
    : data.stax_accounts;

  if (!account || account.is_banned) return null;

  return {
    account,
    accountId: data.account_id,
    tokenHash,
  };
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (request.method !== "POST") {
    return json({ error: "POST only" }, 405);
  }

  try {
    const body = await request.json();
    const action = body?.action;

    if (typeof action !== "string") {
      return json({ error: "action is required" }, 400);
    }

    const supabase = db();

    if (action === "register") {
      const userId = body.user_id;
      const password = body.password;
      const displayName = body.display_name;

      if (!validUserId(userId)) {
        return json({
          error: "IDは英数字と_を使った3〜20文字にしてください。",
        }, 400);
      }

      if (!validPassword(password)) {
        return json({
          error: "パスワードは8〜128文字にしてください。",
        }, 400);
      }

      if (
        typeof displayName !== "string" ||
        displayName.trim().length < 1 ||
        displayName.trim().length > 40
      ) {
        return json({ error: "表示名は1〜40文字にしてください。" }, 400);
      }

      const { data: existing, error: lookupError } = await supabase
        .from("stax_accounts")
        .select("id")
        .ilike("user_id", userId)
        .limit(1);

      if (lookupError) throw lookupError;

      if (existing && existing.length > 0) {
        return json({ error: "このIDは既に使用されています。" }, 409);
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const { data: account, error: insertError } = await supabase
        .from("stax_accounts")
        .insert({
          user_id: userId,
          display_name: displayName.trim(),
          password_hash: passwordHash,
        })
        .select("id,user_id,display_name,avatar_url,bio,is_private")
        .single();

      if (insertError) {
        if (insertError.code === "23505") {
          return json({ error: "このIDは既に使用されています。" }, 409);
        }
        throw insertError;
      }

      const session = await createSession(supabase, account.id);

      return json({
        user: account,
        token: session.token,
        expires_at: session.expires_at,
      }, 201);
    }

    if (action === "login") {
      const userId = body.user_id;
      const password = body.password;

      if (!validUserId(userId) || !validPassword(password)) {
        return json({ error: "IDまたはパスワードが正しくありません。" }, 401);
      }

      const { data: account, error } = await supabase
        .from("stax_accounts")
        .select(
          "id,user_id,display_name,password_hash,avatar_url,bio,is_private,is_banned",
        )
        .ilike("user_id", userId)
        .maybeSingle();

      if (error) throw error;

      if (
        !account ||
        account.is_banned ||
        !(await bcrypt.compare(password, account.password_hash))
      ) {
        return json({ error: "IDまたはパスワードが正しくありません。" }, 401);
      }

      const { error: updateError } = await supabase
        .from("stax_accounts")
        .update({ last_login_at: new Date().toISOString() })
        .eq("id", account.id);

      if (updateError) throw updateError;

      const session = await createSession(supabase, account.id);

      const { password_hash: _secret, is_banned: _banned, ...safeUser } =
        account;

      return json({
        user: safeUser,
        token: session.token,
        expires_at: session.expires_at,
      });
    }

    if (action === "me") {
      const session = await getSession(supabase, request);

      if (!session) return json({ error: "ログインしてください。" }, 401);

      return json({ user: session.account });
    }

    if (action === "logout") {
      const session = await getSession(supabase, request);

      if (!session) return json({ success: true });

      const { error } = await supabase
        .from("stax_sessions")
        .delete()
        .eq("token_hash", session.tokenHash);

      if (error) throw error;

      return json({ success: true });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (error) {
    console.error("stax-auth error:", error);
    return json({ error: "サーバー処理に失敗しました。" }, 500);
  }
});
