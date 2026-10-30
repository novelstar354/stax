
import { createClient } from "npm:@supabase/supabase-js@2";

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

async function sha256(value: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function requiredText(value: unknown, max = 2000): string | null {
  if (typeof value !== "string") return null;
  const result = value.trim();
  return result.length > 0 && result.length <= max ? result : null;
}

async function authenticate(request: Request, supabase: ReturnType<typeof db>) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token || token.length > 512) return null;

  const tokenHash = await sha256(token);
  const { data: session, error } = await supabase
    .from("stax_sessions")
    .select("account_id")
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();

  if (error || !session) return null;

  const { data: account, error: accountError } = await supabase
    .from("stax_accounts")
    .select("id,user_id,display_name,avatar_url,is_private,is_banned,is_admin")
    .eq("id", session.account_id)
    .maybeSingle();

  if (accountError || !account || account.is_banned) return null;
  return { account, tokenHash };
}

async function blockedEitherWay(
  supabase: ReturnType<typeof db>,
  a: string,
  b: string,
) {
  const { data, error } = await supabase
    .from("stax_blocks")
    .select("blocker_id")
    .or(`and(blocker_id.eq.${a},blocked_id.eq.${b}),and(blocker_id.eq.${b},blocked_id.eq.${a})`)
    .limit(1);

  if (error) throw error;
  return Boolean(data?.length);
}

async function notify(
  supabase: ReturnType<typeof db>,
  recipientId: string,
  actorId: string,
  type: string,
  postId?: string,
) {
  if (recipientId === actorId) return;

  const { error } = await supabase.from("stax_notifications").insert({
    recipient_id: recipientId,
    actor_id: actorId,
    notification_type: type,
    post_id: postId ?? null,
  });

  if (error) throw error;
}

async function isFollowing(
  supabase: ReturnType<typeof db>,
  followerId: string,
  followingId: string,
) {
  const { data, error } = await supabase
    .from("stax_follows")
    .select("follower_id")
    .eq("follower_id", followerId)
    .eq("following_id", followingId)
    .maybeSingle();

  if (error) throw error;
  return Boolean(data);
}

async function isMutualFollowing(
  supabase: ReturnType<typeof db>,
  a: string,
  b: string,
) {
  return (await isFollowing(supabase, a, b)) &&
    (await isFollowing(supabase, b, a));
}

async function isConversationMember(
  supabase: ReturnType<typeof db>,
  conversationId: string,
  accountId: string,
) {
  const { data, error } = await supabase
    .from("stax_conversation_members")
    .select("account_id")
    .eq("conversation_id", conversationId)
    .eq("account_id", accountId)
    .maybeSingle();

  if (error) throw error;
  return Boolean(data);
}

async function attachPostCounts(supabase: ReturnType<typeof db>, posts: any[]) {
  return await Promise.all(posts.map(async (post) => {
    const [{ count: comments, error: commentsError }, { count: reposts, error: repostsError }] = await Promise.all([
      supabase.from("stax_posts").select("id", { count: "exact", head: true })
        .eq("reply_to_id", post.id).eq("is_deleted", false),
      supabase.from("stax_posts").select("id", { count: "exact", head: true })
        .eq("repost_of_id", post.id).eq("is_deleted", false),
    ]);
    if (commentsError) throw commentsError;
    if (repostsError) throw repostsError;
    return { ...post, comment_count: comments || 0, repost_count: reposts || 0 };
  }));
}

async function attachPostMedia(supabase: ReturnType<typeof db>, posts: any[]) {
  if (!posts.length) return posts;
  const ids = posts.map((post) => post.id).filter(Boolean);
  if (!ids.length) return posts;
  const { data, error } = await supabase.from("stax_post_media")
    .select("post_id,media_url,media_type,position")
    .in("post_id", ids).order("position", { ascending: true });
  if (error) throw error;
  const grouped = new Map<string, any[]>();
  for (const media of data || []) {
    const list = grouped.get(media.post_id) || [];
    list.push(media);
    grouped.set(media.post_id, list);
  }
  return posts.map((post) => ({ ...post, media: grouped.get(post.id) || [] }));
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (request.method !== "POST") return json({ error: "POST only" }, 405);

  try {
    const body = await request.json();
    const action = body?.action;
    if (typeof action !== "string") {
      return json({ error: "action is required" }, 400);
    }

    const supabase = db();
    const auth = await authenticate(request, supabase);
    if (!auth) return json({ error: "ログインしてください。" }, 401);

    const me = auth.account;
    const myId = me.id;

    // Current account
    if (action === "me") return json({ user: me });

    // Update own profile
    if (action === "update_profile") {
      const displayName = requiredText(body.display_name, 40);
      if (!displayName) {
        return json({ error: "表示名は1〜40文字で入力してください。" }, 400);
      }

      const bio = typeof body.bio === "string" ? body.bio.trim().slice(0, 300) : "";
      const website = typeof body.website === "string" ? body.website.trim().slice(0, 2048) : "";
      const avatarUrl = typeof body.avatar_url === "string" ? body.avatar_url.trim().slice(0, 2048) : "";

      for (const [label, value] of [["ウェブサイト", website], ["プロフィール画像URL", avatarUrl]] as const) {
        if (value) {
          try {
            const parsed = new URL(value);
            if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("bad protocol");
          } catch {
            return json({ error: `${label}にはhttpまたはhttpsのURLを指定してください。` }, 400);
          }
        }
      }

      const { data: user, error } = await supabase
        .from("stax_accounts")
        .update({
          display_name: displayName,
          bio,
          website: website || null,
          ...(Object.prototype.hasOwnProperty.call(body, "avatar_url") ? { avatar_url: avatarUrl || null } : {}),
          ...(typeof body.is_private === "boolean" ? { is_private: body.is_private } : {}),
          updated_at: new Date().toISOString(),
        })
        .eq("id", myId)
        .select("id,user_id,display_name,bio,website,avatar_url,is_private,is_banned,is_admin,updated_at")
        .single();

      if (error) throw error;
      return json({ user });
    }

    // Upload profile avatar to the public Supabase Storage bucket "stax-avatars".
    // Client sends data_url: "data:image/png;base64,..." (max 2 MiB).
    if (action === "upload_avatar") {
      const dataUrl = typeof body.data_url === "string" ? body.data_url : "";
      const match = dataUrl.match(/^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+/=]+)$/);
      if (!match) return json({ error: "PNG/JPEG/WEBP/GIF画像を選択してください。" }, 400);
      const mime = match[1];
      let binary: string;
      try { binary = atob(match[2]); } catch { return json({ error: "画像データが不正です。" }, 400); }
      if (binary.length < 1 || binary.length > 2 * 1024 * 1024) {
        return json({ error: "画像は2MB以下にしてください。" }, 413);
      }
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const ext = mime === "image/jpeg" ? "jpg" : mime.split("/")[1];
      const path = `${myId}/${crypto.randomUUID()}.${ext}`;
      const { error: uploadError } = await supabase.storage
        .from("stax-avatars")
        .upload(path, bytes, { contentType: mime, upsert: false, cacheControl: "3600" });
      if (uploadError) throw uploadError;
      const { data: publicData } = supabase.storage.from("stax-avatars").getPublicUrl(path);
      const avatarUrl = publicData.publicUrl;
      const { data: user, error: updateError } = await supabase
        .from("stax_accounts")
        .update({ avatar_url: avatarUrl, updated_at: new Date().toISOString() })
        .eq("id", myId)
        .select("id,user_id,display_name,bio,website,avatar_url,is_private,is_banned,is_admin,updated_at")
        .single();
      if (updateError) throw updateError;
      return json({ user, avatar_url: avatarUrl });
    }

    // Public profile by user_id (or own profile when omitted), plus privacy-aware posts.
    if (action === "profile") {
      const requestedUserId = typeof body.user_id === "string" ? body.user_id.trim() : "";
      let userQuery = supabase.from("stax_accounts")
        .select("id,user_id,display_name,bio,website,avatar_url,is_private,created_at")
        .eq("is_banned", false);
      userQuery = requestedUserId ? userQuery.eq("user_id", requestedUserId) : userQuery.eq("id", myId);
      const { data: user, error: userError } = await userQuery.maybeSingle();
      if (userError) throw userError;
      if (!user) return json({ error: "プロフィールが見つかりません。" }, 404);
      if (user.id !== myId && await blockedEitherWay(supabase, myId, user.id)) {
        return json({ error: "このプロフィールは表示できません。" }, 403);
      }

      const following_by_me = user.id === myId ? false : await isFollowing(supabase, myId, user.id);
      const followed_by_me = user.id === myId ? false : await isFollowing(supabase, user.id, myId);
      const { data: pendingRequest, error: pendingError } = user.id === myId
        ? { data: null, error: null }
        : await supabase.from("stax_follow_requests").select("id,status")
            .eq("requester_id", myId).eq("target_id", user.id).eq("status", "pending").maybeSingle();
      if (pendingError) throw pendingError;

      const { count: followersCount, error: followersError } = await supabase.from("stax_follows")
        .select("follower_id", { count: "exact", head: true }).eq("following_id", user.id);
      if (followersError) throw followersError;
      const { count: followingCount, error: followingError } = await supabase.from("stax_follows")
        .select("following_id", { count: "exact", head: true }).eq("follower_id", user.id);
      if (followingError) throw followingError;

      const privateLocked = Boolean(user.is_private && user.id !== myId && !following_by_me);
      const posts = [];
      if (!privateLocked) {
        const { data: rows, error: postsError } = await supabase.from("stax_posts")
          .select("id,author_id,content,reply_to_id,repost_of_id,quote_post_id,visibility,created_at,is_pinned")
          .eq("author_id", user.id).eq("is_deleted", false).is("reply_to_id", null)
          .order("is_pinned", { ascending: false }).order("created_at", { ascending: false }).limit(100);
        if (postsError) throw postsError;
        for (const post of rows || []) {
          if (post.visibility === "private" && user.id !== myId) continue;
          if (post.visibility === "followers" && user.id !== myId && !following_by_me) continue;
          const { count: likes, error: likesError } = await supabase.from("stax_likes")
            .select("post_id", { count: "exact", head: true }).eq("post_id", post.id);
          if (likesError) throw likesError;
          const { data: liked, error: likedError } = await supabase.from("stax_likes")
            .select("post_id").eq("post_id", post.id).eq("account_id", myId).maybeSingle();
          if (likedError) throw likedError;
          const { data: repost, error: repostError } = await supabase.from("stax_posts")
            .select("id").eq("author_id", myId).eq("repost_of_id", post.id).eq("is_deleted", false).maybeSingle();
          if (repostError) throw repostError;
          posts.push({ ...post, user_id: user.user_id, display_name: user.display_name,
            avatar_url: user.avatar_url, like_count: likes || 0,
            liked_by_me: Boolean(liked), reposted_by_me: Boolean(repost) });
        }
      }
      const postsWithCounts = await attachPostCounts(supabase, posts);
      const postsWithMedia = await attachPostMedia(supabase, postsWithCounts);
      return json({ user, posts: postsWithMedia, private_locked: privateLocked,
        following_by_me, followed_by_me, requested_by_me: Boolean(pendingRequest),
        followers_count: followersCount || 0, following_count: followingCount || 0,
        is_me: user.id === myId });
    }

    // Followers / following list for a visible profile.
    if (action === "follow_list") {
      const targetId = typeof body.account_id === "string" ? body.account_id : myId;
      const kind = body.kind === "following" ? "following" : "followers";
      if (await blockedEitherWay(supabase, myId, targetId)) return json({ error: "この一覧は表示できません。" }, 403);
      const { data: target, error: targetError } = await supabase.from("stax_accounts")
        .select("id,is_private").eq("id", targetId).eq("is_banned", false).maybeSingle();
      if (targetError) throw targetError;
      if (!target) return json({ error: "ユーザーが見つかりません。" }, 404);
      const amFollowing = targetId === myId || await isFollowing(supabase, myId, targetId);
      if (target.is_private && targetId !== myId && !amFollowing) {
        return json({ error: "鍵アカウントをフォローすると一覧を見られます。" }, 403);
      }
      const column = kind === "following" ? "follower_id" : "following_id";
      const { data: relations, error } = await supabase.from("stax_follows")
        .select("follower_id,following_id,created_at").eq(column, targetId).order("created_at", { ascending: false }).limit(100);
      if (error) throw error;
      const ids = (relations || []).map((r) => kind === "following" ? r.following_id : r.follower_id);
      const accounts = [];
      for (const id of ids) {
        if (await blockedEitherWay(supabase, myId, id)) continue;
        const { data: account, error: accountError } = await supabase.from("stax_accounts")
          .select("id,user_id,display_name,avatar_url,is_private").eq("id", id).eq("is_banned", false).maybeSingle();
        if (accountError) throw accountError;
        if (!account) continue;
        accounts.push({ ...account, following_by_me: id === myId ? false : await isFollowing(supabase, myId, id) });
      }
      return json({ accounts, kind });
    }

    // Delete own post or reply (soft-delete)
    if (action === "delete_post") {
      const postId = body.post_id;
      if (typeof postId !== "string") return json({ error: "post_id is required" }, 400);

      const { data: post, error: postError } = await supabase
        .from("stax_posts")
        .select("id,author_id,is_deleted")
        .eq("id", postId)
        .maybeSingle();
      if (postError) throw postError;
      if (!post || post.is_deleted) return json({ error: "投稿が見つかりません。" }, 404);
      if (post.author_id !== myId) return json({ error: "自分の投稿だけ削除できます。" }, 403);

      const { error } = await supabase
        .from("stax_posts")
        .update({ is_deleted: true, updated_at: new Date().toISOString() })
        .eq("id", postId)
        .eq("author_id", myId);
      if (error) throw error;
      return json({ success: true, deleted: true });
    }

    // Pin/unpin one of own posts
    if (action === "pin_post") {
      const postId = body.post_id;
      const pinned = body.pinned === true;
      if (typeof postId !== "string") return json({ error: "post_id is required" }, 400);

      const { data: post, error: postError } = await supabase
        .from("stax_posts")
        .select("id,author_id,is_deleted")
        .eq("id", postId)
        .maybeSingle();
      if (postError) throw postError;
      if (!post || post.is_deleted) return json({ error: "投稿が見つかりません。" }, 404);
      if (post.author_id !== myId) return json({ error: "自分の投稿だけピン留めできます。" }, 403);

      if (pinned) {
        const { error: unpinError } = await supabase
          .from("stax_posts")
          .update({ is_pinned: false })
          .eq("author_id", myId)
          .eq("is_pinned", true);
        if (unpinError) throw unpinError;
      }

      const { error } = await supabase
        .from("stax_posts")
        .update({ is_pinned: pinned, updated_at: new Date().toISOString() })
        .eq("id", postId)
        .eq("author_id", myId);
      if (error) throw error;
      return json({ success: true, pinned });
    }

    // Create post / reply / quote
    if (action === "create_post" || action === "reply") {
      const content = requiredText(body.text, 2000) || "";
      const images = action === "create_post" && Array.isArray(body.images) ? body.images : [];
      if (images.length > 4) return json({ error: "画像は4枚まで添付できます。" }, 400);
      if (!content && images.length === 0) return json({ error: "本文または画像を入力してください。" }, 400);
      if (images.some((item: unknown) => typeof item !== "string")) return json({ error: "画像データが不正です。" }, 400);

      const replyTo = action === "reply" ? body.post_id : body.reply_to_id;
      const quoteId = body.quote_post_id;

      if (replyTo || quoteId) {
        const targetId = replyTo || quoteId;
        const { data: target, error: targetError } = await supabase
          .from("stax_posts")
          .select("id,author_id,visibility,is_deleted")
          .eq("id", targetId)
          .eq("is_deleted", false)
          .maybeSingle();

        if (targetError) throw targetError;
        if (!target) return json({ error: "対象の投稿がありません。" }, 404);
        if (await blockedEitherWay(supabase, myId, target.author_id)) {
          return json({ error: "この投稿には操作できません。" }, 403);
        }
        if (target.visibility !== "public" &&
            target.author_id !== myId &&
            !(await isFollowing(supabase, myId, target.author_id))) {
          return json({ error: "この投稿は閲覧できません。" }, 403);
        }
      }

      const { data: post, error } = await supabase
        .from("stax_posts")
        .insert({
          author_id: myId,
          content,
          reply_to_id: replyTo || null,
          quote_post_id: quoteId || null,
          visibility: "public",
        })
        .select("*")
        .single();

      if (error) throw error;

      // Upload post images to the public Storage bucket and save their metadata.
      const uploadedPaths: string[] = [];
      try {
        const mediaRows = [];
        for (let index = 0; index < images.length; index++) {
          const dataUrl = images[index] as string;
          const match = dataUrl.match(/^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+/=]+)$/);
          if (!match) throw new Error("PNG/JPEG/WEBP/GIF画像を選択してください。");
          const mime = match[1];
          let binary: string;
          try { binary = atob(match[2]); } catch { throw new Error("画像データが不正です。"); }
          if (binary.length < 1 || binary.length > 2 * 1024 * 1024) throw new Error("画像は1枚2MB以下にしてください。");
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const ext = mime === "image/jpeg" ? "jpg" : mime.split("/")[1];
          const path = `${myId}/${post.id}/${crypto.randomUUID()}.${ext}`;
          const { error: uploadError } = await supabase.storage.from("stax-post-images")
            .upload(path, bytes, { contentType: mime, upsert: false, cacheControl: "3600" });
          if (uploadError) throw uploadError;
          uploadedPaths.push(path);
          const { data: publicData } = supabase.storage.from("stax-post-images").getPublicUrl(path);
          mediaRows.push({ post_id: post.id, media_url: publicData.publicUrl, media_type: mime, position: index });
        }
        if (mediaRows.length) {
          const { error: mediaError } = await supabase.from("stax_post_media").insert(mediaRows);
          if (mediaError) throw mediaError;
        }
      } catch (mediaError) {
        if (uploadedPaths.length) await supabase.storage.from("stax-post-images").remove(uploadedPaths);
        await supabase.from("stax_posts").update({ is_deleted: true }).eq("id", post.id).eq("author_id", myId);
        throw mediaError;
      }

      // Extract and attach hashtags.
      const tags = [...new Set(
        [...content.matchAll(/#([\p{L}\p{N}_]{1,50})/gu)]
          .map((match) => match[1].toLowerCase())
      )].slice(0, 20);

      for (const tag of tags) {
        const { data: hashtag, error: tagError } = await supabase
          .from("stax_hashtags")
          .upsert({ tag }, { onConflict: "tag" })
          .select("id")
          .single();

        if (tagError) throw tagError;

        const { error: linkError } = await supabase
          .from("stax_post_hashtags")
          .upsert(
            { post_id: post.id, hashtag_id: hashtag.id },
            { onConflict: "post_id,hashtag_id" },
          );

        if (linkError) throw linkError;
      }

      if (replyTo || quoteId) {
        const targetId = replyTo || quoteId;
        const { data: target } = await supabase
          .from("stax_posts")
          .select("author_id")
          .eq("id", targetId)
          .maybeSingle();

        if (target) {
          await notify(
            supabase,
            target.author_id,
            myId,
            replyTo ? "reply" : "mention",
            post.id,
          );
        }
      }

      return json({ post }, 201);
    }

    // Timeline
    if (action === "timeline") {
      const { data: follows, error: followError } = await supabase
        .from("stax_follows")
        .select("following_id")
        .eq("follower_id", myId);

      if (followError) throw followError;

      const authorIds = [
        myId,
        ...(follows || []).map((row) => row.following_id),
      ];

      const { data: posts, error } = await supabase
        .from("stax_posts")
        .select("id,author_id,content,reply_to_id,repost_of_id,quote_post_id,visibility,created_at,is_pinned")
        .eq("is_deleted", false)
        .is("reply_to_id", null)
        .in("author_id", authorIds)
        .order("created_at", { ascending: false })
        .limit(50);

      if (error) throw error;

      const visible = [];
      for (const timelineEntry of posts || []) {
        if (await blockedEitherWay(supabase, myId, timelineEntry.author_id)) continue;

        const { data: entryAuthor } = await supabase.from("stax_accounts")
          .select("user_id,display_name,avatar_url,is_private")
          .eq("id", timelineEntry.author_id).maybeSingle();
        if (!entryAuthor) continue;

        // Reposts appear as an attribution above the original post, like X.
        let post = timelineEntry;
        let author = entryAuthor;
        let repostedBy = null;
        if (timelineEntry.repost_of_id) {
          const { data: original, error: originalError } = await supabase.from("stax_posts")
            .select("id,author_id,content,reply_to_id,repost_of_id,quote_post_id,visibility,created_at,is_pinned,is_deleted")
            .eq("id", timelineEntry.repost_of_id).maybeSingle();
          if (originalError) throw originalError;
          if (!original || original.is_deleted) continue;
          if (await blockedEitherWay(supabase, myId, original.author_id)) continue;
          const { data: originalAuthor } = await supabase.from("stax_accounts")
            .select("user_id,display_name,avatar_url,is_private")
            .eq("id", original.author_id).maybeSingle();
          if (!originalAuthor) continue;
          if (originalAuthor.is_private && original.author_id !== myId &&
              !(await isFollowing(supabase, myId, original.author_id))) continue;
          if (original.visibility === "private" && original.author_id !== myId) continue;
          if (original.visibility === "followers" && original.author_id !== myId &&
              !(await isFollowing(supabase, myId, original.author_id))) continue;
          repostedBy = entryAuthor.display_name || entryAuthor.user_id;
          post = original;
          author = originalAuthor;
        } else {
          if (entryAuthor.is_private && post.author_id !== myId &&
              !(await isFollowing(supabase, myId, post.author_id))) continue;
          if (post.visibility === "private" && post.author_id !== myId) continue;
          if (post.visibility === "followers" && post.author_id !== myId &&
              !(await isFollowing(supabase, myId, post.author_id))) continue;
        }

        const { count: likes } = await supabase.from("stax_likes")
          .select("*", { count: "exact", head: true }).eq("post_id", post.id);
        const { data: liked } = await supabase.from("stax_likes")
          .select("post_id").eq("post_id", post.id).eq("account_id", myId).maybeSingle();
        const { data: myRepost, error: repostError } = await supabase.from("stax_posts")
          .select("id").eq("author_id", myId).eq("repost_of_id", post.id)
          .eq("is_deleted", false).maybeSingle();
        if (repostError) throw repostError;

        visible.push({ ...post, timeline_entry_id: timelineEntry.id,
          reposted_by_name: repostedBy,
          reposted_by_user_id: timelineEntry.repost_of_id ? entryAuthor.user_id : null,
          reposted_by_avatar_url: timelineEntry.repost_of_id ? entryAuthor.avatar_url : null,
          user_id: author.user_id, display_name: author.display_name,
          avatar_url: author.avatar_url, like_count: likes || 0,
          liked_by_me: Boolean(liked), reposted_by_me: Boolean(myRepost) });
      }

      const postsWithCounts = await attachPostCounts(supabase, visible);
      const postsWithMedia = await attachPostMedia(supabase, postsWithCounts);
      return json({ posts: postsWithMedia });
    }

    // List comments for a post
    if (action === "replies") {
      const postId = body.post_id;
      if (typeof postId !== "string") return json({ error: "post_id is required" }, 400);
      const { data: parent, error: parentError } = await supabase.from("stax_posts")
        .select("id,author_id,visibility,is_deleted").eq("id", postId).eq("is_deleted", false).maybeSingle();
      if (parentError) throw parentError;
      if (!parent) return json({ error: "投稿が見つかりません。" }, 404);
      if (await blockedEitherWay(supabase, myId, parent.author_id)) return json({ error: "この投稿は表示できません。" }, 403);
      if (parent.visibility !== "public" && parent.author_id !== myId && !(await isFollowing(supabase, myId, parent.author_id))) {
        return json({ error: "この投稿は閲覧できません。" }, 403);
      }
      const { data: rows, error } = await supabase.from("stax_posts")
        .select("id,author_id,content,created_at,visibility")
        .eq("reply_to_id", postId).eq("is_deleted", false)
        .order("created_at", { ascending: true }).limit(100);
      if (error) throw error;
      const replies = [];
      for (const reply of rows || []) {
        if (await blockedEitherWay(supabase, myId, reply.author_id)) continue;
        const { data: author, error: authorError } = await supabase.from("stax_accounts")
          .select("user_id,display_name").eq("id", reply.author_id).maybeSingle();
        if (authorError) throw authorError;
        if (!author) continue;
        replies.push({ ...reply, ...author });
      }
      return json({ replies });
    }

    // Like / unlike
    if (action === "like") {
      const postId = body.post_id;
      if (typeof postId !== "string") {
        return json({ error: "post_id is required" }, 400);
      }

      const { data: post, error: postError } = await supabase
        .from("stax_posts")
        .select("id,author_id,visibility,is_deleted")
        .eq("id", postId)
        .eq("is_deleted", false)
        .maybeSingle();

      if (postError) throw postError;
      if (!post) return json({ error: "投稿がありません。" }, 404);
      if (await blockedEitherWay(supabase, myId, post.author_id)) {
        return json({ error: "この投稿には操作できません。" }, 403);
      }

      const { data: existing, error: existingError } = await supabase
        .from("stax_likes")
        .select("post_id")
        .eq("post_id", postId)
        .eq("account_id", myId)
        .maybeSingle();

      if (existingError) throw existingError;

      if (existing) {
        const { error } = await supabase
          .from("stax_likes")
          .delete()
          .eq("post_id", postId)
          .eq("account_id", myId);
        if (error) throw error;
        return json({ liked: false });
      }

      const { error } = await supabase.from("stax_likes").insert({
        post_id: postId,
        account_id: myId,
      });
      if (error) throw error;

      await notify(supabase, post.author_id, myId, "like", postId);
      return json({ liked: true });
    }

    // Repost / unrepost
    if (action === "repost") {
      const postId = body.post_id;
      if (typeof postId !== "string") {
        return json({ error: "post_id is required" }, 400);
      }

      const { data: target, error: targetError } = await supabase
        .from("stax_posts")
        .select("id,author_id,is_deleted")
        .eq("id", postId)
        .eq("is_deleted", false)
        .maybeSingle();

      if (targetError) throw targetError;
      if (!target) return json({ error: "投稿がありません。" }, 404);
      if (await blockedEitherWay(supabase, myId, target.author_id)) {
        return json({ error: "この投稿には操作できません。" }, 403);
      }

      const { data: existing, error: lookupError } = await supabase
        .from("stax_posts")
        .select("id")
        .eq("author_id", myId)
        .eq("repost_of_id", postId)
        .eq("is_deleted", false)
        .maybeSingle();

      if (lookupError) throw lookupError;

      if (existing) {
        const { error } = await supabase
          .from("stax_posts")
          .update({ is_deleted: true })
          .eq("id", existing.id)
          .eq("author_id", myId);
        if (error) throw error;
        return json({ reposted: false });
      }

      const { data: repost, error } = await supabase
        .from("stax_posts")
        .insert({
          author_id: myId,
          content: "",
          repost_of_id: postId,
          visibility: "public",
        })
        .select("*")
        .single();

      if (error) throw error;
      await notify(supabase, target.author_id, myId, "repost", postId);
      return json({ reposted: true, post: repost }, 201);
    }

    // Follow / unfollow
    if (action === "follow") {
      const targetId = body.account_id;
      if (typeof targetId !== "string" || targetId === myId) {
        return json({ error: "account_id is invalid" }, 400);
      }

      if (await blockedEitherWay(supabase, myId, targetId)) {
        return json({ error: "このユーザーには操作できません。" }, 403);
      }

      const { data: target, error: targetError } = await supabase
        .from("stax_accounts")
        .select("id,is_private,is_banned")
        .eq("id", targetId)
        .maybeSingle();

      if (targetError) throw targetError;
      if (!target || target.is_banned) {
        return json({ error: "ユーザーが見つかりません。" }, 404);
      }

      const following = await isFollowing(supabase, myId, targetId);

      if (following) {
        const { error } = await supabase
          .from("stax_follows")
          .delete()
          .eq("follower_id", myId)
          .eq("following_id", targetId);
        if (error) throw error;
        return json({ following: false });
      }

      const { data: pendingRequest, error: pendingRequestError } = await supabase
        .from("stax_follow_requests").select("id")
        .eq("requester_id", myId).eq("target_id", targetId)
        .eq("status", "pending").maybeSingle();
      if (pendingRequestError) throw pendingRequestError;
      if (pendingRequest) {
        const { error: cancelError } = await supabase.from("stax_follow_requests")
          .delete().eq("id", pendingRequest.id).eq("requester_id", myId);
        if (cancelError) throw cancelError;
        return json({ requested: false, canceled_request: true });
      }

      if (target.is_private) {
        const { error } = await supabase.from("stax_follow_requests").upsert({
          requester_id: myId,
          target_id: targetId,
          status: "pending",
        }, { onConflict: "requester_id,target_id" });
        if (error) throw error;
        await notify(supabase, targetId, myId, "follow_request");
        return json({ requested: true });
      }

      const { error } = await supabase.from("stax_follows").insert({
        follower_id: myId,
        following_id: targetId,
      });
      if (error) throw error;

      await notify(supabase, targetId, myId, "follow");
      return json({ following: true });
    }

    // Incoming follow requests for private accounts
    if (action === "follow_requests") {
      const { data: requests, error } = await supabase
        .from("stax_follow_requests")
        .select("id,requester_id,target_id,status,created_at")
        .eq("target_id", myId)
        .eq("status", "pending")
        .order("created_at", { ascending: false })
        .limit(100);
      if (error) throw error;
      const result = [];
      for (const request of requests || []) {
        if (await blockedEitherWay(supabase, myId, request.requester_id)) continue;
        const { data: requester, error: requesterError } = await supabase
          .from("stax_accounts")
          .select("id,user_id,display_name,avatar_url,bio")
          .eq("id", request.requester_id)
          .eq("is_banned", false)
          .maybeSingle();
        if (requesterError) throw requesterError;
        if (requester) result.push({ ...request, requester });
      }
      return json({ requests: result });
    }

    // Accept a pending follow request addressed to the current account
    if (action === "accept_follow_request") {
      const requestId = body.request_id;
      if (typeof requestId !== "string") return json({ error: "request_id is required" }, 400);
      const { data: request, error: requestError } = await supabase
        .from("stax_follow_requests")
        .select("id,requester_id,target_id,status")
        .eq("id", requestId)
        .eq("target_id", myId)
        .eq("status", "pending")
        .maybeSingle();
      if (requestError) throw requestError;
      if (!request) return json({ error: "有効なフォロー申請が見つかりません。" }, 404);
      if (await blockedEitherWay(supabase, myId, request.requester_id)) {
        return json({ error: "このユーザーの申請は承認できません。" }, 403);
      }
      const { error: followError } = await supabase.from("stax_follows").upsert({
        follower_id: request.requester_id, following_id: myId,
      }, { onConflict: "follower_id,following_id" });
      if (followError) throw followError;
      const { error: updateError } = await supabase
        .from("stax_follow_requests")
        .update({ status: "accepted" })
        .eq("id", requestId)
        .eq("target_id", myId);
      if (updateError) throw updateError;
      await notify(supabase, request.requester_id, myId, "follow_accepted");
      return json({ success: true, accepted: true, account_id: request.requester_id });
    }

    // Reject a pending follow request
    if (action === "reject_follow_request") {
      const requestId = body.request_id;
      if (typeof requestId !== "string") return json({ error: "request_id is required" }, 400);
      const { data: request, error: requestError } = await supabase
        .from("stax_follow_requests")
        .select("id")
        .eq("id", requestId)
        .eq("target_id", myId)
        .eq("status", "pending")
        .maybeSingle();
      if (requestError) throw requestError;
      if (!request) return json({ error: "有効なフォロー申請が見つかりません。" }, 404);
      const { error } = await supabase.from("stax_follow_requests")
        .update({ status: "rejected" }).eq("id", requestId).eq("target_id", myId);
      if (error) throw error;
      return json({ success: true, rejected: true });
    }

    // Search accounts / posts / hashtags
    if (action === "search") {
      const query = requiredText(body.query, 100);
      if (!query) return json({ accounts: [], posts: [], hashtags: [] });

      const safeQuery = query.replace(/[%_\\]/g, "\\$&");
      const { data: accountsById, error: accountIdError } = await supabase
        .from("stax_accounts")
        .select("id,user_id,display_name,avatar_url,bio,is_private")
        .ilike("user_id", `%${safeQuery}%`)
        .eq("is_banned", false)
        .limit(20);
      if (accountIdError) throw accountIdError;
      const { data: accountsByName, error: accountNameError } = await supabase
        .from("stax_accounts")
        .select("id,user_id,display_name,avatar_url,bio,is_private")
        .ilike("display_name", `%${safeQuery}%`)
        .eq("is_banned", false)
        .limit(20);
      if (accountNameError) throw accountNameError;
      const accounts = [...new Map([...(accountsById || []), ...(accountsByName || [])]
        .map((account) => [account.id, account])).values()];

      const { data: posts, error: postError } = await supabase
        .from("stax_posts")
        .select("id,author_id,content,reply_to_id,repost_of_id,quote_post_id,visibility,created_at,is_pinned")
        .eq("is_deleted", false)
        .is("reply_to_id", null)
        .ilike("content", `%${safeQuery}%`)
        .order("created_at", { ascending: false })
        .limit(30);

      if (postError) throw postError;

      const visiblePosts = [];
      for (const post of posts || []) {
        if (await blockedEitherWay(supabase, myId, post.author_id)) continue;

        const { data: author } = await supabase
          .from("stax_accounts")
          .select("user_id,display_name,is_private")
          .eq("id", post.author_id)
          .maybeSingle();

        if (!author) continue;
        if (author.is_private && post.author_id !== myId &&
            !(await isFollowing(supabase, myId, post.author_id))) continue;
        if (post.visibility === "private" && post.author_id !== myId) continue;
        if (post.visibility === "followers" && post.author_id !== myId &&
            !(await isFollowing(supabase, myId, post.author_id))) continue;

        const { count: likeCount, error: likeCountError } = await supabase
          .from("stax_likes")
          .select("post_id", { count: "exact", head: true })
          .eq("post_id", post.id);
        if (likeCountError) throw likeCountError;

        const { data: liked, error: likedError } = await supabase
          .from("stax_likes")
          .select("post_id")
          .eq("post_id", post.id)
          .eq("account_id", myId)
          .maybeSingle();
        if (likedError) throw likedError;

        const { data: myRepost, error: repostError } = await supabase
          .from("stax_posts")
          .select("id")
          .eq("author_id", myId)
          .eq("repost_of_id", post.id)
          .eq("is_deleted", false)
          .maybeSingle();
        if (repostError) throw repostError;

        visiblePosts.push({
          ...post,
          user_id: author.user_id,
          display_name: author.display_name,
          like_count: likeCount || 0,
          liked_by_me: Boolean(liked),
          reposted_by_me: Boolean(myRepost),
        });
      }

      const tag = query.replace(/^#/, "").toLowerCase();
      const { data: hashtags, error: tagError } = await supabase
        .from("stax_hashtags")
        .select("id,tag")
        .ilike("tag", `%${safeQuery.replace(/^#/, "")}%`)
        .limit(20);

      if (tagError) throw tagError;

      // If searching a hashtag, include posts linked to that hashtag even when
      // punctuation/spacing means a plain content search would miss them.
      if (query.startsWith("#")) {
        const exactTag = query.slice(1).toLowerCase();
        const { data: exactHashtag, error: exactTagError } = await supabase
          .from("stax_hashtags").select("id,tag").eq("tag", exactTag).maybeSingle();
        if (exactTagError) throw exactTagError;
        if (exactHashtag) {
          const { data: links, error: linksError } = await supabase
            .from("stax_post_hashtags").select("post_id")
            .eq("hashtag_id", exactHashtag.id).limit(100);
          if (linksError) throw linksError;
          const ids = (links || []).map((link) => link.post_id);
          if (ids.length) {
            const { data: taggedPosts, error: taggedError } = await supabase
              .from("stax_posts")
              .select("id,author_id,content,reply_to_id,repost_of_id,quote_post_id,visibility,created_at,is_pinned")
              .in("id", ids).eq("is_deleted", false)
              .order("created_at", { ascending: false }).limit(50);
            if (taggedError) throw taggedError;
            for (const post of taggedPosts || []) {
              if (visiblePosts.some((item) => item.id === post.id)) continue;
              if (await blockedEitherWay(supabase, myId, post.author_id)) continue;
              const { data: author } = await supabase.from("stax_accounts")
                .select("user_id,display_name,is_private")
                .eq("id", post.author_id).maybeSingle();
              if (!author) continue;
              if (author.is_private && post.author_id !== myId && !(await isFollowing(supabase, myId, post.author_id))) continue;
              if (post.visibility === "private" && post.author_id !== myId) continue;
              if (post.visibility === "followers" && post.author_id !== myId && !(await isFollowing(supabase, myId, post.author_id))) continue;
              visiblePosts.push({ ...post, user_id: author.user_id, display_name: author.display_name });
            }
          }
        }
      }

      const searchAccounts = [];
      for (const account of accounts) {
        if (account.id !== myId && await blockedEitherWay(supabase, myId, account.id)) continue;
        const following_by_me = account.id === myId ? false : await isFollowing(supabase, myId, account.id);
        const { data: request, error: requestError } = account.id === myId
          ? { data: null, error: null }
          : await supabase.from("stax_follow_requests")
              .select("id,status")
              .eq("requester_id", myId)
              .eq("target_id", account.id)
              .eq("status", "pending")
              .maybeSingle();
        if (requestError) throw requestError;
        searchAccounts.push({
          ...account,
          following_by_me,
          requested_by_me: Boolean(request),
        });
      }

      return json({
        accounts: searchAccounts,
        posts: visiblePosts,
        hashtags: hashtags || [],
      });
    }

    // Notifications
    if (action === "notifications") {
      const { data, error } = await supabase
        .from("stax_notifications")
        .select("id,actor_id,notification_type,post_id,is_read,created_at")
        .eq("recipient_id", myId)
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;

      const notifications = [];
      for (const item of data || []) {
        if (item.actor_id && await blockedEitherWay(supabase, myId, item.actor_id)) continue;
        let actor = null;
        if (item.actor_id) {
          const { data: account, error: actorError } = await supabase.from("stax_accounts")
            .select("id,user_id,display_name,avatar_url")
            .eq("id", item.actor_id).maybeSingle();
          if (actorError) throw actorError;
          actor = account;
        }
        notifications.push({ ...item, actor });
      }

      return json({ notifications });
    }

    if (action === "read_notifications") {
      const { error } = await supabase
        .from("stax_notifications")
        .update({ is_read: true })
        .eq("recipient_id", myId)
        .eq("is_read", false);

      if (error) throw error;
      return json({ success: true });
    }

    // Users who can receive a direct message: mutual follows, excluding blocked accounts.
    if (action === "dm_candidates") {
      const { data: followingRows, error: followingError } = await supabase
        .from("stax_follows")
        .select("following_id")
        .eq("follower_id", myId);
      if (followingError) throw followingError;

      const accounts = [];
      const seen = new Set<string>();
      for (const row of followingRows || []) {
        const targetId = row.following_id;
        if (!targetId || targetId === myId || seen.has(targetId)) continue;
        seen.add(targetId);
        if (!await isFollowing(supabase, targetId, myId)) continue;
        if (await blockedEitherWay(supabase, myId, targetId)) continue;

        const { data: account, error: accountError } = await supabase
          .from("stax_accounts")
          .select("id,user_id,display_name,avatar_url,is_private")
          .eq("id", targetId)
          .eq("is_banned", false)
          .maybeSingle();
        if (accountError) throw accountError;
        if (account) accounts.push(account);
      }
      accounts.sort((a, b) =>
        (a.display_name || a.user_id).localeCompare(b.display_name || b.user_id, "ja")
      );
      return json({ accounts });
    }

    // Direct-message conversations list
    if (action === "messages" || action === "conversations") {
      const { data: memberships, error: memberError } = await supabase
        .from("stax_conversation_members")
        .select("conversation_id,last_read_at,is_muted")
        .eq("account_id", myId);

      if (memberError) throw memberError;

      const conversations = [];
      for (const member of memberships || []) {
        const { data: conversation, error } = await supabase
          .from("stax_conversations")
          .select("id,conversation_type,title,owner_id,created_at,updated_at")
          .eq("id", member.conversation_id)
          .maybeSingle();

        if (error) throw error;
        if (!conversation) continue;

        const { data: members } = await supabase
          .from("stax_conversation_members")
          .select("account_id")
          .eq("conversation_id", conversation.id);

        const memberIds = (members || []).map((m) => m.account_id);
        let hasBlockedMember = false;
        for (const id of memberIds) {
          if (id !== myId && await blockedEitherWay(supabase, myId, id)) {
            hasBlockedMember = true;
            break;
          }
        }
        if (hasBlockedMember) continue;
        if (conversation.conversation_type === "direct") {
          const otherId = memberIds.find((id) => id !== myId);
          if (!otherId || !await isMutualFollowing(supabase, myId, otherId)) continue;
        }

        const participantAccounts = [];
        for (const accountId of memberIds) {
          const { data: account, error: accountError } = await supabase
            .from("stax_accounts")
            .select("id,user_id,display_name,avatar_url")
            .eq("id", accountId)
            .maybeSingle();
          if (accountError) throw accountError;
          if (account) participantAccounts.push(account);
        }
        const otherAccounts = participantAccounts.filter((account) => account.id !== myId);
        const displayTitle = conversation.conversation_type === "direct"
          ? (otherAccounts[0]?.display_name || otherAccounts[0]?.user_id || "ユーザー不明")
          : (conversation.title || "グループ");

        conversations.push({
          ...conversation,
          display_title: displayTitle,
          participants: participantAccounts,
          last_read_at: member.last_read_at,
          is_muted: member.is_muted,
        });
      }

      return json({ conversations });
    }

    // Create direct conversation
    if (action === "create_dm") {
      const targetId = body.account_id;
      if (typeof targetId !== "string" || targetId === myId) {
        return json({ error: "account_id is invalid" }, 400);
      }

      if (await blockedEitherWay(supabase, myId, targetId)) {
        return json({ error: "このユーザーにはDMを送れません。" }, 403);
      }

      const { data: target, error: targetError } = await supabase
        .from("stax_accounts")
        .select("id,is_private,is_banned")
        .eq("id", targetId)
        .maybeSingle();

      if (targetError) throw targetError;
      if (!target || target.is_banned) {
        return json({ error: "ユーザーが見つかりません。" }, 404);
      }

      if (!await isMutualFollowing(supabase, myId, targetId)) {
        return json({ error: "DMは相互フォロー中のユーザーとのみ利用できます。" }, 403);
      }

      const { data: existingMemberships, error: membershipError } =
        await supabase
          .from("stax_conversation_members")
          .select("conversation_id")
          .eq("account_id", myId);

      if (membershipError) throw membershipError;

      for (const member of existingMemberships || []) {
        const { data: conversation } = await supabase
          .from("stax_conversations")
          .select("id,conversation_type")
          .eq("id", member.conversation_id)
          .eq("conversation_type", "direct")
          .maybeSingle();

        if (!conversation) continue;

        const { data: otherMembers } = await supabase
          .from("stax_conversation_members")
          .select("account_id")
          .eq("conversation_id", conversation.id);

        const ids = (otherMembers || []).map((m) => m.account_id).sort();
        if (ids.length === 2 && ids.includes(targetId) && ids.includes(myId)) {
          return json({ conversation });
        }
      }

      const { data: conversation, error: createError } = await supabase
        .from("stax_conversations")
        .insert({ conversation_type: "direct", owner_id: myId })
        .select("*")
        .single();

      if (createError) throw createError;

      const { error: addMembersError } = await supabase
        .from("stax_conversation_members")
        .insert([
          { conversation_id: conversation.id, account_id: myId },
          { conversation_id: conversation.id, account_id: targetId },
        ]);

      if (addMembersError) throw addMembersError;
      return json({ conversation }, 201);
    }

    // Create group
    if (action === "create_group") {
      const title = requiredText(body.title, 80);
      const rawMembers = Array.isArray(body.member_ids) ? body.member_ids : [];
      const memberIds = [...new Set([myId, ...rawMembers])]
        .filter((id) => typeof id === "string")
        .slice(0, 51);

      if (!title) return json({ error: "グループ名を入力してください。" }, 400);
      if (memberIds.length < 2) {
        return json({ error: "自分以外のメンバーを指定してください。" }, 400);
      }

      for (const memberId of memberIds) {
        if (memberId !== myId &&
            await blockedEitherWay(supabase, myId, memberId)) {
          return json({ error: "追加できないメンバーが含まれています。" }, 403);
        }
      }

      const { data: conversation, error } = await supabase
        .from("stax_conversations")
        .insert({
          conversation_type: "group",
          title,
          owner_id: myId,
        })
        .select("*")
        .single();

      if (error) throw error;

      const { error: membersError } = await supabase
        .from("stax_conversation_members")
        .insert(memberIds.map((account_id) => ({
          conversation_id: conversation.id,
          account_id,
        })));

      if (membersError) throw membersError;
      return json({ conversation }, 201);
    }

    // Read messages in a conversation
    if (action === "get_messages") {
      const conversationId = body.conversation_id;
      if (typeof conversationId !== "string") {
        return json({ error: "conversation_id is required" }, 400);
      }

      if (!await isConversationMember(supabase, conversationId, myId)) {
        return json({ error: "この会話にはアクセスできません。" }, 403);
      }

      const { data: members } = await supabase
        .from("stax_conversation_members")
        .select("account_id")
        .eq("conversation_id", conversationId);

      const { data: conversationInfo, error: conversationInfoError } = await supabase
        .from("stax_conversations")
        .select("id,conversation_type")
        .eq("id", conversationId)
        .maybeSingle();
      if (conversationInfoError) throw conversationInfoError;
      if (!conversationInfo) return json({ error: "会話が見つかりません。" }, 404);
      if (conversationInfo.conversation_type === "direct") {
        const otherId = (members || []).map((m) => m.account_id).find((id) => id !== myId);
        if (!otherId || !await isMutualFollowing(supabase, myId, otherId)) {
          return json({ error: "DMは相互フォロー中のみ利用できます。" }, 403);
        }
      }

      for (const member of members || []) {
        if (member.account_id !== myId &&
            await blockedEitherWay(supabase, myId, member.account_id)) {
          return json({ error: "この会話は利用できません。" }, 403);
        }
      }

      const { data: messages, error } = await supabase
        .from("stax_messages")
        .select("id,conversation_id,sender_id,content,attachment_url,created_at")
        .eq("conversation_id", conversationId)
        .eq("is_deleted", false)
        .order("created_at", { ascending: true })
        .limit(200);

      if (error) throw error;

      const { error: readError } = await supabase
        .from("stax_conversation_members")
        .update({ last_read_at: new Date().toISOString() })
        .eq("conversation_id", conversationId)
        .eq("account_id", myId);

      if (readError) throw readError;

      const senderIds = [...new Set((messages || []).map((message) => message.sender_id).filter(Boolean))];
      const senderAccounts = new Map();
      for (const senderId of senderIds) {
        const { data: account, error: accountError } = await supabase
          .from("stax_accounts")
          .select("id,user_id,display_name,avatar_url")
          .eq("id", senderId)
          .maybeSingle();
        if (accountError) throw accountError;
        if (account) senderAccounts.set(senderId, account);
      }
      const messagesWithSender = (messages || []).map((message) => {
        const sender = senderAccounts.get(message.sender_id);
        return {
          ...message,
          sender_user_id: sender?.user_id || "unknown",
          sender_display_name: sender?.display_name || sender?.user_id || "不明なユーザー",
          sender_avatar_url: sender?.avatar_url || null,
        };
      });
      return json({ messages: messagesWithSender });
    }

    // Send message
    if (action === "send_message") {
      const conversationId = body.conversation_id;
      const content = requiredText(body.text, 10000);
      const attachmentUrl = requiredText(body.attachment_url, 2048);

      if (typeof conversationId !== "string" || (!content && !attachmentUrl)) {
        return json({ error: "会話とメッセージ内容を指定してください。" }, 400);
      }

      if (!await isConversationMember(supabase, conversationId, myId)) {
        return json({ error: "この会話にはアクセスできません。" }, 403);
      }

      const { data: members } = await supabase
        .from("stax_conversation_members")
        .select("account_id")
        .eq("conversation_id", conversationId);

      const { data: conversationInfo, error: conversationInfoError } = await supabase
        .from("stax_conversations")
        .select("id,conversation_type")
        .eq("id", conversationId)
        .maybeSingle();
      if (conversationInfoError) throw conversationInfoError;
      if (!conversationInfo) return json({ error: "会話が見つかりません。" }, 404);
      if (conversationInfo.conversation_type === "direct") {
        const otherId = (members || []).map((m) => m.account_id).find((id) => id !== myId);
        if (!otherId || !await isMutualFollowing(supabase, myId, otherId)) {
          return json({ error: "DMは相互フォロー中のみ利用できます。" }, 403);
        }
      }

      for (const member of members || []) {
        if (member.account_id !== myId &&
            await blockedEitherWay(supabase, myId, member.account_id)) {
          return json({ error: "この会話は利用できません。" }, 403);
        }
      }

      const { data: message, error } = await supabase
        .from("stax_messages")
        .insert({
          conversation_id: conversationId,
          sender_id: myId,
          content: content || "",
          attachment_url: attachmentUrl || null,
        })
        .select("*")
        .single();

      if (error) throw error;

      for (const member of members || []) {
        if (member.account_id !== myId) {
          await notify(supabase, member.account_id, myId, "message");
        }
      }

      await supabase
        .from("stax_conversations")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", conversationId);

      return json({ message }, 201);
    }

    // Block
    if (action === "block") {
      const targetId = body.account_id;
      if (typeof targetId !== "string" || targetId === myId) {
        return json({ error: "account_id is invalid" }, 400);
      }

      const { error } = await supabase.from("stax_blocks").upsert({
        blocker_id: myId,
        blocked_id: targetId,
      }, { onConflict: "blocker_id,blocked_id" });

      if (error) throw error;

      await supabase.from("stax_follows").delete()
        .eq("follower_id", myId).eq("following_id", targetId);
      await supabase.from("stax_follows").delete()
        .eq("follower_id", targetId).eq("following_id", myId);

      return json({ blocked: true });
    }

    // Unblock
    if (action === "unblock") {
      const targetId = body.account_id;
      if (typeof targetId !== "string") {
        return json({ error: "account_id is required" }, 400);
      }

      const { error } = await supabase
        .from("stax_blocks")
        .delete()
        .eq("blocker_id", myId)
        .eq("blocked_id", targetId);

      if (error) throw error;
      return json({ blocked: false });
    }

    // Report account or post
    if (action === "report") {
      const reason = requiredText(body.reason, 200);
      const details = typeof body.details === "string"
        ? body.details.trim().slice(0, 2000)
        : "";

      if (!reason) return json({ error: "通報理由を入力してください。" }, 400);

      const accountId = typeof body.account_id === "string"
        ? body.account_id
        : null;
      const postId = typeof body.post_id === "string"
        ? body.post_id
        : null;

      if (!accountId && !postId) {
        return json({ error: "通報対象を指定してください。" }, 400);
      }

      if (accountId === myId) {
        return json({ error: "自分自身は通報できません。" }, 400);
      }

      if (postId) {
        const { data: post, error } = await supabase
          .from("stax_posts")
          .select("id")
          .eq("id", postId)
          .maybeSingle();

        if (error) throw error;
        if (!post) return json({ error: "投稿が見つかりません。" }, 404);
      }

      const { data: report, error } = await supabase
        .from("stax_reports")
        .insert({
          reporter_id: myId,
          reported_account_id: accountId,
          reported_post_id: postId,
          reason,
          details,
        })
        .select("id,status,created_at")
        .single();

      if (error) throw error;
      return json({ report }, 201);
    }

    // Admin report queue
    if (action === "admin_reports") {
      if (!me.is_admin) return json({ error: "管理者権限が必要です。" }, 403);

      const { data, error } = await supabase
        .from("stax_report_details")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) throw error;
      return json({ reports: data || [] });
    }

    // Admin account ban / unban
    if (action === "admin_ban") {
      if (!me.is_admin) return json({ error: "管理者権限が必要です。" }, 403);

      const targetId = body.account_id;
      const banned = body.banned === true;
      const reason = typeof body.reason === "string"
        ? body.reason.trim().slice(0, 500)
        : "";

      if (typeof targetId !== "string" || targetId === myId) {
        return json({ error: "対象アカウントが不正です。" }, 400);
      }

      const { data: target, error: targetError } = await supabase
        .from("stax_accounts")
        .select("id")
        .eq("id", targetId)
        .maybeSingle();

      if (targetError) throw targetError;
      if (!target) return json({ error: "ユーザーが見つかりません。" }, 404);

      const { error } = await supabase
        .from("stax_accounts")
        .update({
          is_banned: banned,
          ban_reason: banned ? reason : null,
        })
        .eq("id", targetId);

      if (error) throw error;

      const { error: logError } = await supabase
        .from("stax_admin_logs")
        .insert({
          admin_id: myId,
          action: banned ? "ban_account" : "unban_account",
          target_account_id: targetId,
          details: { reason },
        });

      if (logError) throw logError;

      if (banned) {
        const { error: sessionError } = await supabase
          .from("stax_sessions")
          .delete()
          .eq("account_id", targetId);
        if (sessionError) throw sessionError;
      }

      return json({ success: true, banned });
    }

    return json({ error: "Unknown action", action }, 400);
  } catch (error) {
    console.error("stax-api error:", error);
    const message = error instanceof Error ? error.message : String(error);
    return json({ error: message || "サーバー処理に失敗しました。" }, 500);
  }
});
