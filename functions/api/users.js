import { getSession, hashPassword, json } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);

  const { results } = await env.DB.prepare('SELECT username, role, created_at FROM users ORDER BY created_at ASC').all();
  return json({ users: results });
}

export async function onRequestPost({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_body' }, 400);
  }
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  const role = body.role === 'admin' ? 'admin' : 'editor';
  if (!username || password.length < 6) return json({ error: 'dados_invalidos' }, 400);

  const db = env.DB;
  const { results: existing } = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).all();
  if (existing.length > 0) return json({ error: 'ja_existe' }, 409);

  const { hash, salt } = await hashPassword(password);
  await db.prepare('INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, ?)')
    .bind(username, hash, salt, role).run();
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Adicionou o usuário "${username}" (${role})`).run();

  return json({ ok: true });
}

export async function onRequestDelete({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);

  const url = new URL(request.url);
  const username = url.searchParams.get('username');
  if (!username) return json({ error: 'username_obrigatorio' }, 400);
  if (username === session.username) return json({ error: 'nao_pode_excluir_a_si_mesmo' }, 400);

  const db = env.DB;
  const { results: adminCountRes } = await db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").all();
  const { results: targetRes } = await db.prepare('SELECT role FROM users WHERE username = ?').bind(username).all();
  if (targetRes.length === 0) return json({ error: 'nao_encontrado' }, 404);
  if (targetRes[0].role === 'admin' && adminCountRes[0].count <= 1) {
    return json({ error: 'nao_pode_remover_ultimo_admin' }, 400);
  }

  await db.prepare('DELETE FROM users WHERE username = ?').bind(username).run();
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Removeu o usuário "${username}"`).run();

  return json({ ok: true });
}
