import { getSession, json } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_body' }, 400);
  }
  const chave = String(body.chave || '').trim();
  const valor = String(body.valor ?? '');
  if (!chave) return json({ error: 'chave_obrigatoria' }, 400);

  const db = env.DB;
  await db.prepare('INSERT INTO config (chave, valor) VALUES (?, ?) ON CONFLICT (chave) DO UPDATE SET valor = excluded.valor')
    .bind(chave, valor).run();
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Alterou configuração "${chave}" para "${valor}"`).run();

  return json({ ok: true });
}
