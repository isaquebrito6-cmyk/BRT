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
  const nome = String(body.nome || '').trim();
  if (!nome) return json({ error: 'nome_obrigatorio' }, 400);
  const notas = Array.isArray(body.notas) ? body.notas : [];
  const docs = body.docs && typeof body.docs === 'object' ? body.docs : {};

  const db = env.DB;
  let id = body.id;
  const isNew = !id;

  if (isNew) {
    id = 'e_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
    const { results } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM colaboradores').all();
    const max = results[0].max;
    await db.prepare('INSERT INTO colaboradores (id, nome, notas, docs, ordem) VALUES (?, ?, ?, ?, ?)')
      .bind(id, nome, JSON.stringify(notas), JSON.stringify(docs), max + 1).run();
  } else {
    const { results } = await db.prepare('SELECT id FROM colaboradores WHERE id = ?').bind(id).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE colaboradores SET nome = ?, notas = ?, docs = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .bind(nome, JSON.stringify(notas), JSON.stringify(docs), id).run();
  }

  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, (isNew ? 'Criou' : 'Editou') + ` colaborador "${nome}"`).run();

  return json({ ok: true, id });
}

export async function onRequestDelete({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return json({ error: 'id_obrigatorio' }, 400);

  const db = env.DB;
  const { results } = await db.prepare('SELECT nome FROM colaboradores WHERE id = ?').bind(id).all();
  if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
  const nome = results[0].nome;

  await db.prepare('DELETE FROM colaboradores WHERE id = ?').bind(id).run();
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Excluiu colaborador "${nome}"`).run();

  return json({ ok: true });
}
