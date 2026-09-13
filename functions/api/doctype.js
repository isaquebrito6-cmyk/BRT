import { getSession, json } from '../_lib/auth.js';

const PALETA = ['#f2b705', '#3fae5c', '#f2954a', '#e05a8a', '#8a6de0', '#4fa3e3', '#c94f4f', '#4fc9a8', '#c9a24f', '#7a8fd6'];

export async function onRequestPost({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_body' }, 400);
  }
  const sigla = String(body.sigla || '').trim().toUpperCase().replace(/\s+/g, ' ');
  const nome = String(body.nome || '').trim();
  if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);
  if (!nome) return json({ error: 'nome_obrigatorio' }, 400);

  const db = env.DB;
  const { results: existing } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ?').bind(sigla).all();
  if (existing.length > 0) return json({ error: 'ja_existe' }, 409);

  const { results: maxRes } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM doc_types').all();
  const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM doc_types').all();
  const cor = PALETA[countRes[0].count % PALETA.length];

  await db.prepare('INSERT INTO doc_types (sigla, nome, descricao, cor, ordem) VALUES (?, ?, ?, ?, ?)')
    .bind(sigla, nome, nome, cor, maxRes[0].max + 1).run();
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Incluiu tipo de documento "${sigla}" (${nome})`).run();

  return json({ ok: true, sigla, cor });
}

export async function onRequestDelete({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  const url = new URL(request.url);
  const sigla = url.searchParams.get('sigla');
  if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);

  const db = env.DB;
  const { results } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ?').bind(sigla).all();
  if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);

  await db.prepare('DELETE FROM doc_types WHERE sigla = ?').bind(sigla).run();

  // Remove essa chave do JSON "docs" de todo mundo (SQLite não tem operador nativo tipo o "-" do Postgres para JSONB,
  // então lemos, removemos a chave em JS e regravamos).
  const { results: colaboradores } = await db.prepare('SELECT id, docs FROM colaboradores').all();
  const stmts = colaboradores.map(c => {
    const docs = JSON.parse(c.docs);
    delete docs[sigla];
    return db.prepare('UPDATE colaboradores SET docs = ? WHERE id = ?').bind(JSON.stringify(docs), c.id);
  });
  if (stmts.length > 0) await db.batch(stmts);

  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
    .bind(session.username, `Excluiu tipo de documento "${sigla}"`).run();

  return json({ ok: true });
}
