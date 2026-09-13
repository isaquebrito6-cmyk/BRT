import { getSession, json } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  const db = env.DB;
  const [colaboradoresRes, docTypesRes, configRes, historicoRes] = await Promise.all([
    db.prepare('SELECT id, nome, notas, docs FROM colaboradores ORDER BY ordem ASC, nome ASC').all(),
    db.prepare('SELECT sigla, nome, descricao, cor, ordem FROM doc_types ORDER BY ordem ASC').all(),
    db.prepare('SELECT chave, valor FROM config').all(),
    db.prepare('SELECT ts, username, acao FROM historico ORDER BY ts DESC LIMIT 300').all(),
  ]);

  const colaboradores = colaboradoresRes.results.map(c => ({
    id: c.id, nome: c.nome, notas: JSON.parse(c.notas), docs: JSON.parse(c.docs),
  }));
  const config = {};
  configRes.results.forEach(r => { config[r.chave] = r.valor; });

  return json({
    colaboradores,
    docTypes: docTypesRes.results,
    config,
    historico: historicoRes.results,
    role: session.role,
    username: session.username,
  });
}
