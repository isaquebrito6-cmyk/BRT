import { hashPassword, verifyPassword, makeSessionToken, getSession, json, generateRecoveryCode } from './lib/auth.js';

const PALETA = ['#f2b705', '#3fae5c', '#f2954a', '#e05a8a', '#8a6de0', '#4fa3e3', '#c94f4f', '#4fc9a8', '#c9a24f', '#7a8fd6'];

const MAX_TENTATIVAS = 5;
const BLOQUEIO_MINUTOS = 15;

function clienteInfo(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'desconhecido';
  const ua = request.headers.get('User-Agent') || 'desconhecido';
  return { ip, ua };
}

async function regHist(db, request, username, acao, tipo = 'dados') {
  const { ip, ua } = clienteInfo(request);
  await db.prepare('INSERT INTO historico (username, acao, tipo, ip, user_agent) VALUES (?, ?, ?, ?, ?)')
    .bind(username, acao, tipo, ip, ua).run();
}

async function handleLogin(request, env) {
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  const secret = env.SESSION_SECRET;
  if (!secret) return json({ error: 'server_not_configured' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }

  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || !password) return json({ error: 'missing_credentials' }, 400);

  const db = env.DB;
  const { results: countRows } = await db.prepare('SELECT COUNT(*) AS count FROM users').all();
  const count = countRows[0].count;

  if (count === 0) {
    if (password.length < 8) return json({ error: 'password_too_short' }, 400);
    const { hash, salt } = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();
    const { hash: recoveryHash, salt: recoverySalt } = await hashPassword(recoveryCode);
    await db.prepare('INSERT INTO users (username, password_hash, password_salt, role, recovery_hash, recovery_salt) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(username, hash, salt, 'admin', recoveryHash, recoverySalt).run();
    await regHist(db, request, username, 'Criou a conta de administrador (primeiro acesso)', 'seguranca');
    const token = await makeSessionToken({ username, role: 'admin' }, secret);
    return json({ token, username, role: 'admin', bootstrap: true, recoveryCode });
  }

  const { results } = await db.prepare('SELECT username, password_hash, password_salt, role, failed_attempts, locked_until FROM users WHERE username = ?')
    .bind(username).all();
  const user = results[0];

  if (user && user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
    const minutosRestantes = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
    return json({ error: 'conta_bloqueada', minutos: minutosRestantes }, 423);
  }

  if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
    if (user) {
      const tentativas = user.failed_attempts + 1;
      if (tentativas >= MAX_TENTATIVAS) {
        const bloqueadoAte = new Date(Date.now() + BLOQUEIO_MINUTOS * 60000).toISOString();
        await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE username = ?').bind(bloqueadoAte, username).run();
        await regHist(db, request, username, `Conta bloqueada por ${BLOQUEIO_MINUTOS} minutos após ${MAX_TENTATIVAS} tentativas de login erradas`, 'seguranca');
      } else {
        await db.prepare('UPDATE users SET failed_attempts = ? WHERE username = ?').bind(tentativas, username).run();
        await regHist(db, request, username, 'Tentativa de login falhou (senha incorreta)', 'seguranca');
      }
    }
    return json({ error: 'invalid_credentials' }, 401);
  }

  await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?').bind(username).run();
  const token = await makeSessionToken(user, secret);
  await regHist(db, request, username, 'Entrou no sistema', 'seguranca');
  return json({ token, username: user.username, role: user.role });
}

async function handleData(request, env) {
  if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);

  const db = env.DB;
  const [colaboradoresRes, docTypesRes, configRes, historicoRes] = await Promise.all([
    db.prepare('SELECT id, nome, notas, docs FROM colaboradores WHERE deletado_em IS NULL ORDER BY ordem ASC, nome ASC').all(),
    db.prepare('SELECT sigla, nome, descricao, cor, ordem FROM doc_types ORDER BY ordem ASC').all(),
    db.prepare('SELECT chave, valor FROM config').all(),
    db.prepare('SELECT id, ts, username, acao, tipo, ip, user_agent FROM historico WHERE deletado_em IS NULL ORDER BY ts DESC LIMIT 500').all(),
  ]);
  const colaboradores = colaboradoresRes.results.map(c => ({ id: c.id, nome: c.nome, notas: JSON.parse(c.notas), docs: JSON.parse(c.docs) }));
  const config = {};
  configRes.results.forEach(r => { config[r.chave] = r.valor; });
  return json({ colaboradores, docTypes: docTypesRes.results, config, historico: historicoRes.results, role: session.role, username: session.username });
}

const DIAS_RETENCAO_LIXEIRA = 30;

function dataLimiteRetencao() {
  return new Date(Date.now() - DIAS_RETENCAO_LIXEIRA * 24 * 60 * 60 * 1000).toISOString();
}

async function purgarLixeiraAntiga(db) {
  const limite = dataLimiteRetencao();
  await db.prepare('DELETE FROM colaboradores WHERE deletado_em IS NOT NULL AND deletado_em < ?').bind(limite).run();
  await db.prepare('DELETE FROM historico WHERE deletado_em IS NOT NULL AND deletado_em < ?').bind(limite).run();
}

async function handleColaborador(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;

  if (request.method === 'GET') {
    // Lista a lixeira de colaboradores (e aproveita pra apagar de vez o que passou do prazo de retenção).
    await purgarLixeiraAntiga(db);
    const { results } = await db.prepare("SELECT id, nome, docs, deletado_em FROM colaboradores WHERE deletado_em IS NOT NULL ORDER BY deletado_em DESC").all();
    return json({ lixeira: results.map(c => ({ id: c.id, nome: c.nome, docs: JSON.parse(c.docs), deletado_em: c.deletado_em })), diasRetencao: DIAS_RETENCAO_LIXEIRA });
  }

  if (request.method === 'PUT') {
    // Restaura um colaborador da lixeira.
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const id = String(body.id || '');
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT nome FROM colaboradores WHERE id = ? AND deletado_em IS NOT NULL').bind(id).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE colaboradores SET deletado_em = NULL WHERE id = ?').bind(id).run();
    await regHist(db, request, session.username, `Restaurou colaborador "${results[0].nome}" da lixeira`, 'dados');
    return json({ ok: true });
  }

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const nome = String(body.nome || '').trim();
    if (!nome) return json({ error: 'nome_obrigatorio' }, 400);
    const notas = Array.isArray(body.notas) ? body.notas : [];
    const docs = body.docs && typeof body.docs === 'object' ? body.docs : {};
    let id = body.id;
    const isNew = !id;
    if (isNew) {
      id = 'e_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
      const { results } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM colaboradores').all();
      await db.prepare('INSERT INTO colaboradores (id, nome, notas, docs, ordem) VALUES (?, ?, ?, ?, ?)')
        .bind(id, nome, JSON.stringify(notas), JSON.stringify(docs), results[0].max + 1).run();
    } else {
      const { results } = await db.prepare('SELECT id FROM colaboradores WHERE id = ?').bind(id).all();
      if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
      await db.prepare("UPDATE colaboradores SET nome = ?, notas = ?, docs = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(nome, JSON.stringify(notas), JSON.stringify(docs), id).run();
    }
    await regHist(db, request, session.username, (isNew ? 'Criou' : 'Editou') + ` colaborador "${nome}"`, 'dados');
    return json({ ok: true, id });
  }

  if (request.method === 'DELETE') {
    if (url.searchParams.get('esvaziar') === 'tudo') {
      if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM colaboradores WHERE deletado_em IS NOT NULL').all();
      await db.prepare('DELETE FROM colaboradores WHERE deletado_em IS NOT NULL').run();
      await regHist(db, request, session.username, `Esvaziou a lixeira de colaboradores (${countRes[0].count} apagados definitivamente)`, 'seguranca');
      return json({ ok: true });
    }
    const id = url.searchParams.get('id');
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT nome FROM colaboradores WHERE id = ? AND deletado_em IS NULL').bind(id).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE colaboradores SET deletado_em = ? WHERE id = ?').bind(new Date().toISOString(), id).run();
    await regHist(db, request, session.username, `Moveu colaborador "${results[0].nome}" para a lixeira`, 'dados');
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleDoctype(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const sigla = String(body.sigla || '').trim().toUpperCase().replace(/\s+/g, ' ');
    const nome = String(body.nome || '').trim();
    if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);
    if (!nome) return json({ error: 'nome_obrigatorio' }, 400);
    const { results: existing } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ?').bind(sigla).all();
    if (existing.length > 0) return json({ error: 'ja_existe' }, 409);
    const { results: maxRes } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM doc_types').all();
    const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM doc_types').all();
    const cor = PALETA[countRes[0].count % PALETA.length];
    await db.prepare('INSERT INTO doc_types (sigla, nome, descricao, cor, ordem) VALUES (?, ?, ?, ?, ?)')
      .bind(sigla, nome, nome, cor, maxRes[0].max + 1).run();
    await regHist(db, request, session.username, `Incluiu tipo de documento "${sigla}" (${nome})`, 'dados');
    return json({ ok: true, sigla, cor });
  }

  if (request.method === 'DELETE') {
    const sigla = url.searchParams.get('sigla');
    if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);
    const { results } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ?').bind(sigla).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('DELETE FROM doc_types WHERE sigla = ?').bind(sigla).run();
    const { results: colaboradores } = await db.prepare('SELECT id, docs FROM colaboradores').all();
    const stmts = colaboradores.map(c => {
      const docs = JSON.parse(c.docs);
      delete docs[sigla];
      return db.prepare('UPDATE colaboradores SET docs = ? WHERE id = ?').bind(JSON.stringify(docs), c.id);
    });
    if (stmts.length > 0) await db.batch(stmts);
    await regHist(db, request, session.username, `Excluiu tipo de documento "${sigla}"`, 'dados');
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleConfig(request, env) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
  const chave = String(body.chave || '').trim();
  const valor = String(body.valor ?? '');
  if (!chave) return json({ error: 'chave_obrigatoria' }, 400);
  await env.DB.prepare('INSERT INTO config (chave, valor) VALUES (?, ?) ON CONFLICT (chave) DO UPDATE SET valor = excluded.valor')
    .bind(chave, valor).run();
  await regHist(env.DB, request, session.username, `Alterou configuração "${chave}" para "${valor}"`, 'dados');
  return json({ ok: true });
}

async function handleUsers(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
  const db = env.DB;

  if (request.method === 'GET') {
    const { results } = await db.prepare('SELECT username, role, created_at FROM users ORDER BY created_at ASC').all();
    return json({ users: results });
  }

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const role = body.role === 'admin' ? 'admin' : 'editor';
    if (!username || password.length < 8) return json({ error: 'dados_invalidos' }, 400);
    const { results: existing } = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).all();
    if (existing.length > 0) return json({ error: 'ja_existe' }, 409);
    const { hash, salt } = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();
    const { hash: recoveryHash, salt: recoverySalt } = await hashPassword(recoveryCode);
    await db.prepare('INSERT INTO users (username, password_hash, password_salt, role, recovery_hash, recovery_salt) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(username, hash, salt, role, recoveryHash, recoverySalt).run();
    await regHist(db, request, session.username, `Adicionou o usuário "${username}" (${role})`, 'seguranca');
    return json({ ok: true, recoveryCode });
  }

  if (request.method === 'DELETE') {
    const username = url.searchParams.get('username');
    if (!username) return json({ error: 'username_obrigatorio' }, 400);
    if (username === session.username) return json({ error: 'nao_pode_excluir_a_si_mesmo' }, 400);
    const { results: adminCountRes } = await db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").all();
    const { results: targetRes } = await db.prepare('SELECT role FROM users WHERE username = ?').bind(username).all();
    if (targetRes.length === 0) return json({ error: 'nao_encontrado' }, 404);
    if (targetRes[0].role === 'admin' && adminCountRes[0].count <= 1) return json({ error: 'nao_pode_remover_ultimo_admin' }, 400);
    await db.prepare('DELETE FROM users WHERE username = ?').bind(username).run();
    await regHist(db, request, session.username, `Removeu o usuário "${username}"`, 'seguranca');
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleResetPassword(request, env) {
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
  const username = String(body.username || '').trim();
  const recoveryCode = String(body.recoveryCode || '').trim().toUpperCase();
  const newPassword = String(body.newPassword || '');
  if (!username || !recoveryCode || !newPassword) return json({ error: 'missing_fields' }, 400);
  if (newPassword.length < 8) return json({ error: 'password_too_short' }, 400);

  const db = env.DB;
  const { results } = await db.prepare('SELECT recovery_hash, recovery_salt FROM users WHERE username = ?').bind(username).all();
  const user = results[0];
  if (!user || !user.recovery_hash || !(await verifyPassword(recoveryCode, user.recovery_salt, user.recovery_hash))) {
    await regHist(db, request, username, 'Tentativa de redefinir senha com código de recuperação inválido', 'seguranca');
    return json({ error: 'codigo_invalido' }, 401);
  }

  const { hash, salt } = await hashPassword(newPassword);
  const novoCodigo = generateRecoveryCode();
  const { hash: recoveryHash, salt: recoverySalt } = await hashPassword(novoCodigo);
  await db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, recovery_hash = ?, recovery_salt = ? WHERE username = ?')
    .bind(hash, salt, recoveryHash, recoverySalt, username).run();
  await regHist(db, request, username, 'Redefiniu a própria senha usando o código de recuperação', 'seguranca');

  return json({ ok: true, newRecoveryCode: novoCodigo });
}

async function handleAdminResetPassword(request, env) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
  const username = String(body.username || '').trim();
  const newPassword = String(body.newPassword || '');
  if (!username || newPassword.length < 8) return json({ error: 'dados_invalidos' }, 400);

  const db = env.DB;
  const { results } = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).all();
  if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);

  const { hash, salt } = await hashPassword(newPassword);
  await db.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE username = ?').bind(hash, salt, username).run();
  await regHist(db, request, session.username, `Redefiniu a senha do usuário "${username}"`, 'seguranca');

  return json({ ok: true });
}

async function handleHistorico(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
  const db = env.DB;

  if (request.method === 'GET') {
    // Lista a lixeira: registros apagados, mais recentes primeiro. Aproveita pra apagar de vez o que passou do prazo.
    await purgarLixeiraAntiga(db);
    const { results } = await db.prepare('SELECT id, ts, username, acao, tipo, ip, deletado_em FROM historico WHERE deletado_em IS NOT NULL ORDER BY deletado_em DESC LIMIT 300').all();
    return json({ lixeira: results, diasRetencao: DIAS_RETENCAO_LIXEIRA });
  }

  if (request.method === 'POST') {
    // Restaura um registro apagado.
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const id = parseInt(body.id, 10);
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT id FROM historico WHERE id = ? AND deletado_em IS NOT NULL').bind(id).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE historico SET deletado_em = NULL WHERE id = ?').bind(id).run();
    await regHist(db, request, session.username, `Restaurou um registro do histórico (#${id})`, 'seguranca');
    return json({ ok: true });
  }

  if (request.method === 'DELETE') {
    const idParam = url.searchParams.get('id');
    const limpar = url.searchParams.get('limpar');
    const esvaziar = url.searchParams.get('esvaziar');
    const agora = new Date().toISOString();

    if (esvaziar === 'tudo') {
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM historico WHERE deletado_em IS NOT NULL').all();
      await db.prepare('DELETE FROM historico WHERE deletado_em IS NOT NULL').run();
      await regHist(db, request, session.username, `Esvaziou a lixeira do histórico (${countRes[0].count} registros apagados definitivamente)`, 'seguranca');
      return json({ ok: true });
    }

    if (limpar === 'tudo') {
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM historico WHERE deletado_em IS NULL').all();
      await db.prepare('UPDATE historico SET deletado_em = ? WHERE deletado_em IS NULL').bind(agora).run();
      await regHist(db, request, session.username, `Moveu todo o histórico para a lixeira (${countRes[0].count} registros)`, 'seguranca');
      return json({ ok: true });
    }

    if (!idParam) return json({ error: 'id_obrigatorio' }, 400);
    const id = parseInt(idParam, 10);
    const { results } = await db.prepare('SELECT id FROM historico WHERE id = ? AND deletado_em IS NULL').bind(id).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE historico SET deletado_em = ? WHERE id = ?').bind(agora, id).run();
    await regHist(db, request, session.username, `Moveu um registro do histórico para a lixeira (#${id})`, 'seguranca');
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (p === '/api/login') return await handleLogin(request, env);
      if (p === '/api/reset-password') return await handleResetPassword(request, env);
      if (p === '/api/admin-reset-password') return await handleAdminResetPassword(request, env);
      if (p === '/api/data') return await handleData(request, env);
      if (p === '/api/historico') return await handleHistorico(request, env, url);
      if (p === '/api/colaborador') return await handleColaborador(request, env, url);
      if (p === '/api/doctype') return await handleDoctype(request, env, url);
      if (p === '/api/config') return await handleConfig(request, env);
      if (p === '/api/users') return await handleUsers(request, env, url);
    } catch (err) {
      return json({ error: 'erro_interno', detalhe: String(err) }, 500);
    }
    // Qualquer outra rota (index.html, manifest.json, ícones, sw.js) vem dos arquivos estáticos.
    return env.ASSETS.fetch(request);
  },
};
