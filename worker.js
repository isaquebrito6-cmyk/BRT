import { hashPassword, verifyPassword, makeSessionToken, getSession, json, generateRecoveryCode } from './lib/auth.js';

const PALETA = ['#f2b705', '#3fae5c', '#f2954a', '#e05a8a', '#8a6de0', '#4fa3e3', '#c94f4f', '#4fc9a8', '#c9a24f', '#7a8fd6'];

const BUILTIN_DOC_TYPES = [
  { sigla: 'ASO', nome: 'NR-07 · Atestado de Saúde Ocupacional', desc: 'Exame médico ocupacional obrigatório para todo colaborador.' },
  { sigla: 'NR-35', nome: 'Trabalho em Altura', desc: 'Treinamento obrigatório para atividades acima de 2m com risco de queda.' },
  { sigla: 'NR-33', nome: 'Espaços Confinados', desc: 'Treinamento para entrada e trabalho em espaços confinados (trabalhador).' },
  { sigla: 'NR-33 SUP', nome: 'Espaços Confinados · Supervisor', desc: 'Capacitação de supervisor responsável por entradas em espaços confinados.' },
  { sigla: 'LOTO', nome: 'NR-10/12 · Bloqueio e Etiquetagem', desc: 'Procedimento de bloqueio e etiquetagem (Lockout/Tagout) para energia perigosa.' },
  { sigla: 'NR-11/18', nome: 'Plataforma de Elevação', desc: 'Capacitação para operação de plataformas elevatórias / movimentação de cargas.' },
  { sigla: 'NR-20', nome: 'Inflamáveis e Combustíveis', desc: 'Treinamento para atividades com líquidos inflamáveis e combustíveis.' },
];

const MAX_TENTATIVAS = 5;
const BLOQUEIO_MINUTOS = 15;
const DIAS_RETENCAO_LIXEIRA = 30;

function clienteInfo(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'desconhecido';
  const ua = request.headers.get('User-Agent') || 'desconhecido';
  return { ip, ua };
}

async function regHist(db, request, username, acao, tipo = 'dados', empresaId = null) {
  const { ip, ua } = clienteInfo(request);
  await db.prepare('INSERT INTO historico (username, acao, tipo, ip, user_agent, empresa_id) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(username, acao, tipo, ip, ua, empresaId).run();
}

function dataLimiteRetencao() {
  return new Date(Date.now() - DIAS_RETENCAO_LIXEIRA * 24 * 60 * 60 * 1000).toISOString();
}

async function purgarLixeiraAntiga(db) {
  const limite = dataLimiteRetencao();
  await db.prepare('DELETE FROM colaboradores WHERE deletado_em IS NOT NULL AND deletado_em < ?').bind(limite).run();
  await db.prepare('DELETE FROM historico WHERE deletado_em IS NOT NULL AND deletado_em < ?').bind(limite).run();
}

// Decide de qual empresa a requisição trata, e garante que a pessoa tem permissão pra ela.
// Admins (empresa_id nulo no token) podem escolher qualquer empresa via ?empresa_id=.
// Editores só podem acessar a própria empresa, fixada no login.
async function resolverEmpresa(session, url, db) {
  const requestedRaw = url.searchParams.get('empresa_id');
  const requested = requestedRaw ? parseInt(requestedRaw, 10) : null;

  if (session.role === 'admin') {
    if (requested) return { ok: true, empresaId: requested };
    const { results } = await db.prepare('SELECT id FROM empresas ORDER BY id ASC LIMIT 1').all();
    if (results.length === 0) return { ok: false, error: 'nenhuma_empresa_cadastrada' };
    return { ok: true, empresaId: results[0].id };
  }

  // editor
  if (!session.empresaId) return { ok: false, error: 'usuario_sem_empresa' };
  if (requested && requested !== session.empresaId) return { ok: false, error: 'sem_acesso_a_essa_empresa' };
  return { ok: true, empresaId: session.empresaId };
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
    await db.prepare('INSERT INTO users (username, password_hash, password_salt, role, recovery_hash, recovery_salt, empresa_id) VALUES (?, ?, ?, ?, ?, ?, NULL)')
      .bind(username, hash, salt, 'admin', recoveryHash, recoverySalt).run();
    await regHist(db, request, username, 'Criou a conta de administrador (primeiro acesso)', 'seguranca');
    const token = await makeSessionToken({ username, role: 'admin', empresaId: null }, secret);
    return json({ token, username, role: 'admin', empresaId: null, bootstrap: true, recoveryCode });
  }

  const { results } = await db.prepare('SELECT username, password_hash, password_salt, role, empresa_id, failed_attempts, locked_until FROM users WHERE username = ?')
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
        await regHist(db, request, username, `Conta bloqueada por ${BLOQUEIO_MINUTOS} minutos após ${MAX_TENTATIVAS} tentativas de login erradas`, 'seguranca', user.empresa_id);
      } else {
        await db.prepare('UPDATE users SET failed_attempts = ? WHERE username = ?').bind(tentativas, username).run();
        await regHist(db, request, username, 'Tentativa de login falhou (senha incorreta)', 'seguranca', user.empresa_id);
      }
    }
    return json({ error: 'invalid_credentials' }, 401);
  }

  await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?').bind(username).run();
  const token = await makeSessionToken({ username: user.username, role: user.role, empresaId: user.empresa_id }, secret);
  await regHist(db, request, username, 'Entrou no sistema', 'seguranca', user.empresa_id);
  return json({ token, username: user.username, role: user.role, empresaId: user.empresa_id });
}

async function handleEmpresas(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;

  if (request.method === 'GET') {
    if (session.role === 'admin') {
      const { results } = await db.prepare('SELECT id, nome, criado_em FROM empresas ORDER BY nome ASC').all();
      return json({ empresas: results });
    }
    if (!session.empresaId) return json({ empresas: [] });
    const { results } = await db.prepare('SELECT id, nome, criado_em FROM empresas WHERE id = ?').bind(session.empresaId).all();
    return json({ empresas: results });
  }

  if (request.method === 'POST') {
    if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const nome = String(body.nome || '').trim();
    if (!nome) return json({ error: 'nome_obrigatorio' }, 400);

    const { meta } = await db.prepare('INSERT INTO empresas (nome) VALUES (?)').bind(nome).run();
    const empresaId = meta.last_row_id;

    const stmts = BUILTIN_DOC_TYPES.map((dt, i) =>
      db.prepare('INSERT INTO doc_types (sigla, nome, descricao, cor, ordem, empresa_id) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(dt.sigla, dt.nome, dt.desc, PALETA[i % PALETA.length], i + 1, empresaId)
    );
    stmts.push(db.prepare('INSERT INTO config (empresa_id, chave, valor) VALUES (?, ?, ?)').bind(empresaId, 'avisoDias', '30'));
    stmts.push(db.prepare('INSERT INTO config (empresa_id, chave, valor) VALUES (?, ?, ?)').bind(empresaId, 'empresa', nome));
    await db.batch(stmts);

    await regHist(db, request, session.username, `Criou a empresa "${nome}"`, 'seguranca', empresaId);
    return json({ ok: true, id: empresaId, nome });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleData(request, env, url) {
  if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;

  const resolvido = await resolverEmpresa(session, url, db);
  if (!resolvido.ok) return json({ error: resolvido.error }, 403);
  const empresaId = resolvido.empresaId;

  const [colaboradoresRes, docTypesRes, configRes, historicoRes, empresaRes] = await Promise.all([
    db.prepare('SELECT id, nome, notas, docs FROM colaboradores WHERE empresa_id = ? AND deletado_em IS NULL ORDER BY ordem ASC, nome ASC').bind(empresaId).all(),
    db.prepare('SELECT sigla, nome, descricao, cor, ordem FROM doc_types WHERE empresa_id = ? ORDER BY ordem ASC').bind(empresaId).all(),
    db.prepare('SELECT chave, valor FROM config WHERE empresa_id = ?').bind(empresaId).all(),
    db.prepare('SELECT id, ts, username, acao, tipo, ip, user_agent FROM historico WHERE empresa_id = ? AND deletado_em IS NULL ORDER BY ts DESC LIMIT 500').bind(empresaId).all(),
    db.prepare('SELECT id, nome FROM empresas WHERE id = ?').bind(empresaId).all(),
  ]);

  const colaboradores = colaboradoresRes.results.map(c => ({ id: c.id, nome: c.nome, notas: JSON.parse(c.notas), docs: JSON.parse(c.docs) }));
  const config = {};
  configRes.results.forEach(r => { config[r.chave] = r.valor; });

  let empresas = null;
  if (session.role === 'admin') {
    const { results } = await db.prepare('SELECT id, nome FROM empresas ORDER BY nome ASC').all();
    empresas = results;
  }

  return json({
    colaboradores, docTypes: docTypesRes.results, config, historico: historicoRes.results,
    role: session.role, username: session.username,
    empresaAtual: empresaRes.results[0] || null,
    empresas,
  });
}

async function handleColaborador(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;
  const resolvido = await resolverEmpresa(session, url, db);
  if (!resolvido.ok) return json({ error: resolvido.error }, 403);
  const empresaId = resolvido.empresaId;

  if (request.method === 'GET') {
    await purgarLixeiraAntiga(db);
    const { results } = await db.prepare('SELECT id, nome, docs, deletado_em FROM colaboradores WHERE empresa_id = ? AND deletado_em IS NOT NULL ORDER BY deletado_em DESC').bind(empresaId).all();
    return json({ lixeira: results.map(c => ({ id: c.id, nome: c.nome, docs: JSON.parse(c.docs), deletado_em: c.deletado_em })), diasRetencao: DIAS_RETENCAO_LIXEIRA });
  }

  if (request.method === 'PUT') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const id = String(body.id || '');
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT nome FROM colaboradores WHERE id = ? AND empresa_id = ? AND deletado_em IS NOT NULL').bind(id, empresaId).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE colaboradores SET deletado_em = NULL WHERE id = ?').bind(id).run();
    await regHist(db, request, session.username, `Restaurou colaborador "${results[0].nome}" da lixeira`, 'dados', empresaId);
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
      const { results } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM colaboradores WHERE empresa_id = ?').bind(empresaId).all();
      await db.prepare('INSERT INTO colaboradores (id, nome, notas, docs, ordem, empresa_id) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(id, nome, JSON.stringify(notas), JSON.stringify(docs), results[0].max + 1, empresaId).run();
    } else {
      const { results } = await db.prepare('SELECT id FROM colaboradores WHERE id = ? AND empresa_id = ?').bind(id, empresaId).all();
      if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
      await db.prepare("UPDATE colaboradores SET nome = ?, notas = ?, docs = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(nome, JSON.stringify(notas), JSON.stringify(docs), id).run();
    }
    await regHist(db, request, session.username, (isNew ? 'Criou' : 'Editou') + ` colaborador "${nome}"`, 'dados', empresaId);
    return json({ ok: true, id });
  }

  if (request.method === 'DELETE') {
    if (url.searchParams.get('esvaziar') === 'tudo') {
      if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM colaboradores WHERE empresa_id = ? AND deletado_em IS NOT NULL').bind(empresaId).all();
      await db.prepare('DELETE FROM colaboradores WHERE empresa_id = ? AND deletado_em IS NOT NULL').bind(empresaId).run();
      await regHist(db, request, session.username, `Esvaziou a lixeira de colaboradores (${countRes[0].count} apagados definitivamente)`, 'seguranca', empresaId);
      return json({ ok: true });
    }
    const id = url.searchParams.get('id');
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT nome FROM colaboradores WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL').bind(id, empresaId).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE colaboradores SET deletado_em = ? WHERE id = ?').bind(new Date().toISOString(), id).run();
    await regHist(db, request, session.username, `Moveu colaborador "${results[0].nome}" para a lixeira`, 'dados', empresaId);
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleDoctype(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  const db = env.DB;
  const resolvido = await resolverEmpresa(session, url, db);
  if (!resolvido.ok) return json({ error: resolvido.error }, 403);
  const empresaId = resolvido.empresaId;

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const sigla = String(body.sigla || '').trim().toUpperCase().replace(/\s+/g, ' ');
    const nome = String(body.nome || '').trim();
    if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);
    if (!nome) return json({ error: 'nome_obrigatorio' }, 400);
    const { results: existing } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ? AND empresa_id = ?').bind(sigla, empresaId).all();
    if (existing.length > 0) return json({ error: 'ja_existe' }, 409);
    const { results: maxRes } = await db.prepare('SELECT COALESCE(MAX(ordem), 0) AS max FROM doc_types WHERE empresa_id = ?').bind(empresaId).all();
    const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM doc_types WHERE empresa_id = ?').bind(empresaId).all();
    const cor = PALETA[countRes[0].count % PALETA.length];
    await db.prepare('INSERT INTO doc_types (sigla, nome, descricao, cor, ordem, empresa_id) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(sigla, nome, nome, cor, maxRes[0].max + 1, empresaId).run();
    await regHist(db, request, session.username, `Incluiu tipo de documento "${sigla}" (${nome})`, 'dados', empresaId);
    return json({ ok: true, sigla, cor });
  }

  if (request.method === 'DELETE') {
    const sigla = url.searchParams.get('sigla');
    if (!sigla) return json({ error: 'sigla_obrigatoria' }, 400);
    const { results } = await db.prepare('SELECT sigla FROM doc_types WHERE sigla = ? AND empresa_id = ?').bind(sigla, empresaId).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('DELETE FROM doc_types WHERE sigla = ? AND empresa_id = ?').bind(sigla, empresaId).run();
    const { results: colaboradores } = await db.prepare('SELECT id, docs FROM colaboradores WHERE empresa_id = ?').bind(empresaId).all();
    const stmts = colaboradores.map(c => {
      const docs = JSON.parse(c.docs);
      delete docs[sigla];
      return db.prepare('UPDATE colaboradores SET docs = ? WHERE id = ?').bind(JSON.stringify(docs), c.id);
    });
    if (stmts.length > 0) await db.batch(stmts);
    await regHist(db, request, session.username, `Excluiu tipo de documento "${sigla}"`, 'dados', empresaId);
    return json({ ok: true });
  }

  return json({ error: 'method_not_allowed' }, 405);
}

async function handleConfig(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  const db = env.DB;
  const resolvido = await resolverEmpresa(session, url, db);
  if (!resolvido.ok) return json({ error: resolvido.error }, 403);
  const empresaId = resolvido.empresaId;

  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
  const chave = String(body.chave || '').trim();
  const valor = String(body.valor ?? '');
  if (!chave) return json({ error: 'chave_obrigatoria' }, 400);
  await db.prepare('INSERT INTO config (empresa_id, chave, valor) VALUES (?, ?, ?) ON CONFLICT (empresa_id, chave) DO UPDATE SET valor = excluded.valor')
    .bind(empresaId, chave, valor).run();
  await regHist(db, request, session.username, `Alterou configuração "${chave}" para "${valor}"`, 'dados', empresaId);
  return json({ ok: true });
}

async function handleUsers(request, env, url) {
  const session = await getSession(request, env.SESSION_SECRET);
  if (!session) return json({ error: 'unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'somente_admin' }, 403);
  const db = env.DB;

  if (request.method === 'GET') {
    const { results } = await db.prepare(`
      SELECT u.username, u.role, u.empresa_id, u.created_at, e.nome AS empresa_nome
      FROM users u LEFT JOIN empresas e ON e.id = u.empresa_id
      ORDER BY u.created_at ASC
    `).all();
    return json({ users: results });
  }

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const role = body.role === 'admin' ? 'admin' : 'editor';
    const empresaId = role === 'editor' ? parseInt(body.empresaId, 10) || null : null;
    if (!username || password.length < 8) return json({ error: 'dados_invalidos' }, 400);
    if (role === 'editor' && !empresaId) return json({ error: 'empresa_obrigatoria_para_editor' }, 400);
    const { results: existing } = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).all();
    if (existing.length > 0) return json({ error: 'ja_existe' }, 409);
    const { hash, salt } = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();
    const { hash: recoveryHash, salt: recoverySalt } = await hashPassword(recoveryCode);
    await db.prepare('INSERT INTO users (username, password_hash, password_salt, role, recovery_hash, recovery_salt, empresa_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(username, hash, salt, role, recoveryHash, recoverySalt, empresaId).run();
    await regHist(db, request, session.username, `Adicionou o usuário "${username}" (${role})`, 'seguranca', empresaId);
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
  const { results } = await db.prepare('SELECT recovery_hash, recovery_salt, empresa_id FROM users WHERE username = ?').bind(username).all();
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
  await regHist(db, request, username, 'Redefiniu a própria senha usando o código de recuperação', 'seguranca', user.empresa_id);

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
  const resolvido = await resolverEmpresa(session, url, db);
  if (!resolvido.ok) return json({ error: resolvido.error }, 403);
  const empresaId = resolvido.empresaId;

  if (request.method === 'GET') {
    await purgarLixeiraAntiga(db);
    const { results } = await db.prepare('SELECT id, ts, username, acao, tipo, ip, deletado_em FROM historico WHERE empresa_id = ? AND deletado_em IS NOT NULL ORDER BY deletado_em DESC LIMIT 300').bind(empresaId).all();
    return json({ lixeira: results, diasRetencao: DIAS_RETENCAO_LIXEIRA });
  }

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'invalid_body' }, 400); }
    const id = parseInt(body.id, 10);
    if (!id) return json({ error: 'id_obrigatorio' }, 400);
    const { results } = await db.prepare('SELECT id FROM historico WHERE id = ? AND empresa_id = ? AND deletado_em IS NOT NULL').bind(id, empresaId).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE historico SET deletado_em = NULL WHERE id = ?').bind(id).run();
    await regHist(db, request, session.username, `Restaurou um registro do histórico (#${id})`, 'seguranca', empresaId);
    return json({ ok: true });
  }

  if (request.method === 'DELETE') {
    const idParam = url.searchParams.get('id');
    const limpar = url.searchParams.get('limpar');
    const esvaziar = url.searchParams.get('esvaziar');
    const agora = new Date().toISOString();

    if (esvaziar === 'tudo') {
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM historico WHERE empresa_id = ? AND deletado_em IS NOT NULL').bind(empresaId).all();
      await db.prepare('DELETE FROM historico WHERE empresa_id = ? AND deletado_em IS NOT NULL').bind(empresaId).run();
      await regHist(db, request, session.username, `Esvaziou a lixeira do histórico (${countRes[0].count} registros apagados definitivamente)`, 'seguranca', empresaId);
      return json({ ok: true });
    }

    if (limpar === 'tudo') {
      const { results: countRes } = await db.prepare('SELECT COUNT(*) AS count FROM historico WHERE empresa_id = ? AND deletado_em IS NULL').bind(empresaId).all();
      await db.prepare('UPDATE historico SET deletado_em = ? WHERE empresa_id = ? AND deletado_em IS NULL').bind(agora, empresaId).run();
      await regHist(db, request, session.username, `Moveu todo o histórico para a lixeira (${countRes[0].count} registros)`, 'seguranca', empresaId);
      return json({ ok: true });
    }

    if (!idParam) return json({ error: 'id_obrigatorio' }, 400);
    const id = parseInt(idParam, 10);
    const { results } = await db.prepare('SELECT id FROM historico WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL').bind(id, empresaId).all();
    if (results.length === 0) return json({ error: 'nao_encontrado' }, 404);
    await db.prepare('UPDATE historico SET deletado_em = ? WHERE id = ?').bind(agora, id).run();
    await regHist(db, request, session.username, `Moveu um registro do histórico para a lixeira (#${id})`, 'seguranca', empresaId);
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
      if (p === '/api/empresas') return await handleEmpresas(request, env, url);
      if (p === '/api/data') return await handleData(request, env, url);
      if (p === '/api/historico') return await handleHistorico(request, env, url);
      if (p === '/api/colaborador') return await handleColaborador(request, env, url);
      if (p === '/api/doctype') return await handleDoctype(request, env, url);
      if (p === '/api/config') return await handleConfig(request, env, url);
      if (p === '/api/users') return await handleUsers(request, env, url);
    } catch (err) {
      return json({ error: 'erro_interno', detalhe: String(err) }, 500);
    }
    // Qualquer outra rota (index.html, manifest.json, ícones, sw.js) vem dos arquivos estáticos.
    return env.ASSETS.fetch(request);
  },
};
