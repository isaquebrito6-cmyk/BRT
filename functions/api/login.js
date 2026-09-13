import { hashPassword, verifyPassword, makeSessionToken, json } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const secret = env.SESSION_SECRET;
  if (!secret) return json({ error: 'server_not_configured' }, 500);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_body' }, 400);
  }

  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || !password) return json({ error: 'missing_credentials' }, 400);
  if (password.length < 6) return json({ error: 'password_too_short' }, 400);

  const db = env.DB;
  const { results: countRows } = await db.prepare('SELECT COUNT(*) AS count FROM users').all();
  const count = countRows[0].count;

  if (count === 0) {
    // Bootstrap: primeiro login numa base vazia cria o primeiro administrador.
    const { hash, salt } = await hashPassword(password);
    await db.prepare('INSERT INTO users (username, password_hash, password_salt, role) VALUES (?, ?, ?, ?)')
      .bind(username, hash, salt, 'admin').run();
    await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)')
      .bind(username, 'Criou a conta de administrador (primeiro acesso)').run();
    const token = await makeSessionToken({ username, role: 'admin' }, secret);
    return json({ token, username, role: 'admin', bootstrap: true });
  }

  const { results } = await db.prepare('SELECT username, password_hash, password_salt, role FROM users WHERE username = ?')
    .bind(username).all();
  const user = results[0];
  if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
    return json({ error: 'invalid_credentials' }, 401);
  }

  const token = await makeSessionToken(user, secret);
  await db.prepare('INSERT INTO historico (username, acao) VALUES (?, ?)').bind(username, 'Entrou no sistema').run();
  return json({ token, username: user.username, role: user.role });
}
