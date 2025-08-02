import { hash } from 'bcryptjs';

export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/signup') {
      try {
        const { email, password } = await request.json();

        if (!email || !password) {
          return new Response(JSON.stringify({ error: '邮箱和密码不能为空' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const hashedPassword = await hash(password, 10);

        await env.DB.prepare(
          `INSERT INTO users (email, password) VALUES (?, ?)`
        ).bind(email, hashedPassword).run();

        return new Response(JSON.stringify({ message: '注册成功' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};