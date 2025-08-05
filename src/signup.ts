export interface Env {
  DB: D1Database;
}

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hashPassword(password: string): Promise<{ salt: string; hash: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  
  return {
    salt: bufferToHex(salt),
    hash: bufferToHex(derivedKey)
  };
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400'
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 处理OPTIONS预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: CORS_HEADERS
      });
    }

    // 请求大小限制
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 1024 * 10) {
      return new Response('request too large', {
        status: 413,
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'text/plain'
        }
      });
    }

    // 只处理/signup路径
    if (url.pathname === '/signup') {
      // 只允许POST方法
      if (request.method !== 'POST') {
        return new Response('method not allowed', {
          status: 405,
          headers: {
            ...CORS_HEADERS,
            'Allow': 'POST',
            'Content-Type': 'text/plain'
          }
        });
      }

      try {
        let data: any;
        try {
          data = await request.json();
        } catch (e) {
          return new Response('invalid request format', {
            status: 400,
            headers: {
              ...CORS_HEADERS,
              'Content-Type': 'text/plain'
            }
          });
        }

        const { email, password } = data;

        // 空值检查
        if (!email || !password) {
          return new Response('forbidden', {
            status: 403,
            headers: {
              ...CORS_HEADERS,
              'Content-Type': 'text/plain'
            }
          });
        }

        // 邮箱规范化
        const normalizedEmail = email.toLowerCase().trim();

        // 检查邮箱是否已注册
        const existingUser = await env.DB.prepare(
          `SELECT 1 FROM users WHERE email = ? LIMIT 1`
        ).bind(normalizedEmail).first();

        if (existingUser) {
          return new Response('registration failed', {
            status: 409,
            headers: {
              ...CORS_HEADERS,
              'Content-Type': 'text/plain'
            }
          });
        }

        // 密码哈希处理
        const { salt, hash } = await hashPassword(password);

        // 存储到数据库
        const result = await env.DB.prepare(
          `INSERT INTO users (email, salt, password) VALUES (?, ?, ?)`
        ).bind(normalizedEmail, salt, hash).run();

        if (!result.success) {
          throw new Error('database insert failed');
        }

        return new Response('registration success', {
          status: 200,
          headers: {
            ...CORS_HEADERS,
            'Content-Type': 'text/plain'
          }
        });
      } catch (err: any) {
        console.error(`signup error: ${err.message}`, { stack: err.stack });

        // 错误信息脱敏
        const message = err.message.includes('UNIQUE constraint failed')
          ? 'registration failed'
          : 'internal server error';

        return new Response(message, {
          status: err.message.includes('UNIQUE constraint failed') ? 409 : 500,
          headers: {
            ...CORS_HEADERS,
            'Content-Type': 'text/plain'
          }
        });
      }
    }

    // 非/signup路径
    return new Response('not found', {
      status: 404,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': 'text/plain'
      }
    });
  }
};