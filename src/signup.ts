export interface Env {
  DB: D1Database;
}

// 辅助函数：将 ArrayBuffer 转换为十六进制字符串
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 密码哈希函数
async function hashPassword(password: string): Promise<{ salt: string; hash: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  // 导入密钥
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  // 使用 PBKDF2 算法派生密钥
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // ================= 安全保护层 =================
    // 请求大小限制 (10KB)
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 1024 * 10) {
      return new Response(JSON.stringify({ error: '请求过大' }), {
        status: 413,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    
    // ================= 路由处理 =================
    // 只处理 /signup 路径
    if (url.pathname === '/signup') {
      // 只允许 POST 方法
      if (request.method !== 'POST') {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: { 'Allow': 'POST' }
        });
      }
      
      try {
        // 安全JSON解析
        let data: any;
        try {
          data = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: '无效请求格式' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        
        const { email, password } = data;
        
        // 空值检查 (返回403且不提供详细信息)
        if (!email || !password) {
          return new Response(JSON.stringify({ error: '注册失败' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        
        // 检查邮箱是否已被注册
        const existingUser = await env.DB.prepare(
          `SELECT 1 FROM users WHERE email = ? LIMIT 1`
        ).bind(email).first();

        if (existingUser) {
          return new Response(JSON.stringify({ error: '该邮箱已被注册' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        
        // 密码哈希处理
        const { salt, hash } = await hashPassword(password);
        
        // 存储到数据库
        const result = await env.DB.prepare(
          `INSERT INTO users (email, salt, password) VALUES (?, ?, ?)`
        ).bind(email, salt, hash).run();
        
        // 检查插入操作
        if (!result.success) {
          throw new Error('D1数据库插入失败');
        }
        
        return new Response(JSON.stringify({ message: '注册成功' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err: any) {
        // 错误日志记录
        console.error(`注册错误: ${err.message}`, { stack: err.stack });
        
        // 处理唯一约束错误
        if (err.message.includes('UNIQUE constraint failed')) {
          return new Response(JSON.stringify({ error: '该邮箱已被注册' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        
        // 其他错误返回500
        return new Response(JSON.stringify({ error: '服务器错误' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }
    
    // 非/signup路径返回404
    return new Response('Not Found', { status: 404 });
  },
};