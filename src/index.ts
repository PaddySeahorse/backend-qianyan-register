// src/index.ts

export interface Env {
  DB: D1Database;
  TOKEN: string;
  RATE_LIMIT_KV: KVNamespace;
}

interface UserRequest {
  email: string;
  password: string;
  oldpwd?: string;
  newpwd?: string;
}

interface ApiResponse {
  success: boolean;
  message: string;
  data?: any;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // 处理OPTIONS请求（CORS预检）
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    // 检查授权
    if (!await isAuthorized(request, env)) {
      return jsonResponse({ success: false, message: '未授权访问' }, 401);
    }

    // 只处理/auth路径的请求
    const url = new URL(request.url);
    if (url.pathname !== '/auth') {
      return jsonResponse({ success: false, message: '接口不存在' }, 404);
    }

    try {
      // 根据HTTP方法路由到不同的处理函数
      switch (request.method) {
        case 'POST':
          return await handleLogin(request, env);
        case 'PUT':
          return await handleSignup(request, env);
        case 'PATCH':
          return await handleUpdatePassword(request, env);
        case 'DELETE':
          return await handleDeleteAccount(request, env);
        default:
          return jsonResponse({ success: false, message: '不支持的请求方法' }, 405);
      }
    } catch (error) {
      console.error('处理请求时出错:', error);
      return jsonResponse({ success: false, message: '服务器内部错误' }, 500);
    }
  },
};

// 处理OPTIONS请求
function handleOptions(): Response {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': 'https://account-qianyan.pages.dev',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

// 检查请求是否授权
async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  // 检查Token认证（开发者直接访问）
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    return token === env.TOKEN;
  }

  // 检查前端域名
  const origin = request.headers.get('Origin');
  return origin === 'https://account-qianyan.pages.dev';
}

// 生成JSON响应
function jsonResponse(data: ApiResponse, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': 'https://account-qianyan.pages.dev',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

// 简单的哈希函数
function simpleHash(str: string): string {
  let hash = 0;
  if (str.length === 0) return hash.toString();
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // 转换为32位整数
  }
  return Math.abs(hash).toString(16);
}

// 检查速率限制
async function checkRateLimit(
  request: Request, 
  env: Env, 
  email: string
): Promise<{ allowed: boolean; remaining?: number }> {
  try {
    // 获取客户端信息
    const ip = request.headers.get('CF-Connecting-IP') || 
               request.headers.get('X-Forwarded-For') || 
               'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';
    
    // 生成复合标识符
    const compositeStr = `${email}:${ip}:${userAgent}`;
    const compositeHash = simpleHash(compositeStr);
    const rateLimitKey = `rate_limit:${compositeHash}`;
    
    // 获取当前限制状态
    const current = await env.RATE_LIMIT_KV.get(rateLimitKey);
    const now = Date.now();
    const fiveMinutesAgo = now - 5 * 60 * 1000;
    
    if (!current) {
      // 第一次请求，创建新记录
      await env.RATE_LIMIT_KV.put(
        rateLimitKey, 
        JSON.stringify({ count: 1, firstRequest: now }),
        { expirationTtl: 300 } // 5分钟过期
      );
      return { allowed: true, remaining: 49 };
    }
    
    // 解析现有记录
    const data = JSON.parse(current);
    
    if (data.firstRequest < fiveMinutesAgo) {
      // 超过5分钟，重置计数
      await env.RATE_LIMIT_KV.put(
        rateLimitKey, 
        JSON.stringify({ count: 1, firstRequest: now }),
        { expirationTtl: 300 }
      );
      return { allowed: true, remaining: 49 };
    }
    
    if (data.count >= 50) {
      // 超过限制
      return { allowed: false };
    }
    
    // 增加计数
    data.count++;
    await env.RATE_LIMIT_KV.put(
      rateLimitKey, 
      JSON.stringify(data),
      { expirationTtl: 300 }
    );
    
    return { allowed: true, remaining: 50 - data.count };
  } catch (error) {
    console.error('速率限制检查错误:', error);
    // 出错时允许请求通过，避免因速率限制系统故障导致服务不可用
    return { allowed: true };
  }
}

// 密码哈希函数
async function hashPassword(password: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成随机盐值
function generateSalt(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// 处理登录请求
async function handleLogin(request: Request, env: Env): Promise<Response> {
  try {
    const { email, password }: UserRequest = await request.json();

    if (!email || !password) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱和密码为必填项' 
      }, 400);
    }

    // 检查速率限制
    const rateLimitCheck = await checkRateLimit(request, env, email);
    if (!rateLimitCheck.allowed) {
      return jsonResponse({ 
        success: false, 
        message: '请求过于频繁，请5分钟后再试' 
      }, 429);
    }

    // 查询用户
    const user = await env.DB.prepare(
      'SELECT id, password_hash, salt FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱或密码错误' 
      }, 401);
    }

    // 验证密码
    const hashedPassword = await hashPassword(password, user.salt as string);
    if (hashedPassword !== user.password_hash) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱或密码错误' 
      }, 401);
    }

    return jsonResponse({ 
      success: true, 
      message: '登录成功' 
    });
  } catch (error) {
    console.error('登录处理出错:', error);
    return jsonResponse({ 
      success: false, 
      message: '处理登录请求时发生错误' 
    }, 500);
  }
}

// 处理注册请求
async function handleSignup(request: Request, env: Env): Promise<Response> {
  try {
    const { email, password }: UserRequest = await request.json();

    if (!email || !password) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱和密码为必填项' 
      }, 400);
    }

    // 检查速率限制
    const rateLimitCheck = await checkRateLimit(request, env, email);
    if (!rateLimitCheck.allowed) {
      return jsonResponse({ 
        success: false, 
        message: '请求过于频繁，请5分钟后再试' 
      }, 429);
    }

    // 检查邮箱格式
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱格式不正确' 
      }, 400);
    }

    // 检查密码长度
    if (password.length < 6) {
      return jsonResponse({ 
        success: false, 
        message: '密码长度至少为6位' 
      }, 400);
    }

    // 检查用户是否已存在
    const existingUser = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (existingUser) {
      return jsonResponse({ 
        success: false, 
        message: '用户已存在' 
      }, 409);
    }

    // 生成盐值和哈希密码
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    // 插入新用户
    await env.DB.prepare(
      'INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)'
    ).bind(email, passwordHash, salt).run();

    return jsonResponse({ 
      success: true, 
      message: '用户创建成功' 
    }, 201);
  } catch (error) {
    console.error('注册处理出错:', error);
    return jsonResponse({ 
      success: false, 
      message: '创建用户时发生错误' 
    }, 500);
  }
}

// 处理密码修改请求
async function handleUpdatePassword(request: Request, env: Env): Promise<Response> {
  try {
    const { email, oldpwd, newpwd }: UserRequest = await request.json();

    if (!email || !oldpwd || !newpwd) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱、旧密码和新密码为必填项' 
      }, 400);
    }

    // 检查速率限制
    const rateLimitCheck = await checkRateLimit(request, env, email);
    if (!rateLimitCheck.allowed) {
      return jsonResponse({ 
        success: false, 
        message: '请求过于频繁，请5分钟后再试' 
      }, 429);
    }

    // 检查新密码长度
    if (newpwd.length < 6) {
      return jsonResponse({ 
        success: false, 
        message: '新密码长度至少为6位' 
      }, 400);
    }

    // 查询用户
    const user = await env.DB.prepare(
      'SELECT id, password_hash, salt FROM users WHERE email = ?'
    ).bind(email).first();

    // 用户不存在或旧密码错误都返回401
    if (!user) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱或旧密码错误' 
      }, 401);
    }

    // 验证旧密码
    const hashedOldPassword = await hashPassword(oldpwd, user.salt as string);
    if (hashedOldPassword !== user.password_hash) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱或旧密码错误' 
      }, 401);
    }

    // 生成新盐值和哈希新密码
    const newSalt = generateSalt();
    const newPasswordHash = await hashPassword(newpwd, newSalt);

    // 更新密码
    await env.DB.prepare(
      'UPDATE users SET password_hash = ?, salt = ? WHERE email = ?'
    ).bind(newPasswordHash, newSalt, email).run();

    return jsonResponse({ 
      success: true, 
      message: '密码更新成功' 
    });
  } catch (error) {
    console.error('密码修改处理出错:', error);
    return jsonResponse({ 
      success: false, 
      message: '更新密码时发生错误' 
    }, 500);
  }
}

// 处理账户删除请求
async function handleDeleteAccount(request: Request, env: Env): Promise<Response> {
  try {
    const { email, password }: UserRequest = await request.json();

    if (!email || !password) {
      return jsonResponse({ 
        success: false, 
        message: '邮箱和密码为必填项' 
      }, 400);
    }

    // 检查速率限制
    const rateLimitCheck = await checkRateLimit(request, env, email);
    if (!rateLimitCheck.allowed) {
      return jsonResponse({ 
        success: false, 
        message: '请求过于频繁，请5分钟后再试' 
      }, 429);
    }

    // 查询用户
    const user = await env.DB.prepare(
      'SELECT id, password_hash, salt FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      return jsonResponse({ 
        success: false, 
        message: '用户不存在' 
      }, 404);
    }

    // 验证密码
    const hashedPassword = await hashPassword(password, user.salt as string);
    if (hashedPassword !== user.password_hash) {
      return jsonResponse({ 
        success: false, 
        message: '密码错误' 
      }, 401);
    }

    // 删除用户
    await env.DB.prepare(
      'DELETE FROM users WHERE email = ?'
    ).bind(email).run();

    return jsonResponse({ 
      success: true, 
      message: '账户删除成功' 
    });
  } catch (error) {
    console.error('账户删除处理出错:', error);
    return jsonResponse({ 
      success: false, 
      message: '删除账户时发生错误' 
    }, 500);
  }
}