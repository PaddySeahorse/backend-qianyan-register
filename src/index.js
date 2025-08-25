// worker.js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    
    // 设置CORS头
    const corsHeaders = {
      'Access-Control-Allow-Origin': 'https://account-qianyan.pages.dev',
      'Access-Control-Allow-Methods': 'POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    
    // 处理预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // 只处理/auth路径
    if (pathname !== '/auth') {
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    }
    
    // 根据请求方法路由
    switch (request.method) {
      case 'POST':
        return handlePost(request, env, corsHeaders);
      case 'PUT':
        return handlePut(request, env, corsHeaders);
      case 'PATCH':
        return handlePatch(request, env, corsHeaders);
      case 'DELETE':
        return handleDelete(request, env, corsHeaders);
      default:
        return new Response('Method Not Allowed', { 
          status: 405, 
          headers: corsHeaders 
        });
    }
  }
};

// 处理用户登录验证并返回token
async function handlePost(request, env, corsHeaders) {
  try {
    const { email, password } = await request.json();
    
    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Email and password required" }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 查询用户
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: "用户不存在或密码错误" }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 验证密码
    const passwordMatch = await bcryptCompare(password, user.password_hash);
    
    if (!passwordMatch) {
      return new Response(JSON.stringify({ error: "用户不存在或密码错误" }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 生成JWT token
    const token = generateJWT(user.id, user.email, env.JWT_SECRET);
    
    return new Response(JSON.stringify({ 
      message: "登录成功",
      token: token,
      user: { id: user.id, email: user.email }
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: "服务器错误" }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 处理用户注册
async function handlePut(request, env, corsHeaders) {
  try {
    const { email, password } = await request.json();
    
    if (!email || !password) {
      return new Response(JSON.stringify({ error: "Email and password required" }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 检查用户是否已存在
    const existingUser = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email).first();
    
    if (existingUser) {
      return new Response(JSON.stringify({ error: "用户已存在" }), {
        status: 409,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 加密密码
    const passwordHash = await bcryptHash(password, 10);
    
    // 插入新用户
    const result = await env.DB.prepare(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)"
    ).bind(email, passwordHash).run();
    
    return new Response(JSON.stringify({ message: "用户创建成功" }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: "创建用户失败" }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 处理密码修改
async function handlePatch(request, env, corsHeaders) {
  try {
    // 验证token
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: "需要认证token" }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    const { email, newPassword } = await request.json();
    
    if (!email || !newPassword) {
      return new Response(JSON.stringify({ error: "Email and new password required" }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 验证token有效性
    let tokenData;
    try {
      tokenData = verifyJWT(token, env.JWT_SECRET);
    } catch (e) {
      // 如果JWT验证失败，检查是否是API_TOKEN
      if (token !== env.API_TOKEN) {
        return new Response(JSON.stringify({ error: "无效的token" }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      // 如果是API_TOKEN，允许操作
      tokenData = { email: "api_token" };
    }
    
    // 如果是普通用户token，验证email是否匹配
    if (tokenData.email !== "api_token" && tokenData.email !== email) {
      return new Response(JSON.stringify({ error: "无权操作此用户" }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 获取用户
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: "用户不存在" }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 更新密码
    const newPasswordHash = await bcryptHash(newPassword, 10);
    
    await env.DB.prepare(
      "UPDATE users SET password_hash = ? WHERE email = ?"
    ).bind(newPasswordHash, email).run();
    
    return new Response(JSON.stringify({ message: "密码修改成功" }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: "密码修改失败" }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 处理账户删除
async function handleDelete(request, env, corsHeaders) {
  try {
    // 验证token
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: "需要认证token" }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    const { email } = await request.json();
    
    if (!email) {
      return new Response(JSON.stringify({ error: "Email required" }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 验证token有效性
    let tokenData;
    try {
      tokenData = verifyJWT(token, env.JWT_SECRET);
    } catch (e) {
      // 如果JWT验证失败，检查是否是API_TOKEN
      if (token !== env.API_TOKEN) {
        return new Response(JSON.stringify({ error: "无效的token" }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      // 如果是API_TOKEN，允许操作
      tokenData = { email: "api_token" };
    }
    
    // 如果是普通用户token，验证email是否匹配
    if (tokenData.email !== "api_token" && tokenData.email !== email) {
      return new Response(JSON.stringify({ error: "无权操作此用户" }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 获取用户
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: "用户不存在" }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // 删除用户
    await env.DB.prepare(
      "DELETE FROM users WHERE email = ?"
    ).bind(email).run();
    
    return new Response(JSON.stringify({ message: "账户已删除" }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: "删除账户失败" }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 生成JWT Token
function generateJWT(userId, email, secret) {
  const header = {
    alg: "HS256",
    typ: "JWT"
  };
  
  const payload = {
    sub: userId,
    email: email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24小时有效期
  };
  
  const base64Header = base64UrlEncode(JSON.stringify(header));
  const base64Payload = base64UrlEncode(JSON.stringify(payload));
  
  // 在实际应用中，这里应该使用HMAC-SHA256算法生成签名
  // 简化处理，直接使用base64编码
  const signature = base64UrlEncode(JSON.stringify({
    value: "signature_placeholder",
    secret: secret
  }));
  
  return `${base64Header}.${base64Payload}.${signature}`;
}

// 验证JWT Token
function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }
  
  try {
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    
    // 检查token是否过期
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error("Token expired");
    }
    
    // 在实际应用中，这里应该验证签名
    // 简化处理，直接返回payload
    
    return payload;
  } catch (e) {
    throw new Error("Invalid token");
  }
}

// Base64 URL编码
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Base64 URL解码
function base64UrlDecode(str) {
  str = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  // 补全等号
  while (str.length % 4) {
    str += '=';
  }
  
  return atob(str);
}

// 密码加密和验证函数（实际应用中应使用完整的bcrypt实现）
async function bcryptHash(password, rounds) {
  // 这里应该使用实际的bcrypt哈希逻辑
  // 简化示例，实际使用时请使用完整的加密库
  return "hashed_" + password;
}

async function bcryptCompare(password, hash) {
  // 这里应该使用实际的bcrypt比较逻辑
  // 简化示例，实际使用时请使用完整的加密库
  return "hashed_" + password === hash;
}