/* eslint-disable no-console */
import { NextRequest, NextResponse } from 'next/server';
import { isAccessTokenInvalidated } from '@/lib/access-token-invalidation';
import { getAuthInfoFromCookie } from '@/lib/auth';
import { TOKEN_CONFIG } from '@/lib/refresh-token';
import { isTVModeEnabled, resolveLoginPath } from '@/lib/tv-mode';

// ========== 访客模式配置 新增 ==========
// 访客禁止访问【写操作API】（修改配置、收藏、下载、保存记录等）
const GUEST_BLOCK_API = [
  '/api/config',
  '/api/collect',
  '/api/download',
  '/api/watchroom',
  '/api/history',
  '/api/user',
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const enableGuest = process.env.ENABLE_GUEST === "true";

  if (!isTVModeEnabled() && isTVModePath(pathname)) {
    return new NextResponse('Not Found', { status: 404 });
  }

  // 跳过不需要认证的路径
  if (shouldSkipAuth(pathname)) {
    return NextResponse.next();
  }

  const authInfo = getAuthInfoFromCookie(request);

  // ====================== 【访客核心逻辑，提前优先判断】======================
  // ✅ 开启访客模式，并且用户没有登录
  if (enableGuest && !authInfo) {
    // 判断当前访问的API是否在访客黑名单（写接口）
    const isBlockApi = GUEST_BLOCK_API.some(api => pathname.startsWith(api));
    if(isBlockApi){
      return NextResponse.json({message:"访客模式：禁止修改配置/收藏/下载/保存记录"}, {status:401})
    }
    // 读接口、播放页面直接放行访客，直接return，不再执行下面鉴权
    return NextResponse.next();
  }
  // ================================================================

  // ========== 原版鉴权逻辑（只有登录用户才会走到这里） ==========
  if (!process.env.PASSWORD) {
    // 如果未配置密码，重定向到警告页面
    const warningUrl = new URL('/warning', request.url);
    return warningUrl.pathname === pathname ? NextResponse.next() : NextResponse.redirect(warningUrl);
  }

  if (!authInfo) {
    return handleAuthFailure(request, pathname);
  }

  // localstorage模式：在middleware中完成验证
  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';
  if (storageType === 'localstorage') {
    if (!authInfo.password || authInfo.password !== process.env.PASSWORD) {
      return handleAuthFailure(request, pathname);
    }
    return NextResponse.next();
  }

  // 其他模式：验证签名和时间戳，支持自动续期
  if (!authInfo.username || !authInfo.role || !authInfo.signature || !authInfo.timestamp) {
    return handleAuthFailure(request, pathname);
  }

  // 强制要求新版 Cookie
  if (!authInfo.tokenId || !authInfo.refreshToken || !authInfo.refreshExpires) {
    console.log(`Old cookie format detected for ${authInfo.username}, forcing re-login`);
    return handleAuthFailure(request, pathname);
  }

  const ACCESS_TOKEN_AGE = TOKEN_CONFIG.ACCESS_TOKEN_AGE;
  const now = Date.now();
  const age = now - authInfo.timestamp;

  if (now >= authInfo.refreshExpires) {
    console.log(`Refresh token expired for ${authInfo.username}, redirecting to login`);
    return handleAuthFailure(request, pathname);
  }

  if (age > ACCESS_TOKEN_AGE) {
    console.log(`Access token expired for ${authInfo.username}`);
    if (pathname.startsWith('/api')) {
      return new NextResponse('Access token expired', { status: 401 });
    }
    console.log(`Allowing page request to pass, frontend will refresh token`);
  }

  const isValidSignature = await verifySignature(
    authInfo.username,
    authInfo.role,
    authInfo.timestamp,
    authInfo.signature,
    process.env.PASSWORD || ''
  );
  if (!isValidSignature) {
    return handleAuthFailure(request, pathname);
  }

  if (isAccessTokenInvalidated(authInfo)) {
    console.log(`Access token invalidated for ${authInfo.username}`);
    return handleAuthFailure(request, pathname);
  }

  return NextResponse.next();
}

// 验证签名（原版不动）
async function verifySignature(
  username: string,
  role: string,
  timestamp: number,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const dataToSign = JSON.stringify({
    username,
    role,
    timestamp
  });
  const messageData = encoder.encode(dataToSign);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData
    );
  } catch (error) {
    console.error('签名验证失败:', error);
    return false;
  }
}

// 处理认证失败（原版不动）
function handleAuthFailure(
  request: NextRequest,
  pathname: string
): NextResponse {
  if (pathname.startsWith('/api')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  const loginUrl = new URL(resolveLoginPath(pathname), request.url);
  const fullUrl = `${pathname}${request.nextUrl.search}`;
  loginUrl.searchParams.set('redirect', fullUrl);
  return NextResponse.redirect(loginUrl);
}

// 跳过鉴权路径（原版不动）
function shouldSkipAuth(pathname: string): boolean {
  const skipPaths = [
    '/_next',
    '/favicon.ico',
    '/robots.txt',
    '/manifest.json',
    '/icons/',
    '/logo.png',
    '/screenshot.png',
  ];
  return skipPaths.some((path) => pathname.startsWith(path));
}

function isTVModePath(pathname: string): boolean {
  return pathname === '/tv' || pathname.startsWith('/tv/') || pathname.startsWith('/api/tv-remote/');
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|register|oidc-register|qr-login|warning|tv/login|api/login|api/register|api/logout|api/auth/oidc|api/auth/qr|api/auth/refresh|api/telegram/login|api/telegram/config|api/telegram/webhook|api/cron/|api/server-config|api/proxy-m3u8|api/cms-proxy|api/tvbox/subscribe|api/theme/css|api/openlist/cms-proxy|api/openlist/play|api/openlist/proxy|api/emby/cms-proxy|api/emby/play|api/emby/subtitle|api/emby/sources|tvbox/).*)',
  ],
};
