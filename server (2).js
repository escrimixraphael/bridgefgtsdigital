import express from 'express'
import https from 'node:https'
import http from 'node:http'
import tls from 'node:tls'
import cors from 'cors'
import crypto from 'node:crypto'
import { Buffer } from 'node:buffer'
import querystring from 'node:querystring'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'

const execFileAsync = promisify(execFile)

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

// ======================================================
// CONFIG
// ======================================================
const X_API_KEY = process.env.BRIDGE_API_KEY || 'uma-chave-secreta-bem-longa'
const PORT = process.env.PORT || 3000

if (!process.env.BRIDGE_API_KEY) {
  console.warn('[WARN] BRIDGE_API_KEY não definida em env — usando fallback. Configure no Render!')
}

// ======================================================
// SEGURANÇA — comparação em tempo constante
// ======================================================
function apiKeyValida(recebida) {
  if (!recebida) return false
  try {
    const a = crypto.createHash('sha256').update(String(recebida)).digest()
    const b = crypto.createHash('sha256').update(String(X_API_KEY)).digest()
    return crypto.timingSafeEqual(a, b)
  } catch {
    return false
  }
}

function requireApiKey(req, res, next) {
  if (!apiKeyValida(req.headers['x-api-key'])) {
    return res.status(403).json({ success: false, error: 'Acesso negado: Chave API inválida' })
  }
  next()
}

// ======================================================
// CACHE DE TOKEN SERPRO
// ======================================================
const tokenCache = new Map()

function cacheKey(clientId, cnpj) {
  return crypto.createHash('sha256').update(`${clientId}::${cnpj || ''}`).digest('hex')
}

function getCachedToken(key) {
  const t = tokenCache.get(key)
  if (t && t.expiresAt - 60_000 > Date.now()) return t
  if (t) tokenCache.delete(key)
  return null
}

// ======================================================
// CACHE DE PFX CONVERTIDO (legacy -> AES-256)
// evita reconverter o mesmo cert a cada request
// ======================================================
const pfxConvCache = new Map()

function pfxCacheKey(pfxBase64, password) {
  return crypto
    .createHash('sha256')
    .update(pfxBase64.slice(0, 200) + '::' + pfxBase64.length + '::' + (password || ''))
    .digest('hex')
}

// ======================================================
// CLASSIFICADOR DE ERROS DE REDE / TLS
// ======================================================
const NETWORK_CODES = new Set([
  'ETIMEDOUT',
  'ECONNRESET',
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'ECONNABORTED',
  'ERR_TLS_HANDSHAKE_TIMEOUT',
])

function classifyError(err, stage) {
  const code = err?.code || ''
  const msg = err?.message || String(err)

  if (/^Timeout:/i.test(msg) || code === 'ETIMEDOUT') {
    return {
      errorType: 'SERPRO_CONNECTION_ERROR',
      stage,
      code: code || 'TIMEOUT',
      message: `Timeout de conexão ao conectar (${stage}). Verifique whitelist de IP no SERPRO / rede.`,
      raw: msg,
    }
  }

  if (NETWORK_CODES.has(code)) {
    return {
      errorType: 'SERPRO_CONNECTION_ERROR',
      stage,
      code,
      message: `Falha de conexão (${code}) no estágio ${stage}.`,
      raw: msg,
    }
  }

  if (
    code.startsWith('ERR_TLS') ||
    /handshake|alert|SSL routines|tlsv1|certificate verify failed|unable to get local issuer/i.test(msg)
  ) {
    return {
      errorType: 'TLS_HANDSHAKE_ERROR',
      stage,
      code: code || 'TLS',
      message: `Falha no handshake TLS (${stage}). Pode ser mTLS/whitelist ou cadeia do servidor.`,
      raw: msg,
    }
  }

  return {
    errorType: 'BRIDGE_INTERNAL',
    stage,
    code: code || 'UNKNOWN',
    message: msg,
    raw: msg,
  }
}

// ======================================================
// CONVERSÃO LEGACY -> AES-256 via binário openssl (-legacy)
// ======================================================
async function convertLegacyPfx(pfxBuffer, password) {
  const tmp = os.tmpdir()
  const id = crypto.randomBytes(8).toString('hex')
  const inPfx = path.join(tmp, `in_${id}.pfx`)
  const pem = path.join(tmp, `mid_${id}.pem`)
  const outPfx = path.join(tmp, `out_${id}.pfx`)
  const pass = password || ''

  const cleanup = async () => {
    await Promise.allSettled([fs.unlink(inPfx), fs.unlink(pem), fs.unlink(outPfx)])
  }

  try {
    await fs.writeFile(inPfx, pfxBuffer)

    await execFileAsync('openssl', [
      'pkcs12',
      '-in', inPfx,
      '-nodes',
      '-legacy',
      '-passin', `pass:${pass}`,
      '-out', pem,
    ])

    await execFileAsync('openssl', [
      'pkcs12',
      '-export',
      '-in', pem,
      '-out', outPfx,
      '-passout', `pass:${pass}`,
      '-keypbe', 'AES-256-CBC',
      '-certpbe', 'AES-256-CBC',
      '-macalg', 'sha256',
    ])

    const converted = await fs.readFile(outPfx)
    console.log(`[convertLegacyPfx] OK — reempacotado AES-256 (${converted.length} bytes)`)
    return converted
  } finally {
    await cleanup()
  }
}

// ======================================================
// PFX / mTLS — detecta legado (OpenSSL 3) vs senha real
// ======================================================
async function makePfxTls(pfxBase64, password) {
  if (!pfxBase64) {
    const e = new Error('Certificado (pfxBase64) ausente')
    e.pfxStage = 'MISSING'
    throw e
  }

  const pfx = Buffer.from(pfxBase64, 'base64')
  if (pfx.length < 500) {
    const e = new Error('PFX vazio ou truncado (base64 muito pequeno)')
    e.pfxStage = 'TRUNCATED'
    throw e
  }

  const passphrase = password || ''

  try {
    tls.createSecureContext({ pfx, passphrase })
    return { pfx, passphrase, converted: false }
  } catch (err) {
    const msg = err.message || ''
    console.error('[makePfxTls] ERRO CRU OpenSSL:', msg, '| code:', err.code)

    if (/unsupported|digital envelope|legacy|EVP_|routines|DECODER/i.test(msg)) {
      const ck = pfxCacheKey(pfxBase64, password)
      const cached = pfxConvCache.get(ck)
      if (cached) {
        console.log('[makePfxTls] usando PFX convertido do cache')
        return { pfx: cached, passphrase, converted: true }
      }

      try {
        console.warn('[makePfxTls] PFX legado detectado — tentando conversão automática AES-256...')
        const convertedPfx = await convertLegacyPfx(pfx, passphrase)

        tls.createSecureContext({ pfx: convertedPfx, passphrase })

        pfxConvCache.set(ck, convertedPfx)
        return { pfx: convertedPfx, passphrase, converted: true }
      } catch (convErr) {
        const rawConv = convErr.stderr || convErr.message || ''
        console.error('[makePfxTls] conversão automática FALHOU:', rawConv)

        if (/mac verify|invalid password|wrong password|bad decrypt|password is not correct/i.test(rawConv)) {
          const e = new Error('Senha do certificado incorreta (falha ao converter PFX legado)')
          e.pfxStage = 'PFX_INVALID'
          e.raw = rawConv
          throw e
        }

        const e = new Error(
          'PFX usa algoritmo legado não suportado pelo OpenSSL 3 e a conversão automática falhou. ' + msg,
        )
        e.pfxStage = 'PFX_LEGACY_ALGO'
        e.raw = rawConv || msg
        throw e
      }
    }

    if (/mac verify|invalid password|wrong password|PKCS12|pkcs12|bad decrypt|password is not correct/i.test(msg)) {
      const e = new Error('Senha do certificado incorreta ou PFX corrompido')
      e.pfxStage = 'PFX_INVALID'
      e.raw = msg
      throw e
    }

    const e = new Error('Falha ao carregar certificado: ' + msg)
    e.pfxStage = 'PFX_LOAD_ERROR'
    e.raw = msg
    throw e
  }
}

// ======================================================
// HTTP HELPER
// ======================================================
function httpRequest(
  urlStr,
  { method = 'GET', headers = {}, body = null, mtls = null, timeout = 30000, jar = null } = {},
) {
  return new Promise((resolve, reject) => {
    let url
    try {
      url = new URL(urlStr)
    } catch {
      return reject(new Error('URL inválida: ' + urlStr))
    }

    const isHttps = url.protocol === 'https:'
    const lib = isHttps ? https : http

    const reqHeaders = { ...headers }
    
    if (jar) {
      const cookieStr = jar.header()
      if (cookieStr) reqHeaders['Cookie'] = cookieStr
    }

    if (body && !reqHeaders['Content-Length'] && !reqHeaders['content-length']) {
      reqHeaders['Content-Length'] = Buffer.byteLength(body)
    }

    const opts = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      rejectUnauthorized: false,
      timeout,
      headers: reqHeaders,
    }

    if (mtls) {
      opts.pfx = mtls.pfx
      opts.passphrase = mtls.passphrase
      opts.secureOptions = crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT 
    }

    const reqH = lib.request(opts, (resp) => {
      const chunks = []
      resp.on('data', (c) => chunks.push(c))
      resp.on('end', () => {
        if (jar && resp.headers['set-cookie']) {
          jar.set(resp.headers['set-cookie'])
        }
        const buf = Buffer.concat(chunks)
        resolve({
          status: resp.statusCode,
          headers: resp.headers,
          location: resp.headers.location,
          body: buf.toString('utf8'),
          bodyBuffer: buf,
        })
      })
    })

    reqH.on('error', (err) => reject(err))

    reqH.on('timeout', () => {
      reqH.destroy()
      const e = new Error('Timeout: ' + url.hostname)
      e.code = 'ETIMEDOUT'
      reject(e)
    })

    if (body) reqH.write(body)
    reqH.end()
  })
}

function tryParseJson(str) {
  try {
    return JSON.parse(str)
  } catch {
    return null
  }
}

// ======================================================
// COOKIE JAR
// ======================================================
function newCookieJar() {
  const store = {}
  return {
    set(setCookie = []) {
      if (!Array.isArray(setCookie)) setCookie = [setCookie]
      for (const sc of setCookie) {
        if (!sc) continue
        const [kv] = sc.split(';')
        const idx = kv.indexOf('=')
        if (idx === -1) continue
        const k = kv.slice(0, idx).trim()
        const v = kv.slice(idx + 1).trim()
        store[k] = v
      }
    },
    header() {
      const entries = Object.entries(store)
      return entries.length ? entries.map(([k, v]) => `${k}=${v}`).join('; ') : ''
    },
    raw: store,
  }
}

// ======================================================
// PARSER DE HTML
// ======================================================
function decodeHtmlEntities(str) {
  return String(str)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x2F;/g, '/')
}

// ======================================================
// LOGIN GOV.BR OAUTH2 (COM NAVEGADOR INTELIGENTE WAF-BYPASS)
// ======================================================
async function loginGovBr(pfxBase64, password) {
  const mtls = await makePfxTls(pfxBase64, password)
  const jar = newCookieJar()
  const headersGovBr = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'
  }

  console.log('[FGTS] Iniciando fluxo de SSO (OAuth2)...')
  
  const nonce = crypto.randomBytes(16).toString('hex')
  const state = crypto.randomBytes(16).toString('hex')
  const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`

  let currentUrl = authUrl;
  let loginPageHtml = '';
  let baseLoginUrl = '';

  // LOOP DE IDA (Encontra a página de Login e dribla o WAF)
  for(let i = 0; i < 5; i++) {
     console.log(`[HOP-IDA ${i}] GET ${currentUrl.substring(0,70)}...`);
     const resp = await httpRequest(currentUrl, { method: 'GET', jar, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         continue;
     }

     if (resp.status === 200) {
         if (currentUrl.includes('/login?client_id=')) {
             baseLoginUrl = currentUrl;
             loginPageHtml = resp.body;
             break;
         }
         // Se cair no firewall (F5/Datadome), ele envia cookies e um script de refresh
         if (resp.body.includes('refresh') || resp.body.includes('reload') || resp.body.includes('TSPD_')) {
             console.log(`[HOP-IDA ${i}] WAF detectado, recarregando a página...`);
             const metaMatch = resp.body.match(/url\s*=\s*([^"'>]+)/i);
             if (metaMatch) {
                 let metaUrl = decodeHtmlEntities(metaMatch[1]);
                 currentUrl = metaUrl.startsWith('http') ? metaUrl : new URL(metaUrl, currentUrl).toString();
             }
             continue;
         }
         throw new Error(`Travou numa página desconhecida (200 OK). URL: ${currentUrl}. Body: ${resp.body.substring(0,100)}`);
     }
     throw new Error(`Erro HTTP ${resp.status} em ${currentUrl}`);
  }

  if (!baseLoginUrl || !loginPageHtml) throw new Error('Falha ao chegar na página de login do Gov.br');

  // =========================================================================
  // O SEGREDO DO 400 BAD REQUEST ESTAVA AQUI:
  // Extrair APENAS Inputs Ocultos (type="hidden") para não sujar o payload
  // =========================================================================
  const fields = {}
  const hiddenRegex = /<input[^>]+type=["']hidden["'][^>]*>/gi
  let m
  while ((m = hiddenRegex.exec(loginPageHtml)) !== null) {
      const tag = m[0]
      const nameMatch = tag.match(/name=["']([^"']+)["']/i)
      const valueMatch = tag.match(/value=["']([^"']*)["']/i)
      if (nameMatch) {
          fields[nameMatch[1]] = valueMatch ? decodeHtmlEntities(valueMatch[1]) : ''
      }
  }

  const payload = querystring.stringify(fields)
  let urlLoginTls = baseLoginUrl.replace('sso.acesso.gov.br', 'certificado.sso.acesso.gov.br')

  console.log(`[FGTS] Disparando POST mTLS -> ${urlLoginTls.substring(0, 70)}...`)

  const certHeaders = {
      ...headersGovBr,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Referer': baseLoginUrl
  }

  // O POST oficial do login com mTLS
  const respCert = await httpRequest(urlLoginTls, {
      method: 'POST', jar, mtls, headers: certHeaders, body: payload
  })

  if (respCert.status === 401) throw new Error('Certificado rejeitado pelo Gov.br (Erro 401). Verifique versão Node.js ou a Senha.')
  if (respCert.status === 403) throw new Error('WAF Gov.br bloqueou a requisição (403) mTLS. Verifique a rede ou headers.')
  if (respCert.status === 400) throw new Error(`Gov.br retornou 400 Bad Request. Payload enviado: ${payload}`)
  if (!respCert.location) throw new Error(`Falha SSO: Sem redirecionamento mTLS. HTTP ${respCert.status}. Body: ${respCert.body.substring(0,100)}`)

  // LOOP DE VOLTA (Do Login mTLS até validar no FGTS Digital)
  currentUrl = respCert.location;
  let urlFgtsCode = '';

  for(let i = 0; i < 5; i++) {
     console.log(`[HOP-VOLTA ${i}] GET ${currentUrl.substring(0,70)}...`);
     const resp = await httpRequest(currentUrl, { method: 'GET', jar, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         continue;
     }

     // Se o servidor respondeu 200 OK na página do FGTS com Code
     if (resp.status === 200 && (currentUrl.includes('code=') || currentUrl.includes('acessogov'))) {
         urlFgtsCode = currentUrl;
         break;
     }
  }

  if (!urlFgtsCode) throw new Error('Falha no SSO: Não chegou na página do FGTS Digital com o CODE.');

  const headersApiFgts = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'User-Agent': headersGovBr['User-Agent'],
      'Referer': urlFgtsCode
  }

  // 4. ATIVAÇÃO INVISÍVEL (Token do Portal)
  console.log('[FGTS] Gerando fgtsd_login...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', {
    method: 'POST', jar, headers: headersApiFgts, body: JSON.stringify({})
  })

  console.log('[FGTS] Acessando escolha de perfil...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', {
    method: 'GET', jar, headers: headersGovBr
  })

  console.log('[FGTS] Confirmando primeiro acesso / Sincronizando Cookies...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', {
    method: 'GET', jar, headers: headersApiFgts
  })

  console.log('[FGTS] Sessão estabelecida com sucesso!')
  return { jar, finalUrl: urlFgtsCode, mtls }
}

// ======================================================
// AUTENTICAÇÃO SERPRO
// ======================================================
async function resolveSerproAuth({ clientId, clientSecret, pfxBase64, password, cnpj, role, reuseAuth }) {
  const key = cacheKey(clientId, cnpj)

  if (
    reuseAuth?.access_token &&
    reuseAuth?.jwt_token &&
    reuseAuth?.expires_at &&
    reuseAuth.expires_at - 60_000 > Date.now()
  ) {
    console.log('[auth] reuseAuth do hook — pulando /authenticate')
    return {
      auth: {
        access_token: reuseAuth.access_token,
        jwt_token: reuseAuth.jwt_token,
        token_type: 'Bearer',
        scope: reuseAuth.scope,
        expires_at: reuseAuth.expires_at,
      },
    }
  }

  const cached = getCachedToken(key)
  if (cached) {
    console.log('[auth] token do cache server-side')
    return {
      auth: {
        access_token: cached.accessToken,
        jwt_token: cached.jwtToken,
        token_type: 'Bearer',
        scope: cached.scope,
        expires_at: cached.expiresAt,
      },
    }
  }

  if (!pfxBase64) {
    return { error: { code: 'NO_PFX', stage: 'open_pfx', message: 'Sem token válido e sem pfxBase64 para autenticar' } }
  }

  let tlsPfx
  try {
    tlsPfx = await makePfxTls(pfxBase64, password)
    console.log(
      `[auth] PFX aberto com sucesso (${tlsPfx.pfx.length} bytes)${tlsPfx.converted ? ' [convertido AES-256]' : ''} — senha OK.`,
    )
  } catch (convErr) {
    return {
      error: {
        code: convErr.pfxStage || 'PFX_LOAD_ERROR',
        stage: 'open_pfx',
        message: convErr.message,
        raw: convErr.raw,
        certError: convErr.pfxStage === 'PFX_INVALID',
      },
    }
  }

  const authHeader = 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')

  console.log(`[auth] Conectando /authenticate (Role: ${role})...`)
  let authResult
  try {
    authResult = await httpRequest('https://autenticacao.sapi.serpro.gov.br/authenticate', {
      method: 'POST',
      mtls: tlsPfx,
      timeout: 15000,
      headers: {
        Authorization: authHeader,
        'role-type': role,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: querystring.stringify({ grant_type: 'client_credentials' }),
    })
  } catch (netErr) {
    const c = classifyError(netErr, 'serpro_authenticate')
    console.error('[auth] Falha de conexão no /authenticate:', c.code, c.raw)
    return { error: c }
  }

  console.log(`[auth] Resposta /authenticate: HTTP ${authResult.status}`)

  const tokens = tryParseJson(authResult.body) || {}
  const accessToken = tokens.access_token
  const jwtToken =
    tokens.jwt_token || authResult.headers['jwt_token'] || authResult.headers['jwt-token']

  if (authResult.status === 401 || authResult.status === 403) {
    return {
      error: {
        code: 'SERPRO_AUTH_REJECTED',
        stage: 'serpro_authenticate',
        status: authResult.status,
        message: `SERPRO rejeitou as credenciais (HTTP ${authResult.status}). Verifique clientId/clientSecret e vínculo do certificado.`,
        detalhe: tokens.error ? tokens : authResult.body,
      },
    }
  }

  if (!accessToken || !jwtToken) {
    return {
      error: {
        code: 'SERPRO_AUTH',
        stage: 'serpro_authenticate',
        status: authResult.status,
        message: 'O SERPRO não retornou os tokens necessários (access_token ou jwt_token).',
        detalhe: tokens.error ? tokens : authResult.body,
        tokens: {
          access_token: accessToken ? 'PRESENTE' : 'AUSENTE',
          jwt_token: jwtToken ? 'PRESENTE' : 'AUSENTE',
          scope: tokens.scope,
        },
      },
    }
  }

  const expiresIn = Number(tokens.expires_in) || 3600
  const expiresAt = Date.now() + expiresIn * 1000

  tokenCache.set(key, { accessToken, jwtToken, scope: tokens.scope, expiresAt })

  return {
    auth: {
      access_token: accessToken,
      jwt_token: jwtToken,
      token_type: 'Bearer',
      scope: tokens.scope,
      expires_at: expiresAt,
      pfxConverted: tlsPfx.converted, 
    },
  }
}

// ======================================================
// ROTA: SERPRO Integra Contador
// ======================================================
app.post('/consultar-serpro', requireApiKey, async (req, res) => {
  const {
    pfxBase64,
    password,
    clientId,
    clientSecret,
    tipoAcesso,
    endpoint,
    payload,
    cnpj,
    reuseAuth,
  } = req.body

  if (!clientId || !clientSecret) {
    return res.status(400).json({ success: false, error: 'clientId/clientSecret ausentes' })
  }
  if (!endpoint) {
    return res.status(400).json({ success: false, error: 'Endpoint do serviço ausente' })
  }

  const role = tipoAcesso || 'TERCEIROS'
  const key = cacheKey(clientId, cnpj)

  try {
    const authRes = await resolveSerproAuth({
      clientId,
      clientSecret,
      pfxBase64,
      password,
      cnpj,
      role,
      reuseAuth,
    })

    if (authRes.error) {
      const e = authRes.error

      if (['NO_PFX', 'PFX_INVALID', 'PFX_LOAD_ERROR', 'PFX_LEGACY_ALGO', 'MISSING', 'TRUNCATED'].includes(e.code)) {
        return res.status(400).json({
          success: false,
          certError: e.code === 'PFX_INVALID',
          errorType: e.code,
          stage: e.stage || 'open_pfx',
          error: e.message,
          raw: e.raw,
        })
      }

      return res.status(200).json({
        success: false,
        certError: false,
        errorType: e.code,
        stage: e.stage || 'serpro_authenticate',
        status: e.status,
        error: e.message,
        detalhe: e.detalhe,
        diagnostico: {
          code: e.code,
          raw: e.raw,
          dica:
            e.errorType === 'SERPRO_CONNECTION_ERROR' || e.code === 'SERPRO_CONNECTION_ERROR'
              ? 'Timeout/rede: confirme whitelist do IP de saída da bridge no SERPRO.'
              : undefined,
        },
        tokens: e.tokens,
      })
    }

    const authBlock = authRes.auth

    console.log(`[service] Consultando: ${endpoint}`)
    let serviceResult
    try {
      serviceResult = await httpRequest(endpoint, {
        method: 'POST',
        timeout: 45000,
        headers: {
          Authorization: `Bearer ${authBlock.access_token}`,
          jwt_token: authBlock.jwt_token,
          'role-type': role,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(payload),
      })
    } catch (netErr) {
      const c = classifyError(netErr, 'serpro_service')
      console.error('[service] Falha de conexão:', c.code, c.raw)
      return res.status(200).json({
        success: false,
        certError: false,
        errorType: c.errorType,
        stage: c.stage,
        error: c.message,
        diagnostico: { code: c.code, raw: c.raw },
        auth: authBlock,
      })
    }

    const serviceData = tryParseJson(serviceResult.body)

    if (serviceResult.status === 401) {
      tokenCache.delete(key)
      return res.status(200).json({
        success: false,
        errorType: 'SERPRO_TOKEN_EXPIRED',
        stage: 'serpro_service',
        error: 'Token SERPRO expirado/rejeitado — reenvie com pfxBase64 para reautenticar',
        auth: null,
      })
    }

    if (serviceResult.status >= 400) {
      return res.status(200).json({
        success: false,
        certError: false,
        errorType: 'SERPRO_SERVICE',
        stage: 'serpro_service',
        status: serviceResult.status,
        error: `Erro no serviço SERPRO (${serviceResult.status})`,
        detalhe: serviceData || serviceResult.body,
        auth: authBlock,
      })
    }

    return res.json({
      success: true,
      data: serviceData ?? serviceResult.body,
      auth: authBlock,
    })
  } catch (error) {
    const c = classifyError(error, 'bridge')
    console.error('[bridge] Erro não tratado:', c.code, c.raw)
    return res.status(500).json({
      success: false,
      certError: false,
      errorType: c.errorType,
      stage: c.stage,
      error: 'Erro interno na Bridge: ' + c.message,
      diagnostico: { code: c.code, raw: c.raw },
    })
  }
})

// ======================================================
// ROTA DE DIAGNÓSTICO DE PFX
// ======================================================
app.post('/diag-pfx', requireApiKey, async (req, res) => {
  const { pfxBase64, password } = req.body
  const out = {
    nodeVersion: process.version,
    openssl: process.versions.openssl,
    passLen: (password || '').length,
  }

  try {
    const { stdout } = await execFileAsync('openssl', ['version'])
    out.opensslBinario = stdout.trim()
  } catch (e) {
    out.opensslBinario = { erro: e.message }
  }

  if (!pfxBase64) return res.status(400).json({ error: 'pfxBase64 ausente', ...out })

  const pfx = Buffer.from(pfxBase64, 'base64')
  out.pfxBytes = pfx.length

  let precisaConverter = false
  try {
    tls.createSecureContext({ pfx, passphrase: password || '' })
    out.comSenha = 'OK ✅ (senha correta, PFX moderno)'
  } catch (e) {
    out.comSenha = { msg: e.message, code: e.code }
    if (/unsupported|digital envelope|legacy|EVP_|routines|DECODER/i.test(e.message || '')) {
      precisaConverter = true
    }
  }

  try {
    tls.createSecureContext({ pfx, passphrase: '' })
    out.semSenha = 'OK (abre SEM senha — senha enviada é desnecessária/errada)'
  } catch (e) {
    out.semSenha = { msg: e.message }
  }

  if (precisaConverter) {
    try {
      const converted = await convertLegacyPfx(pfx, password || '')
      tls.createSecureContext({ pfx: converted, passphrase: password || '' })
      out.conversaoLegacy = `OK ✅ (convertido para AES-256, ${converted.length} bytes — a bridge fará isso automaticamente)`
    } catch (e) {
      out.conversaoLegacy = { erro: 'FALHOU', msg: e.stderr || e.message }
    }
  }

  res.json(out)
})

// ======================================================
// ROTAS RPA (gov.br)
// ======================================================
async function handleRpaError(res, tag, err) {
  if (err.pfxStage) {
    console.error(`[${tag}] erro PFX:`, err.pfxStage, err.message)
    return res.status(400).json({
      success: false,
      certError: err.pfxStage === 'PFX_INVALID',
      errorType: err.pfxStage,
      error: err.message,
      raw: err.raw,
    })
  }
  const c = classifyError(err, tag)
  console.error(`[${tag}] erro:`, c.code, c.raw)
  return res.status(200).json({
    success: false,
    certError: false,
    errorType: c.errorType,
    stage: c.stage,
    error: c.message,
    diagnostico: { code: c.code, raw: c.raw },
  })
}

// ==========================
// Rota principal FGTS (de coleta real)
// ==========================
app.post('/rpa/fgts/extrato', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password, payloadBusca } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    console.log('[FGTS] Iniciando login...')
    const { jar, finalUrl } = await loginGovBr(pfxBase64, password)
    console.log("[FGTS] Login OK, final URL:", finalUrl.slice(0,80))

    // Montar ID do empregador (8 primeiros digitos do CNPJ + 1)
    const cnpjNum = cnpj.replace(/\D/g,'')
    const empId = `${cnpjNum.substring(0,8)}1`

    // Requisições API - Headers base
    const headers = {
      'Accept': 'application/json, text/plain, */*',
      'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'
    }

    // 1. Coleta de dados do Usuário (Valida Sessão)
    const respUsuario = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/usuario', { method:'GET', jar, headers })
    const dadosUsuario = tryParseJson(respUsuario.body)

    // 2. Coleta de Competências (Envolvido em try/catch silencioso pois retornou 400 no seu log)
    let competencias = null;
    const respComp = await httpRequest(`https://fgtsdigital.sistema.gov.br/consignado/api/empregadores/${empId}/competencias`, { method:'GET', jar, headers })
    if (respComp.status === 200) {
        competencias = tryParseJson(respComp.body)
    }

    // 3. Lista Guias
    const bodyGuias = payloadBusca || {}
    const respLista = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/consultar-guias/guias', { method:'POST', jar, headers, body: JSON.stringify(bodyGuias) })
    const listaGuias = tryParseJson(respLista.body)
    const guiasArray = Array.isArray(listaGuias) ? listaGuias : (listaGuias?.content || listaGuias?.itens || [])

    // 4. Detalhes por guia
    const detalhes = []
    
    // Obs: Se quiser puxar todas as guias, remova o .slice(0,3).
    for (const g of guiasArray.slice(0,3)) {
      const idGuia = g.id || g.idGuia || g.numeroGuia
      if (!idGuia) continue
      
      const respTot = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/totalizador`, { method:'GET', jar, headers })
      const respDeb = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/debitos?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })
      
      // 5. Coleta de Consignados da Guia
      const respConsig = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/consignados?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })

      detalhes.push({
        guiaBase: g,
        totalizador: tryParseJson(respTot.body),
        debitos: tryParseJson(respDeb.body),
        consignados: tryParseJson(respConsig.body)
      })
    }

    res.json({ 
        success: true, 
        usuario: dadosUsuario,
        competencias: competencias,
        guias: detalhes, 
        rawData: { listaGuias, detalhes } 
    })

  } catch(e) {
    return handleRpaError(res, 'FGTS', e)
  }
});

// ======================================================
// HEALTHCHECK
// ======================================================
app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))

// ======================================================
// START
// ======================================================
app.listen(PORT, () => console.log(`Bridge SERPRO/RPA rodando na porta ${PORT}`))
