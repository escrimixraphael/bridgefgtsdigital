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
// CONFIGURAÇÃO
// ======================================================
// Puxa do Render (process.env) ou usa as chaves fornecidas como fallback absoluto
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || '9c6c38a65f8052500b7d4c2aff0b87fa'
const FGTS_API_KEY = process.env.FGTS_API_KEY || '5341b41fa01513c5b3e23f6dc35b8e94'
const PORT = process.env.PORT || 3000

// ======================================================
// SEGURANÇA — Validação de Chave API
// ======================================================
function apiKeyValida(recebida) {
  if (!recebida) return false
  try {
    const hashRecebido = crypto.createHash('sha256').update(String(recebida)).digest()
    const hashBridge = crypto.createHash('sha256').update(String(BRIDGE_API_KEY)).digest()
    const hashFgts = crypto.createHash('sha256').update(String(FGTS_API_KEY)).digest()
    
    // Libera o acesso se bater com qualquer uma das duas chaves
    return crypto.timingSafeEqual(hashRecebido, hashBridge) || crypto.timingSafeEqual(hashRecebido, hashFgts)
  } catch {
    return false
  }
}

function requireApiKey(req, res, next) {
  // O Backend pode mandar a chave em qualquer um desses dois headers
  const recebida = req.headers['x-api-key'] || req.headers['fgts-api-key']
  
  if (!apiKeyValida(recebida)) {
    return res.status(403).json({ 
      success: false, 
      error: 'Acesso negado: Chave API inválida ou ausente. Envie x-api-key no header.' 
    })
  }
  next()
}

// ======================================================
// CLASSIFICADOR DE ERROS
// ======================================================
function classifyError(err, stage) {
  const code = err?.code || ''
  const msg = err?.message || String(err)

  if (/^Timeout:/i.test(msg) || code === 'ETIMEDOUT') {
    return { errorType: 'TIMEOUT', stage, code: 'TIMEOUT', message: 'Timeout de conexão ao acessar Gov.br/FGTS.' }
  }
  if (code.startsWith('ERR_TLS') || /handshake|alert|SSL routines/i.test(msg)) {
    return { errorType: 'TLS_HANDSHAKE_ERROR', stage, code: code || 'TLS', message: 'Falha no handshake TLS (Certificado).' }
  }
  return { errorType: 'BRIDGE_INTERNAL', stage, code: code || 'UNKNOWN', message: msg, raw: msg }
}

// ======================================================
// CACHE DE CONVERSÃO DE PFX (Para não usar CPU à toa)
// ======================================================
const pfxConvCache = new Map()

function pfxCacheKey(pfxBase64, password) {
  return crypto.createHash('sha256').update(pfxBase64.slice(0, 200) + '::' + pfxBase64.length + '::' + (password || '')).digest('hex')
}

// ======================================================
// CONVERSÃO LEGACY PFX -> AES-256 (Resolve Erro OpenSSL 3 Node 18+)
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
    await execFileAsync('openssl', ['pkcs12', '-in', inPfx, '-nodes', '-legacy', '-passin', `pass:${pass}`, '-out', pem])
    await execFileAsync('openssl', ['pkcs12', '-export', '-in', pem, '-out', outPfx, '-passout', `pass:${pass}`, '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'sha256'])
    const converted = await fs.readFile(outPfx)
    console.log(`[PFX] Reempacotado para AES-256 com sucesso (${converted.length} bytes)`)
    return converted
  } finally {
    await cleanup()
  }
}

// ======================================================
// ABERTURA DE CERTIFICADO mTLS
// ======================================================
async function makePfxTls(pfxBase64, password) {
  if (!pfxBase64) {
    const e = new Error('Certificado (pfxBase64) ausente'); e.pfxStage = 'MISSING'; throw e
  }

  const pfx = Buffer.from(pfxBase64, 'base64')
  if (pfx.length < 500) {
    const e = new Error('PFX vazio ou truncado'); e.pfxStage = 'TRUNCATED'; throw e
  }

  const passphrase = password || ''

  try {
    tls.createSecureContext({ pfx, passphrase })
    return { pfx, passphrase, converted: false }
  } catch (err) {
    const msg = err.message || ''
    
    if (/unsupported|digital envelope|legacy|EVP_|routines/i.test(msg)) {
      const ck = pfxCacheKey(pfxBase64, password)
      const cached = pfxConvCache.get(ck)
      if (cached) return { pfx: cached, passphrase, converted: true }

      try {
        console.warn('[PFX] PFX legado detectado — convertendo para AES-256 (Node 18+ compatível)...')
        const convertedPfx = await convertLegacyPfx(pfx, passphrase)
        tls.createSecureContext({ pfx: convertedPfx, passphrase })
        pfxConvCache.set(ck, convertedPfx)
        return { pfx: convertedPfx, passphrase, converted: true }
      } catch (convErr) {
        const rawConv = convErr.stderr || convErr.message || ''
        if (/mac verify|invalid password|wrong password/i.test(rawConv)) {
          const e = new Error('Senha do certificado incorreta'); e.pfxStage = 'PFX_INVALID'; throw e
        }
        const e = new Error('Falha na conversão do PFX legado: ' + rawConv); e.pfxStage = 'PFX_LEGACY_ALGO'; throw e
      }
    }

    if (/mac verify|invalid password/i.test(msg)) {
      const e = new Error('Senha incorreta ou PFX corrompido'); e.pfxStage = 'PFX_INVALID'; throw e
    }
    const e = new Error('Falha ao carregar certificado: ' + msg); e.pfxStage = 'PFX_LOAD_ERROR'; throw e
  }
}

// ======================================================
// GERENCIADOR DE COOKIES (Aprimorado para WAF Gov.br)
// ======================================================
function newCookieJar() {
  const store = new Map()
  return {
    set(setCookieHeaders = []) {
      if (!setCookieHeaders) return;
      if (!Array.isArray(setCookieHeaders)) setCookieHeaders = [setCookieHeaders];
      
      for (const header of setCookieHeaders) {
        if (!header) continue;
        const [kv] = header.split(';');
        const eqIdx = kv.indexOf('=');
        if (eqIdx !== -1) {
          const k = kv.slice(0, eqIdx).trim();
          const v = kv.slice(eqIdx + 1).trim();
          store.set(k, v);
        }
      }
    },
    header() {
      return Array.from(store.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    }
  }
}

// ======================================================
// CLIENTE HTTP NATIVO
// ======================================================
function httpRequest(urlStr, { method = 'GET', headers = {}, body = null, mtls = null, timeout = 30000, jar = null } = {}) {
  return new Promise((resolve, reject) => {
    let url
    try { url = new URL(urlStr) } catch { return reject(new Error('URL inválida: ' + urlStr)) }

    const isHttps = url.protocol === 'https:'
    const lib = isHttps ? https : http

    const reqHeaders = { ...headers }
    
    // Atenção: NUNCA injetar 'Accept-Encoding: gzip' aqui, senão o Node recebe os HTMLs criptografados e quebra o Regex.
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
      rejectUnauthorized: false, // Fundamental para certificados convertidos funcionarem no endpoint Gov.br
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
        resolve({
          status: resp.statusCode,
          headers: resp.headers,
          location: resp.headers.location,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
    })

    reqH.on('error', reject)
    reqH.on('timeout', () => { reqH.destroy(); const e = new Error('Timeout'); e.code = 'ETIMEDOUT'; reject(e) })
    
    if (body) reqH.write(body)
    reqH.end()
  })
}

function tryParseJson(str) {
  try { return JSON.parse(str) } catch { return null }
}

function decodeHtmlEntities(str) {
  return String(str).replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#x2F;/g, '/')
}

// ======================================================
// LOGIN GOV.BR OAUTH2 (Navegador Simulado Impecável)
// ======================================================
async function loginGovBr(pfxBase64, password) {
  const mtls = await makePfxTls(pfxBase64, password)
  const jar = newCookieJar()
  
  // Headers disfarçados 100% como Google Chrome
  const headersGovBr = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"'
  }

  console.log('[LOGIN] Iniciando fluxo de SSO (OAuth2)...')
  
  const nonce = crypto.randomUUID()
  const state = crypto.randomUUID()
  const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`

  let currentUrl = authUrl;
  let loginPageHtml = '';
  let baseLoginUrl = '';

  // 1. LOOP DE IDA (Encontra a página de Login e dribla o WAF BIG-IP)
  for(let i = 0; i < 7; i++) {
     console.log(`[LOGIN-IDA] GET ${currentUrl.substring(0,80)}...`);
     const resp = await httpRequest(currentUrl, { method: 'GET', jar, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         continue;
     }

     if (resp.status === 200) {
         // Chegamos na tela de Login final
         if (currentUrl.includes('/login?client_id=')) {
             baseLoginUrl = currentUrl;
             loginPageHtml = resp.body;
             break;
         }
         
         // F5 BIG-IP WAF Detection (Challenge JS ou Meta Refresh)
         if (resp.body.includes('refresh') || resp.body.includes('reload') || resp.body.includes('TSPD_')) {
             console.log(`[WAF] Desafio detectado. Cookies absorvidos. Aguardando 1s para o próximo salto...`);
             await new Promise(r => setTimeout(r, 1000));
             
             const metaMatch = resp.body.match(/url\s*=\s*([^"'>]+)/i);
             if (metaMatch) {
                 let metaUrl = decodeHtmlEntities(metaMatch[1]);
                 currentUrl = metaUrl.startsWith('http') ? metaUrl : new URL(metaUrl, currentUrl).toString();
             }
             continue;
         }
         throw new Error(`Travou numa página desconhecida (HTTP 200). URL: ${currentUrl}`);
     }
     throw new Error(`Erro HTTP ${resp.status} em ${currentUrl}`);
  }

  if (!baseLoginUrl || !loginPageHtml) throw new Error('Falha ao chegar na página HTML de login do Gov.br');

  // 2. EXTRAIR O FORMULÁRIO DO CERTIFICADO E SEUS CAMPOS SECRETOS (Para evitar HTTP 400)
  let formHtml = loginPageHtml;
  const certFormRegex = /<form[^>]+action=["'][^"']*certificado\.sso\.acesso\.gov\.br[^"']*["'][^>]*>([\s\S]*?)<\/form>/i;
  const certFormMatch = loginPageHtml.match(certFormRegex);
  if (certFormMatch) {
      formHtml = certFormMatch[1];
  }

  const fields = {}
  const hiddenRegex = /<input[^>]+type=["']?hidden["']?[^>]*>/gi
  let m
  while ((m = hiddenRegex.exec(formHtml)) !== null) {
      const tag = m[0]
      const nameMatch = tag.match(/name=["']([^"']+)["']/i)
      const valueMatch = tag.match(/value=["']([^"']*)["']/i)
      if (nameMatch) {
          fields[nameMatch[1]] = valueMatch ? decodeHtmlEntities(valueMatch[1]) : ''
      }
  }

  const payload = querystring.stringify(fields)
  let urlLoginTls = baseLoginUrl.replace('sso.acesso.gov.br', 'certificado.sso.acesso.gov.br')

  console.log(`[LOGIN] Disparando POST mTLS (Certificado) -> ${urlLoginTls.substring(0, 80)}...`)

  const certHeaders = {
      ...headersGovBr,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://sso.acesso.gov.br',
      'Referer': baseLoginUrl,
      'Sec-Fetch-Site': 'same-site'
  }

  const respCert = await httpRequest(urlLoginTls, { method: 'POST', jar, mtls, headers: certHeaders, body: payload })

  if (respCert.status === 401) throw new Error('Certificado rejeitado pelo Gov.br (Erro 401).')
  if (respCert.status === 403) throw new Error('WAF Gov.br bloqueou a requisição mTLS (403).')
  if (respCert.status === 400) throw new Error(`Gov.br retornou 400 Bad Request. WAF suspeitou do formulário.`)
  if (!respCert.location) throw new Error(`Falha SSO: Sem redirecionamento mTLS. HTTP ${respCert.status}.`)

  // 3. LOOP DE VOLTA (Do Login mTLS até a resposta com o código do FGTS)
  currentUrl = respCert.location;
  let urlFgtsCode = '';

  for(let i = 0; i < 5; i++) {
     console.log(`[LOGIN-VOLTA] GET ${currentUrl.substring(0,80)}...`);
     const resp = await httpRequest(currentUrl, { method: 'GET', jar, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         continue;
     }

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

  // 4. ATIVAÇÃO INVISÍVEL (Token do Portal do FGTS Digital)
  console.log('[LOGIN] Gerando Token do FGTS Digital...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', {
    method: 'POST', jar, headers: headersApiFgts, body: JSON.stringify({})
  })

  console.log('[LOGIN] Acessando escolha de perfil...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', {
    method: 'GET', jar, headers: headersGovBr
  })

  console.log('[LOGIN] Sincronizando Cookies e Habilitando Acesso...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', {
    method: 'GET', jar, headers: headersApiFgts
  })

  console.log('[LOGIN] SESSÃO FGTS ESTABELECIDA COM SUCESSO! 🚀')
  return { jar, finalUrl: urlFgtsCode, mtls }
}

// ======================================================
// ROTA: DIAGNÓSTICO DE PFX
// ======================================================
app.post('/diag-pfx', requireApiKey, async (req, res) => {
  const { pfxBase64, password } = req.body
  const out = { nodeVersion: process.version, openssl: process.versions.openssl, passLen: (password || '').length }

  try { out.opensslBinario = (await execFileAsync('openssl', ['version'])).stdout.trim() } catch (e) { out.opensslBinario = { erro: e.message } }
  if (!pfxBase64) return res.status(400).json({ error: 'pfxBase64 ausente', ...out })

  const pfx = Buffer.from(pfxBase64, 'base64')
  out.pfxBytes = pfx.length
  let precisaConverter = false

  try { tls.createSecureContext({ pfx, passphrase: password || '' }); out.comSenha = 'OK ✅ (senha correta, PFX moderno)' } catch (e) {
    out.comSenha = { msg: e.message, code: e.code }; if (/unsupported|digital envelope|legacy/i.test(e.message || '')) precisaConverter = true
  }

  try { tls.createSecureContext({ pfx, passphrase: '' }); out.semSenha = 'OK (abre SEM senha)' } catch (e) { out.semSenha = { msg: e.message } }

  if (precisaConverter) {
    try {
      const converted = await convertLegacyPfx(pfx, password || '')
      tls.createSecureContext({ pfx: converted, passphrase: password || '' })
      out.conversaoLegacy = `OK ✅ (convertido para AES-256)`
    } catch (e) { out.conversaoLegacy = { erro: 'FALHOU', msg: e.stderr || e.message } }
  }
  res.json(out)
})

// ======================================================
// ROTA PRINCIPAL RPA: Extrato FGTS Digital
// ======================================================
app.post('/rpa/fgts/extrato', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password, payloadBusca } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    const { jar } = await loginGovBr(pfxBase64, password)

    // Montar ID do empregador (8 primeiros digitos do CNPJ + 1)
    const cnpjNum = cnpj.replace(/\D/g,'')
    const empId = `${cnpjNum.substring(0,8)}1`

    const headers = { 
      'Accept': 'application/json, text/plain, */*', 
      'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36' 
    }

    console.log(`[FGTS-RPA] Consultando dados para o Empregador ${empId}...`)

    const respUsuario = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/usuario', { method:'GET', jar, headers })
    const dadosUsuario = tryParseJson(respUsuario.body)

    let competencias = null;
    const respComp = await httpRequest(`https://fgtsdigital.sistema.gov.br/consignado/api/empregadores/${empId}/competencias`, { method:'GET', jar, headers })
    if (respComp.status === 200) competencias = tryParseJson(respComp.body)

    const bodyGuias = payloadBusca || {}
    const respLista = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/consultar-guias/guias', { method:'POST', jar, headers, body: JSON.stringify(bodyGuias) })
    const listaGuias = tryParseJson(respLista.body)
    const guiasArray = Array.isArray(listaGuias) ? listaGuias : (listaGuias?.content || listaGuias?.itens || [])

    const detalhes = []
    
    // Varre as Guias e Busca os Detalhes e Consignados
    // (Pode aumentar o slice caso a empresa tenha muitas guias)
    for (const g of guiasArray.slice(0, 5)) {
      const idGuia = g.id || g.idGuia || g.numeroGuia
      if (!idGuia) continue
      
      const respTot = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/totalizador`, { method:'GET', jar, headers })
      const respDeb = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/debitos?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })
      const respConsig = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/consignados?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })

      detalhes.push({ 
        guiaBase: g, 
        totalizador: tryParseJson(respTot.body), 
        debitos: tryParseJson(respDeb.body), 
        consignados: tryParseJson(respConsig.body) 
      })
    }

    console.log(`[FGTS-RPA] Extração concluída com sucesso! ${detalhes.length} guias extraídas.`)

    res.json({ 
      success: true, 
      usuario: dadosUsuario, 
      competencias: competencias, 
      guias: detalhes, 
      rawData: { listaGuias, detalhes } 
    })

  } catch(e) {
    if (e.pfxStage) {
      console.error(`[FGTS] Erro PFX:`, e.pfxStage, e.message)
      return res.status(400).json({ success: false, certError: e.pfxStage === 'PFX_INVALID', errorType: e.pfxStage, error: e.message })
    }
    const c = classifyError(e, 'FGTS')
    console.error(`[FGTS] Erro:`, c.code, c.raw)
    return res.status(200).json({ success: false, certError: false, errorType: c.errorType, stage: c.stage, error: c.message, rawError: c.raw })
  }
});

// ======================================================
// HEALTHCHECK
// ======================================================
app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))

// ======================================================
// START
// ======================================================
app.listen(PORT, () => console.log(`🚀 Bridge FGTS Digital RPA rodando na porta ${PORT}`))
