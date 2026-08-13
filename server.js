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
import zlib from 'node:zlib'

const execFileAsync = promisify(execFile)

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

// ======================================================
// CONFIGURAÇÃO
// ======================================================
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || '9c6c38a65f8052500b7d4c2aff0b87fa'
const FGTS_API_KEY = process.env.FGTS_API_KEY || '5341b41fa01513c5b3e23f6dc35b8e94'
const PORT = process.env.PORT || 3000

// ======================================================
// SEGURANÇA
// ======================================================
function apiKeyValida(recebida) {
  if (!recebida) return false
  try {
    const hashRecebido = crypto.createHash('sha256').update(String(recebida)).digest()
    const hashBridge = crypto.createHash('sha256').update(String(BRIDGE_API_KEY)).digest()
    const hashFgts = crypto.createHash('sha256').update(String(FGTS_API_KEY)).digest()
    return crypto.timingSafeEqual(hashRecebido, hashBridge) || crypto.timingSafeEqual(hashRecebido, hashFgts)
  } catch {
    return false
  }
}

function requireApiKey(req, res, next) {
  const recebida = req.headers['x-api-key'] || req.headers['fgts-api-key']
  if (!apiKeyValida(recebida)) {
    return res.status(403).json({ success: false, error: 'Acesso negado: Chave API inválida ou ausente.' })
  }
  next()
}

function classifyError(err, stage) {
  const code = err?.code || ''
  const msg = err?.message || String(err)
  if (/^Timeout:/i.test(msg) || code === 'ETIMEDOUT') return { errorType: 'TIMEOUT', stage, code: 'TIMEOUT', message: 'Timeout de conexão ao acessar Gov.br/FGTS.' }
  if (code.startsWith('ERR_TLS') || /handshake|alert|SSL routines/i.test(msg)) return { errorType: 'TLS_HANDSHAKE_ERROR', stage, code: code || 'TLS', message: 'Falha no handshake TLS (Certificado).' }
  return { errorType: 'BRIDGE_INTERNAL', stage, code: code || 'UNKNOWN', message: msg, raw: msg }
}

// ======================================================
// PFX E mTLS
// ======================================================
const pfxConvCache = new Map()

function pfxCacheKey(pfxBase64, password) {
  return crypto.createHash('sha256').update(pfxBase64.slice(0, 200) + '::' + pfxBase64.length + '::' + (password || '')).digest('hex')
}

async function convertLegacyPfx(pfxBuffer, password) {
  const tmp = os.tmpdir()
  const id = crypto.randomBytes(8).toString('hex')
  const inPfx = path.join(tmp, `in_${id}.pfx`)
  const pem = path.join(tmp, `mid_${id}.pem`)
  const outPfx = path.join(tmp, `out_${id}.pfx`)
  const pass = password || ''
  const cleanup = async () => Promise.allSettled([fs.unlink(inPfx), fs.unlink(pem), fs.unlink(outPfx)])

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

async function makePfxTls(pfxBase64, password) {
  if (!pfxBase64) { const e = new Error('Certificado ausente'); e.pfxStage = 'MISSING'; throw e }
  const pfx = Buffer.from(pfxBase64, 'base64')
  if (pfx.length < 500) { const e = new Error('PFX vazio'); e.pfxStage = 'TRUNCATED'; throw e }
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
        console.warn('[PFX] PFX legado detectado — convertendo para AES-256...')
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
    if (/mac verify|invalid password/i.test(msg)) { const e = new Error('Senha incorreta'); e.pfxStage = 'PFX_INVALID'; throw e }
    const e = new Error('Falha ao carregar cert: ' + msg); e.pfxStage = 'PFX_LOAD_ERROR'; throw e
  }
}

// ======================================================
// HTTP ENGINE & COOKIE JAR
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
        if (eqIdx !== -1) store.set(kv.slice(0, eqIdx).trim(), kv.slice(eqIdx + 1).trim());
      }
    },
    header() {
      return Array.from(store.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    }
  }
}

function httpRequest(urlStr, { method = 'GET', headers = {}, body = null, mtls = null, timeout = 30000, jar = null } = {}) {
  return new Promise((resolve, reject) => {
    let url
    try { url = new URL(urlStr) } catch { return reject(new Error('URL inválida: ' + urlStr)) }
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
      hostname: url.hostname, port: url.port || (isHttps ? 443 : 80), path: url.pathname + url.search,
      method, rejectUnauthorized: false, timeout, headers: reqHeaders,
    }
    
    if (mtls) { 
      opts.pfx = mtls.pfx; 
      opts.passphrase = mtls.passphrase; 
      opts.secureOptions = crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT; 
    }

    const reqH = lib.request(opts, (resp) => {
      const chunks = []
      resp.on('data', (c) => chunks.push(c))
      resp.on('end', () => {
        if (jar && resp.headers['set-cookie']) jar.set(resp.headers['set-cookie'])
        
        const buf = Buffer.concat(chunks)
        let bodyText = ''
        const encoding = resp.headers['content-encoding'] || ''
        
        try {
          // Descomprime GZIP/Deflate (Essencial para não cair na malha fina do WAF)
          if (encoding.includes('br')) bodyText = zlib.brotliDecompressSync(buf).toString('utf8')
          else if (encoding.includes('gzip')) bodyText = zlib.gunzipSync(buf).toString('utf8')
          else if (encoding.includes('deflate')) bodyText = zlib.inflateSync(buf).toString('utf8')
          else bodyText = buf.toString('utf8')
        } catch (e) {
          bodyText = buf.toString('utf8')
        }
        resolve({ status: resp.statusCode, headers: resp.headers, location: resp.headers.location, body: bodyText })
      })
    })
    reqH.on('error', reject)
    reqH.on('timeout', () => { reqH.destroy(); const e = new Error('Timeout'); e.code = 'ETIMEDOUT'; reject(e) })
    if (body) reqH.write(body)
    reqH.end()
  })
}

function tryParseJson(str) { try { return JSON.parse(str) } catch { return null } }
function decodeHtmlEntities(str) { return String(str).replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#x2F;/g, '/') }

// ======================================================
// LOGIN GOV.BR OAUTH2 (Híbrido: Ida cookies -> mTLS API)
// ======================================================
async function loginGovBr(pfxBase64, password) {
  const mtls = await makePfxTls(pfxBase64, password)
  const jar = newCookieJar()
  
  // Headers camuflados perfeitamente (usando gzip/deflate para HTTP/1.1)
  const headersGovBr = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate', 
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
  }

  const nonce = crypto.randomUUID()
  const state = crypto.randomUUID()
  
  // URL raiz do SSO (Domínio principal)
  const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`

  console.log('[LOGIN] Fase 1: Entrando no SSO principal para absorver cookies do F5 WAF...')
  
  let currentUrl = authUrl;

  // ==========================================================
  // 1. IDA (Pegar os Cookies de Segurança TS01)
  // ==========================================================
  for(let i = 0; i < 5; i++) {
     console.log(`[LOGIN-IDA] GET ${currentUrl.substring(0,80)}...`);
     const resp = await httpRequest(currentUrl, { method: 'GET', jar, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         headersGovBr['Sec-Fetch-Site'] = 'same-site';
         continue;
     }

     if (resp.status === 200) {
         if (resp.body.includes('refresh') || resp.body.includes('TSPD_')) {
             console.log(`[WAF] Challenge recebido na Ida. Absorvendo...`);
             await new Promise(r => setTimeout(r, 1000));
             const metaMatch = resp.body.match(/url\s*=\s*([^"'>]+)/i) || 
                               resp.body.match(/window\.location\.href\s*=\s*["']([^"']+)["']/i) ||
                               resp.body.match(/location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i);
             if (metaMatch) {
                 let metaUrl = decodeHtmlEntities(metaMatch[1]);
                 currentUrl = metaUrl.startsWith('http') ? metaUrl : new URL(metaUrl, currentUrl).toString();
             }
             continue;
         }
         // Se chegou aqui (HTTP 200 limpo), passou pelo WAF da Ida com sucesso!
         break;
     }
     throw new Error(`Erro HTTP ${resp.status} em ${currentUrl}`);
  }

  // ==========================================================
  // 2. MTLS API: Vamos direto pro /authorize com os cookies coletados
  // ==========================================================
  console.log(`[LOGIN] Fase 2: Cookies coletados! Iniciando mTLS direto com a API...`);
  
  // Pegamos a MESMA URL que iniciamos e mudamos pro subdomínio do certificado
  const certUrl = authUrl.replace('sso.acesso.gov.br', 'certificado.sso.acesso.gov.br');
  currentUrl = certUrl;
  let urlFgtsCode = '';

  for(let i = 0; i < 6; i++) {
     console.log(`[LOGIN-mTLS] GET ${currentUrl.substring(0, 80)}...`);
     
     // Sempre envia o Certificado quando estiver no domínio certificado.sso
     const isCertDomain = currentUrl.includes('certificado.sso');
     const reqMtls = isCertDomain ? mtls : null;

     const resp = await httpRequest(currentUrl, { method: 'GET', jar, mtls: reqMtls, headers: headersGovBr });

     if (resp.status >= 300 && resp.status < 400 && resp.location) {
         currentUrl = resp.location.startsWith('http') ? resp.location : new URL(resp.location, currentUrl).toString();
         continue;
     }

     if (resp.status === 200) {
         // Chegamos na tela final de sucesso do FGTS Digital?
         if (currentUrl.includes('code=') || currentUrl.includes('acessogov')) {
             urlFgtsCode = currentUrl;
             break;
         }

         // Se o subdomínio tiver um WAF próprio
         if (resp.body.includes('refresh') || resp.body.includes('TSPD_')) {
             console.log(`[WAF] Challenge recebido no Certificado. Absorvendo...`);
             await new Promise(r => setTimeout(r, 1000));
             const metaMatch = resp.body.match(/url\s*=\s*([^"'>]+)/i) || 
                               resp.body.match(/window\.location\.href\s*=\s*["']([^"']+)["']/i) ||
                               resp.body.match(/location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i);
             if (metaMatch) {
                 let metaUrl = decodeHtmlEntities(metaMatch[1]);
                 currentUrl = metaUrl.startsWith('http') ? metaUrl : new URL(metaUrl, currentUrl).toString();
             }
             continue;
         }

         console.error(`[DEBUG mTLS] HTML Inesperado (O certificado falhou silenciosamente):`, resp.body.substring(0, 500));
         throw new Error(`Falha mTLS: Gov.br retornou HTML 200 em vez do código de acesso. O Certificado pode estar revogado ou sem permissão.`);
     }

     if (resp.status === 401) throw new Error('Certificado rejeitado pelo Gov.br (Erro 401). Verifique validade e senha.');
     if (resp.status === 403) throw new Error('WAF Gov.br bloqueou a requisição mTLS (403). Falha no cookie ou IP barrado.');
     if (resp.status === 400) throw new Error(`Gov.br retornou 400 Bad Request no mTLS.`);

     throw new Error(`Erro HTTP ${resp.status} na URL: ${currentUrl}`);
  }

  if (!urlFgtsCode) throw new Error('Falha no SSO: Não chegou na página do FGTS Digital com o CODE.');

  // ==========================================================
  // 3. CHAMADAS INTERNAS DA API FGTS
  // ==========================================================
  const headersApiFgts = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'User-Agent': headersGovBr['User-Agent'],
      'Referer': urlFgtsCode
  }

  console.log('[LOGIN] Gerando Token do FGTS Digital...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', { method: 'POST', jar, headers: headersApiFgts, body: JSON.stringify({}) })
  
  console.log('[LOGIN] Acessando escolha de perfil...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', { method: 'GET', jar, headers: headersGovBr })
  
  console.log('[LOGIN] Sincronizando Cookies e Habilitando Acesso...')
  await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', { method: 'GET', jar, headers: headersApiFgts })

  console.log('[LOGIN] SESSÃO FGTS ESTABELECIDA COM SUCESSO! 🚀')
  return { jar, finalUrl: urlFgtsCode, mtls }
}

// ======================================================
// ROTA PRINCIPAL RPA: Extrato FGTS Digital
// ======================================================
app.post('/rpa/fgts/extrato', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password, payloadBusca } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    const { jar } = await loginGovBr(pfxBase64, password)

    const cnpjNum = cnpj.replace(/\D/g,'')
    const empId = `${cnpjNum.substring(0,8)}1`
    const headers = { 
      'Accept': 'application/json, text/plain, */*', 
      'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' 
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
    
    for (const g of guiasArray.slice(0, 5)) {
      const idGuia = g.id || g.idGuia || g.numeroGuia
      if (!idGuia) continue
      
      const respTot = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/totalizador`, { method:'GET', jar, headers })
      const respDeb = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/debitos?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })
      const respConsig = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/consignados?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers })

      detalhes.push({ guiaBase: g, totalizador: tryParseJson(respTot.body), debitos: tryParseJson(respDeb.body), consignados: tryParseJson(respConsig.body) })
    }

    console.log(`[FGTS-RPA] Extração concluída com sucesso! ${detalhes.length} guias extraídas.`)

    res.json({ success: true, usuario: dadosUsuario, competencias: competencias, guias: detalhes, rawData: { listaGuias, detalhes } })

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

app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))
app.listen(PORT, () => console.log(`🚀 Bridge FGTS Digital RPA rodando na porta ${PORT}`))
