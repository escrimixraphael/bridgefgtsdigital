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
import { chromium } from 'playwright'

const execFileAsync = promisify(execFile)

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

// ======================================================
// CONFIGURAÇÃO E SEGURANÇA
// ======================================================
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || '9c6c38a65f8052500b7d4c2aff0b87fa'
const FGTS_API_KEY = process.env.FGTS_API_KEY || '5341b41fa01513c5b3e23f6dc35b8e94'
const PORT = process.env.PORT || 3000

function apiKeyValida(recebida) {
  if (!recebida) return false
  try {
    const hashRecebido = crypto.createHash('sha256').update(String(recebida)).digest()
    const hashBridge = crypto.createHash('sha256').update(String(BRIDGE_API_KEY)).digest()
    const hashFgts = crypto.createHash('sha256').update(String(FGTS_API_KEY)).digest()
    return crypto.timingSafeEqual(hashRecebido, hashBridge) || crypto.timingSafeEqual(hashRecebido, hashFgts)
  } catch { return false }
}

function requireApiKey(req, res, next) {
  const recebida = req.headers['x-api-key'] || req.headers['fgts-api-key']
  if (!apiKeyValida(recebida)) return res.status(403).json({ success: false, error: 'Acesso negado: Chave API inválida.' })
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
// HTTP ENGINE & COOKIE JAR (PARA ROTAS FGTS)
// ======================================================
function newCookieJar() {
  const store = new Map()
  return {
    set(setCookieHeaders = []) {
      if (!setCookieHeaders) return;
      if (!Array.isArray(setCookieHeaders)) setCookieHeaders = [setCookieHeaders];
      for (const header of setCookieHeaders) {
        if (!header) continue;
        const cookiePart = header.split(';')[0].trim();
        const eqIdx = cookiePart.indexOf('=');
        if (eqIdx !== -1) {
          const k = cookiePart.slice(0, eqIdx).trim();
          const v = cookiePart.slice(eqIdx + 1).trim();
          store.set(k, v);
        }
      }
    },
    header() {
      return Array.from(store.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    }
  }
}

function httpRequest(urlStr, { method = 'GET', headers = {}, body = null, timeout = 30000, jar = null } = {}) {
  return new Promise((resolve, reject) => {
    let url; try { url = new URL(urlStr) } catch { return reject(new Error('URL inválida: ' + urlStr)) }
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

    const opts = { hostname: url.hostname, port: url.port || (isHttps ? 443 : 80), path: url.pathname + url.search, method, timeout, headers: reqHeaders }
    
    if (isHttps) {
        opts.rejectUnauthorized = false;
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
          if (encoding.includes('br')) bodyText = zlib.brotliDecompressSync(buf).toString('utf8')
          else if (encoding.includes('gzip')) bodyText = zlib.gunzipSync(buf).toString('utf8')
          else if (encoding.includes('deflate')) bodyText = zlib.inflateSync(buf).toString('utf8')
          else bodyText = buf.toString('utf8')
        } catch (e) { bodyText = buf.toString('utf8') }
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

// ======================================================
// LOGIN GOV.BR E FGTS DIGITAL (VIA PLAYWRIGHT - BYPASS WAF)
// ======================================================
async function loginGovBr(pfxBase64, password) {
  console.log('[LOGIN] Iniciando motor blindado (Playwright) para bypass do WAF...');

  // 1. Salva o PFX temporariamente para o Playwright conseguir ler
  const tmpDir = os.tmpdir();
  const certId = crypto.randomUUID();
  const certPath = path.join(tmpDir, `cert_${certId}.pfx`);
  
  let browser;

  try {
    await fs.writeFile(certPath, Buffer.from(pfxBase64, 'base64'));

    // 2. Abre o navegador invisível injetando o certificado mTLS
    browser = await chromium.launchPersistentContext('', {
      headless: true, // Roda em background
      args: ['--no-sandbox', '--disable-blink-features=AutomationControlled'], 
      ignoreHTTPSErrors: true,
      clientCertificates: [{
        origin: 'https://*.gov.br',
        pfxPath: certPath,
        passphrase: password || ''
      }]
    });

    const page = browser.pages()[0] || await browser.newPage();

    // 3. FASE 1: Entrando no SSO (Playwright resolve o JS e o WAF automaticamente)
    console.log('[LOGIN] Acessando URL de autorização Gov.br...');
    const nonce = crypto.randomUUID();
    const state = crypto.randomUUID();
    const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`;

    await page.goto(authUrl, { waitUntil: 'networkidle' });

    // 4. FASE 2: Clicar no certificado (O mTLS ocorre nativamente pelo Playwright)
    console.log('[LOGIN] Clicando em "Seu certificado digital"...');
    await page.locator('button:has-text("Seu certificado digital"), a:has-text("Seu certificado digital"), [data-sso-type="certificate"]').first().click();

    // 5. FASE 3: Aguardando o retorno para o FGTS Digital com o CODE
    console.log('[LOGIN] Aguardando validação do Governo e redirecionamento...');
    await page.waitForURL('**/fgtsdigital.sistema.gov.br/portal/acessogov?code=**', { timeout: 60000 });
    
    const urlFgtsCode = page.url();
    console.log('[LOGIN] Sucesso! Capturamos o CODE de autorização.');

    // 6. Extraindo os cookies "humanos" que o Chrome validou para o nosso backend HTTP
    const playwrightCookies = await browser.cookies();
    const jar = newCookieJar();
    const setCookieArray = playwrightCookies.map(c => `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path}`);
    jar.set(setCookieArray);

    // ================= FIM DA ATUAÇÃO DO PLAYWRIGHT =================
    await browser.close();
    await fs.unlink(certPath).catch(() => {}); // Limpa o cert temporário
    
    // 7. FASE 4: Trocando o Código pelo Token JWT usando o seu motor HTTP (rápido!)
    console.log('[LOGIN] Trocando o Código pelo Token JWT no backend HTTP...');
    
    const fgtsUrlObj = new URL(urlFgtsCode);
    const fgtsCode = fgtsUrlObj.searchParams.get('code');
    const fgtsState = fgtsUrlObj.searchParams.get('state');

    const headersApiFgts = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'Referer': urlFgtsCode,
        'Origin': 'https://fgtsdigital.sistema.gov.br'
    };

    const payloadToken = JSON.stringify({ code: fgtsCode, state: fgtsState });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', { method: 'POST', jar, headers: headersApiFgts, body: payloadToken });
    
    console.log('[LOGIN] Habilitando Acesso e Sincronizando Perfil...');
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', { method: 'GET', jar, headers: headersApiFgts });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', { method: 'GET', jar, headers: headersApiFgts });

    console.log('[LOGIN] SESSÃO FGTS ESTABELECIDA COM SUCESSO! 🚀');
    
    return { jar, finalUrl: urlFgtsCode, headersApiFgts };

  } catch (error) {
    console.error('[LOGIN-ERRO]', error);
    if (browser) await browser.close().catch(() => {});
    await fs.unlink(certPath).catch(() => {});
    throw error;
  }
}

// ======================================================
// ROTA 1: Extrato FGTS Digital (Guias e Valores)
// ======================================================
app.post('/rpa/fgts/extrato', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password, payloadBusca } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    const { jar, headersApiFgts } = await loginGovBr(pfxBase64, password)

    const cnpjNum = cnpj.replace(/\D/g,'')
    const empId = `${cnpjNum.substring(0,8)}1`
    
    console.log(`[FGTS-RPA] Consultando guias para o Empregador ${empId}...`)

    const respUsuario = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/usuario', { method:'GET', jar, headers: headersApiFgts })
    const dadosUsuario = tryParseJson(respUsuario.body)

    let competencias = null;
    const respComp = await httpRequest(`https://fgtsdigital.sistema.gov.br/consignado/api/empregadores/${empId}/competencias`, { method:'GET', jar, headers: headersApiFgts })
    if (respComp.status === 200) competencias = tryParseJson(respComp.body)

    const bodyGuias = payloadBusca || {}
    const respLista = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/consultar-guias/guias', { method:'POST', jar, headers: headersApiFgts, body: JSON.stringify(bodyGuias) })
    const listaGuias = tryParseJson(respLista.body)
    const guiasArray = Array.isArray(listaGuias) ? listaGuias : (listaGuias?.content || listaGuias?.itens || [])

    const detalhes = []
    
    for (const g of guiasArray.slice(0, 5)) {
      const idGuia = g.id || g.idGuia || g.numeroGuia
      if (!idGuia) continue
      
      const respTot = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/totalizador`, { method:'GET', jar, headers: headersApiFgts })
      const respDeb = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/debitos?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers: headersApiFgts })
      const respConsig = await httpRequest(`https://fgtsdigital.sistema.gov.br/cobranca/api/guia/${idGuia}/consignados?num-pagina=1&tam-pagina=100&campo-ordem=competenciaApuracao&ordem=desc`, { method:'GET', jar, headers: headersApiFgts })

      detalhes.push({ guiaBase: g, totalizador: tryParseJson(respTot.body), debitos: tryParseJson(respDeb.body), consignados: tryParseJson(respConsig.body) })
    }

    res.json({ success: true, usuario: dadosUsuario, competencias: competencias, guias: detalhes })

  } catch(e) {
    const c = classifyError(e, 'FGTS')
    res.status(200).json({ success: false, certError: e.pfxStage === 'PFX_INVALID', errorType: c.errorType, stage: c.stage, error: c.message })
  }
});

// ======================================================
// ROTA 2: Empregados e Vínculos (Ativos, Afastados, Desligados)
// ======================================================
app.post('/rpa/fgts/empregados', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    const { jar, headersApiFgts } = await loginGovBr(pfxBase64, password)
    
    console.log(`[FGTS-RPA] Extraindo Vínculos de Funcionários para o CNPJ ${cnpj}...`)

    const statuses = ['ativo', 'afastado', 'desligado']
    const todosEmpregados = []
    
    for (const st of statuses) {
        const urlVinculos = `https://fgtsdigital.sistema.gov.br/extrato/api/vinculos/${st}/,,,,0,0?num-pagina=1&tam-pagina=1000&campo-ordem=nmTrabalhador&ordem=asc`
        const resp = await httpRequest(urlVinculos, { method: 'GET', jar, headers: headersApiFgts })
        
        if (resp.status === 200) {
            const dados = tryParseJson(resp.body)
            const lista = dados?.content || dados?.itens || dados || []
            
            if (Array.isArray(lista)) {
                lista.forEach(emp => {
                    emp.statusSistema = st
                    todosEmpregados.push(emp)
                })
            }
        }
    }

    console.log(`[FGTS-RPA] Extração concluída! Total de empregados encontrados: ${todosEmpregados.length}`)

    res.json({ success: true, total: todosEmpregados.length, empregados: todosEmpregados })

  } catch(e) {
    const c = classifyError(e, 'FGTS')
    res.status(200).json({ success: false, certError: e.pfxStage === 'PFX_INVALID', errorType: c.errorType, stage: c.stage, error: c.message })
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))
app.listen(PORT, () => console.log(`🚀 Bridge FGTS Digital RPA rodando na porta ${PORT}`))
