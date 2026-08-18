import express from 'express'
import cors from 'cors'
import crypto from 'node:crypto'
import dns from 'node:dns'
import https from 'node:https'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { execSync } from 'node:child_process'
import { chromium } from 'playwright'

// Resolve DNS de IPv6 do Cloud Run
dns.setDefaultResultOrder('ipv4first'); 

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || '9c6c38a65f8052500b7d4c2aff0b87fa'
const FGTS_API_KEY = process.env.FGTS_API_KEY || '5341b41fa01513c5b3e23f6dc35b8e94'
const PORT = process.env.PORT || 10000 

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
  let recebida = req.headers['x-api-key'] || req.headers['fgts-api-key'] || req.headers['authorization'];
  if (recebida && recebida.startsWith('Bearer ')) recebida = recebida.replace('Bearer ', '');
  if (!apiKeyValida(recebida)) return res.status(403).json({ success: false, error: 'Acesso negado.' });
  next()
}

function classifyError(err, stage) {
  const code = err?.code || ''
  const msg = err?.message || String(err)
  if (/^Timeout:/i.test(msg) || code === 'ETIMEDOUT') return { errorType: 'TIMEOUT', stage, code: 'TIMEOUT', message: 'Timeout de conexão com o Governo.' }
  return { errorType: 'BRIDGE_INTERNAL', stage, code: code || 'UNKNOWN', message: msg }
}

function tryParseJson(str) { try { return JSON.parse(str); } catch { return str; } }

function newCookieJar() {
  return {
    cookies: new Map(),
    set(cookieArray) {
      cookieArray.forEach(c => {
        if (!c) return;
        const [nameValue] = c.split(';');
        const [name, ...valParts] = nameValue.split('=');
        if (name && valParts) this.cookies.set(name.trim(), valParts.join('='));
      });
    },
    getCookieString() {
      let str = '';
      for (const [name, value] of this.cookies.entries()) str += `${name}=${value}; `;
      return str;
    },
    extractFromResponse(headers) {
      const setCookie = headers.getSetCookie ? headers.getSetCookie() : [];
      this.set(Array.isArray(setCookie) ? setCookie : [setCookie]);
    }
  };
}

async function httpRequest(url, options) {
  const fetchOpts = { method: options.method || 'GET', headers: { ...options.headers } };
  if (options.jar) fetchOpts.headers['Cookie'] = options.jar.getCookieString();
  if (options.body) fetchOpts.body = options.body;
  const response = await fetch(url, fetchOpts);
  if (options.jar) options.jar.extractFromResponse(response.headers);
  const text = await response.text();
  return { status: response.status, headers: response.headers, body: text };
}

// ======================================================
// EXTRAÇÃO DE PEM VIA OPENSSL (BYPASS NO NODE 18/20 PFX)
// ======================================================
async function convertPfxToPem(pfxBase64, password) {
  const buf = Buffer.from(pfxBase64, 'base64');
  const tmpDir = os.tmpdir();
  const uuid = crypto.randomUUID();
  const inPath = path.join(tmpDir, `in_${uuid}.pfx`);
  const certPath = path.join(tmpDir, `cert_${uuid}.pem`);
  const keyPath = path.join(tmpDir, `key_${uuid}.pem`);
  const passPath = path.join(tmpDir, `pass_${uuid}.txt`);
  
  await fs.writeFile(inPath, buf);
  await fs.writeFile(passPath, password);
  
  try {
      console.log('[LOGIN] Convertendo PFX legado para PEM via OpenSSL...');
      try {
          // 1. Tenta forçar os providers legacy do OpenSSL 3.0+ (Ubuntu 22/Debian 12)
          // Isso resolve o erro "error:0308010C:digital envelope routines::unsupported" (RC2-40-CBC)
          execSync(`openssl pkcs12 -legacy -provider default -provider legacy -in "${inPath}" -clcerts -nokeys -out "${certPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
          execSync(`openssl pkcs12 -legacy -provider default -provider legacy -in "${inPath}" -nocerts -nodes -out "${keyPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
      } catch (err) {
          // 2. Se falhar, tenta o comando padrão (OpenSSL 1.1 antigo ou versões sem suporte explícito a providers via CLI)
          execSync(`openssl pkcs12 -in "${inPath}" -clcerts -nokeys -out "${certPath}" -passin file:"${passPath}"`);
          execSync(`openssl pkcs12 -in "${inPath}" -nocerts -nodes -out "${keyPath}" -passin file:"${passPath}"`);
      }
      
      const cert = await fs.readFile(certPath, 'utf8');
      const key = await fs.readFile(keyPath, 'utf8');
      
      return { cert, key };
  } catch (err) {
      console.error('[LOGIN-ERRO-SSL]', err.message);
      throw new Error(`Falha ao converter certificado: A senha está incorreta, o arquivo está corrompido, ou falha de criptografia RC2-40-CBC.`);
  } finally {
      // Limpeza de arquivos sensíveis
      await Promise.all([
          fs.unlink(inPath).catch(()=>{}),
          fs.unlink(certPath).catch(()=>{}),
          fs.unlink(keyPath).catch(()=>{}),
          fs.unlink(passPath).catch(()=>{})
      ]);
  }
}

// ======================================================
// MOTOR mTLS NATIVO DO NODE.JS (COM CERTIFICADO PURO)
// ======================================================
async function executeMtlsHandshake(url, certPem, keyPem, playwrightCookies) {
  console.log(`[LOGIN] Disparando Handshake mTLS Nativo para: ${url.substring(0, 70)}...`);
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const cookieStr = playwrightCookies.map(c => `${c.name}=${c.value}`).join('; ');

    const options = {
      hostname: u.hostname,
      port: 443,
      path: u.pathname + u.search,
      method: 'GET',
      cert: certPem, // Passando o texto puro do Certificado
      key: keyPem,   // Passando o texto puro da Chave
      rejectUnauthorized: false,
      secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
      headers: {
        'Cookie': cookieStr,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Referer': 'https://sso.acesso.gov.br/'
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        console.log(`[LOGIN] Resposta mTLS Nativa - Status: ${res.statusCode}`);
        const location = res.headers.location;
        const setCookies = res.headers['set-cookie'] || [];
        
        if (res.statusCode >= 300 && res.statusCode < 400 && location) {
           resolve({ success: true, location, setCookies });
        } else {
           if (body.includes('acesso.gov.br/info/x509') || body.includes('Revogado')) {
               const e = new Error('Certificado Rejeitado/Revogado pelo Gov.br.');
               e.pfxStage = 'PFX_INVALID';
               reject(e);
           } else {
               reject(new Error(`Falha no mTLS nativo. Status: ${res.statusCode}.`));
           }
        }
      });
    });
    
    req.on('error', (err) => reject(new Error(`Falha de rede no mTLS: ${err.message}`)));
    req.end();
  });
}

// ======================================================
// ESTRATÉGIA HÍBRIDA
// ======================================================
async function loginGovBr(pfxBase64, password) {
  console.log('[LOGIN] Iniciando motor híbrido (WAF Bypass)...');
  
  let browser;
  let page; 

  try {
    browser = await chromium.launchPersistentContext('', {
      headless: true,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      args: [
        '--no-sandbox', 
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage', 
        '--disable-gpu',
        '--disable-blink-features=AutomationControlled'
      ], 
      ignoreHTTPSErrors: true
    });
    
    page = browser.pages()[0] || await browser.newPage();

    console.log('[LOGIN] Passo 1: Acessando Autorização Gov.br para gerar sessão...');
    const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${crypto.randomUUID()}&state=${crypto.randomUUID()}`;

    await page.goto(authUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.waitForURL(/authorization_id=/, { timeout: 15000 }).catch(() => {});
    
    const authUrlAtual = new URL(page.url());
    const authId = authUrlAtual.searchParams.get('authorization_id');
    const cId = authUrlAtual.searchParams.get('client_id');

    if (!authId || !cId) throw new Error(`Não capturou authorization_id do SSO. URL: ${page.url()}`);

    console.log(`[LOGIN] Passo 2: Sessão capturada! Pausando navegador e assumindo Node.js...`);
    const certUrl = `https://certificado.sso.acesso.gov.br/login?client_id=${cId}&authorization_id=${authId}`;
    const pwCookies = await browser.cookies();
    
    // NOVIDADE AQUI: Usa a função OpenSSL para quebrar o PFX em PEM (livrando o Node 18 do erro)
    const { cert, key } = await convertPfxToPem(pfxBase64, password);
    const mtlsResult = await executeMtlsHandshake(certUrl, cert, key, pwCookies);
    
    if (mtlsResult.setCookies && mtlsResult.setCookies.length > 0) {
        const cookiesToInject = mtlsResult.setCookies.map(cookieStr => {
            const [nameValue] = cookieStr.split(';');
            const [name, ...valParts] = nameValue.split('=');
            return { name: name.trim(), value: valParts.join('=').trim(), domain: '.acesso.gov.br', path: '/', secure: true };
        });
        await browser.addCookies(cookiesToInject);
    }

    console.log(`[LOGIN] Passo 3: Sucesso! Devolvendo fluxo ao Playwright na rota de autorização.`);
    await page.goto(mtlsResult.location, { waitUntil: 'domcontentloaded', timeout: 30000 });

    console.log('[LOGIN] Passo 4: Aguardando o redirect final da aplicação FGTS Digital...');
    await page.waitForURL(url => {
        const href = url.href;
        return href.includes('fgtsdigital.sistema.gov.br/portal/acessogov?code=') || href.includes('acesso.gov.br/info/x509/');
    }, { timeout: 45000 });

    if (page.url().includes('acesso.gov.br/info/x509/')) {
        const e = new Error(`Certificado inválido ou revogado pelo Governo. URL: ${page.url()}`);
        e.pfxStage = 'PFX_INVALID';
        throw e;
    }
    
    const urlFgtsCode = page.url();
    console.log('[LOGIN] SUCESSO EXTREMO! Código de acesso obtido!');

    const finalCookies = await browser.cookies();
    const jar = newCookieJar();
    jar.set(finalCookies.map(c => `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path}`));

    await browser.close();
    
    console.log('[LOGIN] Trocando o Código pelo Token JWT...');
    const fgtsUrlObj = new URL(urlFgtsCode);
    const headersApiFgts = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
        'Referer': urlFgtsCode,
        'Origin': 'https://fgtsdigital.sistema.gov.br'
    };

    const payloadToken = JSON.stringify({ code: fgtsUrlObj.searchParams.get('code'), state: fgtsUrlObj.searchParams.get('state') });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', { method: 'POST', jar, headers: headersApiFgts, body: payloadToken });
    
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', { method: 'GET', jar, headers: headersApiFgts });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', { method: 'GET', jar, headers: headersApiFgts });

    return { jar, finalUrl: urlFgtsCode, headersApiFgts };

  } catch (error) {
    console.error('[LOGIN-ERRO]', error.message);
    if (browser) await browser.close().catch(() => {});
    throw error;
  }
}

// ======================================================
// ROTAS E SERVIDOR API
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

app.post('/rpa/fgts/empregados', requireApiKey, async (req, res) => {
  const { cnpj, pfxBase64, password } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })

  try {
    const { jar, headersApiFgts } = await loginGovBr(pfxBase64, password)
    console.log(`[FGTS-RPA] Extraindo Vínculos para o CNPJ ${cnpj}...`)

    const statuses = ['ativo', 'afastado', 'desligado']
    const todosEmpregados = []
    
    for (const st of statuses) {
        const urlVinculos = `https://fgtsdigital.sistema.gov.br/extrato/api/vinculos/${st}/,,,,0,0?num-pagina=1&tam-pagina=1000&campo-ordem=nmTrabalhador&ordem=asc`
        const resp = await httpRequest(urlVinculos, { method: 'GET', jar, headers: headersApiFgts })
        if (resp.status === 200) {
            const dados = tryParseJson(resp.body)
            const lista = dados?.content || dados?.itens || dados || []
            if (Array.isArray(lista)) lista.forEach(emp => { emp.statusSistema = st; todosEmpregados.push(emp); })
        }
    }
    res.json({ success: true, total: todosEmpregados.length, empregados: todosEmpregados })

  } catch(e) {
    const c = classifyError(e, 'FGTS')
    res.status(200).json({ success: false, certError: e.pfxStage === 'PFX_INVALID', errorType: c.errorType, stage: c.stage, error: c.message })
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Bridge FGTS Digital RPA rodando na porta ${PORT} (0.0.0.0)`))
