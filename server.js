import express from 'express'
import cors from 'cors'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'
import { execSync } from 'node:child_process'
import dns from 'node:dns'
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
  if (!apiKeyValida(recebida)) return res.status(403).json({ success: false, error: 'Acesso negado: Chave API inválida.' });
  next()
}

function classifyError(err, stage) {
  const code = err?.code || ''
  const msg = err?.message || String(err)
  if (/^Timeout:/i.test(msg) || code === 'ETIMEDOUT') return { errorType: 'TIMEOUT', stage, code: 'TIMEOUT', message: 'Timeout de conexão.' }
  return { errorType: 'BRIDGE_INTERNAL', stage, code: code || 'UNKNOWN', message: msg }
}

function tryParseJson(str) {
  try { return JSON.parse(str); } catch (e) { return str; }
}

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
// NOVO ALGORITMO: EXTRAÇÃO PARA PEM (CERTIFICADO E CHAVE)
// ======================================================
async function makePemTls(pfxBase64, password) {
  const pfxBuffer = Buffer.from(pfxBase64, 'base64');
  console.log('[LOGIN] Extraindo certificado e chave privada para o formato PEM puro...');
  
  const tmpDir = os.tmpdir();
  const tmpId = crypto.randomUUID();
  const inPath = path.join(tmpDir, `in_${tmpId}.pfx`);
  const certPath = path.join(tmpDir, `cert_${tmpId}.pem`);
  const keyPath = path.join(tmpDir, `key_${tmpId}.pem`);
  const passPath = path.join(tmpDir, `pass_${tmpId}.txt`);
  
  try {
    await fs.writeFile(inPath, pfxBuffer);
    await fs.writeFile(passPath, password);
    
    // O parâmetro -nodes remove a criptografia da chave, garantindo que o NodeJS leia 100% liso
    try {
      execSync(`openssl pkcs12 -in "${inPath}" -clcerts -nokeys -out "${certPath}" -legacy -passin file:"${passPath}"`, { stdio: 'pipe' });
      execSync(`openssl pkcs12 -in "${inPath}" -nocerts -nodes -out "${keyPath}" -legacy -passin file:"${passPath}"`, { stdio: 'pipe' });
    } catch (e1) {
      console.log('[LOGIN] Fallback: Tentando extração via padrão OpenSSL 3...');
      execSync(`openssl pkcs12 -in "${inPath}" -clcerts -nokeys -out "${certPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
      execSync(`openssl pkcs12 -in "${inPath}" -nocerts -nodes -out "${keyPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
    }
    
    console.log('[LOGIN] Sucesso absoluto! PEM extraído e pronto para injeção mTLS.');
    return { inPath, certPath, keyPath, passPath };
    
  } catch (err) {
    const linuxError = err.stderr ? err.stderr.toString() : err.message;
    console.error('[LOGIN-ERRO] Falha crítica na extração PEM:', linuxError);
    await Promise.all([fs.unlink(inPath).catch(()=>{}), fs.unlink(certPath).catch(()=>{}), fs.unlink(keyPath).catch(()=>{}), fs.unlink(passPath).catch(()=>{})]);
    throw new Error(`Falha ao ler certificado digital. Verifique a senha ou validade.`);
  }
}

// ======================================================
// MOTOR DE LOGIN COM WAF BYPASS E HTTP/2 DISABLED
// ======================================================
async function loginGovBr(pfxBase64, password) {
  console.log('[LOGIN] Iniciando motor blindado (Playwright) para bypass do WAF...');

  let browser;
  let page; 
  let mtls = null;

  const cleanupMtls = async () => {
    if (mtls) {
      await Promise.all([
        fs.unlink(mtls.inPath).catch(()=>{}),
        fs.unlink(mtls.certPath).catch(()=>{}),
        fs.unlink(mtls.keyPath).catch(()=>{}),
        fs.unlink(mtls.passPath).catch(()=>{})
      ]);
    }
  };

  try {
    mtls = await makePemTls(pfxBase64, password);

    console.log('[LOGIN] Solicitando abertura do motor Chromium no Linux...');
    
    browser = await chromium.launchPersistentContext('', {
      headless: true,
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      args: [
        '--no-sandbox', 
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage', 
        '--disable-gpu',
        '--disable-blink-features=AutomationControlled',
        '--disable-http2' // A CORREÇÃO DE OURO: Mata o bug de ALPN (HTTP/2) do Playwright Proxy
      ], 
      ignoreHTTPSErrors: true,
      clientCertificates: [
        { origin: 'https://sso.acesso.gov.br', certPath: mtls.certPath, keyPath: mtls.keyPath },
        { origin: 'https://certificados.acesso.gov.br', certPath: mtls.certPath, keyPath: mtls.keyPath },
        { origin: 'https://certificado.sso.acesso.gov.br', certPath: mtls.certPath, keyPath: mtls.keyPath },
        { origin: 'https://acesso.gov.br', certPath: mtls.certPath, keyPath: mtls.keyPath }
      ]
    });
    
    console.log('[LOGIN] Motor preparado e HTTP/2 desativado.');
    page = browser.pages()[0] || await browser.newPage();

    console.log('[LOGIN] Acessando URL de autorização do Gov.br...');
    const nonce = crypto.randomUUID();
    const state = crypto.randomUUID();
    const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`;

    await page.goto(authUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    
    try {
      await page.waitForURL(/authorization_id=/, { timeout: 15000 });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    } catch(e) { }

    console.log('[LOGIN] Acionando login por certificado (Estratégia Tripla)...');
    
    let clickSuccess = false;
    const currentUrl = page.url();

    try {
      await page.locator('#login-certificate').click({ force: true, timeout: 5000 });
      await page.waitForURL(url => url.href !== currentUrl, { timeout: 8000 });
      console.log('[LOGIN] Sucesso no clique nativo! URL alterada.');
      clickSuccess = true;
    } catch (e) {
      try {
        await page.evaluate(() => {
          const btn = document.getElementById('login-certificate');
          if (btn) btn.click();
        });
        await page.waitForURL(url => url.href !== currentUrl, { timeout: 8000 });
        console.log('[LOGIN] Sucesso no clique via JS!');
        clickSuccess = true;
      } catch (err) { }
    }

    if (!clickSuccess) {
      const u = new URL(page.url());
      const authId = u.searchParams.get('authorization_id');
      const clientId = u.searchParams.get('client_id');
      if (authId && clientId) {
        const certUrl = `https://certificado.sso.acesso.gov.br/login?client_id=${clientId}&authorization_id=${authId}`;
        console.log(`[LOGIN] Fallback Ativado: URL direta de certificado...`);
        await page.goto(certUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      }
    }

    console.log('[LOGIN] Aguardando validação mTLS do Serpro (Fast-Fail)...');
    
    await page.waitForURL(url => {
        const href = url.href;
        return href.includes('fgtsdigital.sistema.gov.br/portal/acessogov?code=') || href.includes('acesso.gov.br/info/x509/');
    }, { timeout: 60000 });

    if (page.url().includes('acesso.gov.br/info/x509/')) {
        const e = new Error(`Certificado inválido ou revogado pelo Governo. URL: ${page.url()}`);
        e.pfxStage = 'PFX_INVALID';
        throw e;
    }
    
    const urlFgtsCode = page.url();
    console.log('[LOGIN] SUCESSO EXTREMO! Certificado reconhecido e Código capturado!');

    const playwrightCookies = await browser.cookies();
    const jar = newCookieJar();
    const setCookieArray = playwrightCookies.map(c => `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path}`);
    jar.set(setCookieArray);

    await browser.close();
    await cleanupMtls();
    
    console.log('[LOGIN] Trocando o Código pelo Token JWT no motor HTTP...');
    const fgtsUrlObj = new URL(urlFgtsCode);
    const fgtsCode = fgtsUrlObj.searchParams.get('code');
    const fgtsState = fgtsUrlObj.searchParams.get('state');

    const headersApiFgts = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Referer': urlFgtsCode,
        'Origin': 'https://fgtsdigital.sistema.gov.br'
    };

    const payloadToken = JSON.stringify({ code: fgtsCode, state: fgtsState });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/api/v1/acessogov/token', { method: 'POST', jar, headers: headersApiFgts, body: payloadToken });
    
    console.log('[LOGIN] SESSÃO FGTS ESTABELECIDA COM SUCESSO! Acessando dados...');
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/escolhaPerfil', { method: 'GET', jar, headers: headersApiFgts });
    await httpRequest('https://fgtsdigital.sistema.gov.br/portal/empregador/v1/empregadores/primeiroacesso', { method: 'GET', jar, headers: headersApiFgts });

    return { jar, finalUrl: urlFgtsCode, headersApiFgts };

  } catch (error) {
    console.error('[LOGIN-ERRO]', error.message);
    if (page) {
      console.log('[DEBUG] A página travou nesta URL:', page.url());
      try {
        const bodyText = await page.evaluate(() => {
          const errDiv = document.querySelector('.br-message.danger, .feedback-danger, .msg-erro, .error, #modal-erro');
          return errDiv ? `ERRO: ${errDiv.innerText}` : document.body.innerText;
        });
        console.log('[DEBUG] Texto na tela:', bodyText.replace(/\n/g, ' ').substring(0, 300));
      } catch (e) {}
    }
    if (browser) await browser.close().catch(() => {});
    await cleanupMtls();
    throw error;
  }
}

// ======================================================
// ROTAS DE API
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
            if (Array.isArray(lista)) {
                lista.forEach(emp => { emp.statusSistema = st; todosEmpregados.push(emp); })
            }
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
