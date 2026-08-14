import express from 'express'
import cors from 'cors'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs/promises'
import { execSync } from 'node:child_process'
import { chromium } from 'playwright'

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

// ======================================================
// CONFIGURAÇÃO E SEGURANÇA
// ======================================================
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
// FUNÇÕES AUXILIARES (HTTP e JSON)
// ======================================================
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
      for (const [name, value] of this.cookies.entries()) {
        str += `${name}=${value}; `;
      }
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
// CONVERSOR DE CERTIFICADO LEGADO PARA O PLAYWRIGHT
// ======================================================
async function makePfxTls(pfxBase64, password) {
  const pfxBuffer = Buffer.from(pfxBase64, 'base64');
  console.log('[LOGIN] Iniciando modernização blindada do certificado...');
  
  const tmpDir = os.tmpdir();
  const tmpId = crypto.randomUUID();
  const inPath = path.join(tmpDir, `in_${tmpId}.pfx`);
  const pemPath = path.join(tmpDir, `temp_${tmpId}.pem`);
  const outPath = path.join(tmpDir, `out_${tmpId}.pfx`);
  const passPath = path.join(tmpDir, `pass_${tmpId}.txt`);
  
  try {
    // Escreve os arquivos (inclusive a senha, para não dar erro com caracteres especiais)
    await fs.writeFile(inPath, pfxBuffer);
    await fs.writeFile(passPath, password);
    
    console.log('[LOGIN] Extraindo chaves do PFX antigo...');
    try {
      // Tenta com a flag -legacy (para OpenSSL 3+)
      execSync(`openssl pkcs12 -in "${inPath}" -out "${pemPath}" -nodes -legacy -passin file:"${passPath}"`, { stdio: 'pipe' });
    } catch (e1) {
      console.log('[LOGIN] Tentativa com -legacy falhou, tentando padrão...');
      // Tenta sem a flag -legacy (para OpenSSL mais antigo)
      execSync(`openssl pkcs12 -in "${inPath}" -out "${pemPath}" -nodes -passin file:"${passPath}"`, { stdio: 'pipe' });
    }
    
    console.log('[LOGIN] Recriando PFX com criptografia AES-256 (Padrão Playwright)...');
    execSync(`openssl pkcs12 -export -in "${pemPath}" -out "${outPath}" -passout file:"${passPath}" -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256`, { stdio: 'pipe' });
    
    const modernBuffer = await fs.readFile(outPath);
    
    // Limpeza pesada
    await Promise.all([
      fs.unlink(inPath).catch(()=>{}),
      fs.unlink(pemPath).catch(()=>{}),
      fs.unlink(outPath).catch(()=>{}),
      fs.unlink(passPath).catch(()=>{})
    ]);
    
    console.log('[LOGIN] SUCESSO! Certificado modernizado para AES-256!');
    return { pfx: modernBuffer, passphrase: password };
    
  } catch (err) {
    const linuxError = err.stderr ? err.stderr.toString() : err.message;
    console.error('[LOGIN-ERRO] Falha crítica no OpenSSL Linux:', linuxError);
    
    // Limpeza em caso de erro
    await Promise.all([
      fs.unlink(inPath).catch(()=>{}),
      fs.unlink(pemPath).catch(()=>{}),
      fs.unlink(outPath).catch(()=>{}),
      fs.unlink(passPath).catch(()=>{})
    ]);
    
    throw new Error(`Falha ao modernizar certificado. Detalhes: ${linuxError}`);
  }
}


// ======================================================
// LOGIN GOV.BR E FGTS DIGITAL (VIA PLAYWRIGHT - BYPASS WAF)
// ======================================================
async function loginGovBr(pfxBase64, password) {
  console.log('[LOGIN] Iniciando motor blindado (Playwright) para bypass do WAF...');

  let browser;
  const tmpDir = os.tmpdir();
  const certId = crypto.randomUUID();
  const certPath = path.join(tmpDir, `cert_${certId}.pfx`);

  try {
    console.log('[LOGIN] Passo 1: Verificando/Convertendo o Certificado Digital...');
    const mtls = await makePfxTls(pfxBase64, password);
    console.log('[LOGIN] Passo 1 OK: Certificado validado e convertido para formato seguro.');

    console.log('[LOGIN] Passo 2: Escrevendo arquivo PFX temporário...');
    await fs.writeFile(certPath, mtls.pfx);
    console.log('[LOGIN] Passo 2 OK: Arquivo salvo no servidor.');

    console.log('[LOGIN] Passo 3: Solicitando abertura do motor Chromium no Linux...');
    browser = await chromium.launchPersistentContext('', {
      headless: true,
      args: ['--no-sandbox', '--disable-blink-features=AutomationControlled', '--disable-dev-shm-usage', '--disable-gpu'], 
      ignoreHTTPSErrors: true,
      clientCertificates: [{
        origin: 'https://*.gov.br',
        pfxPath: certPath,
        passphrase: mtls.passphrase
      }]
    });
    console.log('[LOGIN] Passo 3 OK: Navegador Chromium abriu com sucesso!');

    const page = browser.pages()[0] || await browser.newPage();

    console.log('[LOGIN] Passo 4: Acessando URL de autorização do Gov.br...');
    const nonce = crypto.randomUUID();
    const state = crypto.randomUUID();
    const authUrl = `https://sso.acesso.gov.br/authorize?response_type=code&client_id=por-p-fgtsd.estaleiro.serpro.gov.br&scope=openid+email+phone+profile+govbr_empresa+govbr_confiabilidades&redirect_uri=https%3A%2F%2Ffgtsdigital.sistema.gov.br%2Fportal%2Facessogov&nonce=${nonce}&state=${state}`;

    await page.goto(authUrl, { waitUntil: 'networkidle', timeout: 45000 });
    console.log('[LOGIN] Passo 4 OK: Página do Governo carregada (WAF superado).');

    console.log('[LOGIN] Passo 5: Clicando no botão do Certificado Digital...');
    await page.locator('button:has-text("Seu certificado digital"), a:has-text("Seu certificado digital"), [data-sso-type="certificate"]').first().click();

    console.log('[LOGIN] Passo 6: Aguardando redirecionamento com código mTLS...');
    await page.waitForURL('**/fgtsdigital.sistema.gov.br/portal/acessogov?code=**', { timeout: 60000 });
    
    const urlFgtsCode = page.url();
    console.log('[LOGIN] Passo 6 OK: SUCESSO! Código capturado:', urlFgtsCode.substring(0, 70) + '...');

    const playwrightCookies = await browser.cookies();
    const jar = newCookieJar();
    const setCookieArray = playwrightCookies.map(c => `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path}`);
    jar.set(setCookieArray);

    await browser.close();
    await fs.unlink(certPath).catch(() => {});
    
    console.log('[LOGIN] Passo 7: Trocando o Código pelo Token JWT no motor HTTP...');
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

    console.log('[LOGIN] SESSÃO FGTS ESTABELECIDA COM SUCESSO! O Robô vai buscar os dados agora.');
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
