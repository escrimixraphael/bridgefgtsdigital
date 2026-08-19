import express from 'express'
import cors from 'cors'
import crypto from 'node:crypto'
import dns from 'node:dns'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { execSync } from 'node:child_process'

import { chromium as playwrightBase } from 'playwright'
import { chromium } from 'playwright-extra'
import StealthPlugin from 'puppeteer-extra-plugin-stealth'

chromium.use(StealthPlugin())

dns.setDefaultResultOrder('ipv4first'); 

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || '9c6c38a65f8052500b7d4c2aff0b87fa'
const FGTS_API_KEY = process.env.FGTS_API_KEY || '5341b41fa01513c5b3e23f6dc35b8e94'
const PORT = process.env.PORT || 10000 

// ==========================================
// GERENCIADOR DE CACHE DE SESSÃO
// ==========================================
const sessionCache = new Map();
const CACHE_TTL_MS = 25 * 60 * 1000; 

async function getCachedOrLogin(cnpj, pfxBase64, password, isProcurador) {
  const now = Date.now();
  const cached = sessionCache.get(cnpj);
  
  if (cached && (now - cached.timestamp < CACHE_TTL_MS)) {
      console.log(`[CACHE] ⚡ Sessão reaproveitada com sucesso para o CNPJ ${cnpj}! Pulando login...`);
      return cached.session;
  }

  console.log(`[CACHE] ⏳ Sem sessão ativa para ${cnpj}. Iniciando login no Gov.br (Procurador: ${isProcurador})...`);
  const session = await loginGovBr(pfxBase64, password, cnpj, isProcurador);
  
  sessionCache.set(cnpj, {
      session,
      timestamp: now
  });
  
  return session;
}
// ==========================================

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
      console.log('[LOGIN] Destravando PFX legado e extraindo chaves modernizadas...');
      try {
          execSync(`openssl pkcs12 -legacy -provider default -provider legacy -in "${inPath}" -nokeys -out "${certPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
          execSync(`openssl pkcs12 -legacy -provider default -provider legacy -in "${inPath}" -nocerts -nodes -out "${keyPath}" -passin file:"${passPath}"`, { stdio: 'pipe' });
      } catch (err) {
          execSync(`openssl pkcs12 -in "${inPath}" -nokeys -out "${certPath}" -passin file:"${passPath}"`);
          execSync(`openssl pkcs12 -in "${inPath}" -nocerts -nodes -out "${keyPath}" -passin file:"${passPath}"`);
      }
      return { 
          certPath, keyPath, 
          cleanup: async () => {
              await Promise.all([ fs.unlink(inPath).catch(()=>{}), fs.unlink(certPath).catch(()=>{}), fs.unlink(keyPath).catch(()=>{}), fs.unlink(passPath).catch(()=>{}) ]);
          }
      };
  } catch (err) {
      console.error('[LOGIN-ERRO-SSL]', err.message);
      await Promise.all([ fs.unlink(inPath).catch(()=>{}), fs.unlink(certPath).catch(()=>{}), fs.unlink(keyPath).catch(()=>{}), fs.unlink(passPath).catch(()=>{}) ]);
      throw new Error(`Falha ao converter certificado. Verifique a senha ou se o OpenSSL está instalado na máquina.`);
  }
}

// ==========================================
// MOTOR DE LOGIN PRINCIPAL
// ==========================================
async function loginGovBr(pfxBase64, password, cnpjDesejado, isProcurador) {
  console.log('[LOGIN] Iniciando motor Playwright ancorado no CHROME REAL...');
  let context; let cleanupFiles = null;

  try {
    const certData = await convertPfxToPem(pfxBase64, password);
    cleanupFiles = certData.cleanup;
    
    // DETECÇÃO DE SISTEMA OPERACIONAL
    const isWindows = process.platform === 'win32';
    
    // APONTANDO PARA O SEU PERFIL REAL DO CHROME NO WINDOWS
    const userDataDir = isWindows 
        ? path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data')
        : '/home/ubuntu/.config/google-chrome';
    
    try {
      context = await chromium.launchPersistentContext(userDataDir, {
        headless: false, 
        channel: 'chrome', // ISSO AQUI FORÇA USAR O CHROME OFICIAL DO SEU COMPUTADOR
        viewport: null, 
        ignoreDefaultArgs: ['--enable-automation'], // ESCONDE O AVISO DE AUTOMAÇÃO
        args: [
          '--start-maximized', 
          '--profile-directory=Default', // ISSO AQUI FORÇA USAR A SUA CONTA GOOGLE PRINCIPAL
          '--disable-blink-features=AutomationControlled'
        ],
        clientCertificates: [{
          origin: 'https://sso.acesso.gov.br', 
          certPath: certData.certPath,
          keyPath: certData.keyPath
        }, {
          origin: 'https://certificado.sso.acesso.gov.br',
          certPath: certData.certPath,
          keyPath: certData.keyPath
        }]
      });
    } catch (launchErr) {
      if (launchErr.message.includes('lock') || launchErr.message.includes('EBUSY')) {
          console.error('\n🔴 ATENÇÃO: ERRO DE PERFIL TRANCADO!');
          console.error('O Google Chrome já está rodando escondido no fundo do seu Windows!');
          console.error('Para resolver: Abra o terminal e rode: taskkill //F //IM chrome.exe //T\n');
          throw new Error('Feche todas as abas e janelas do Chrome e tente novamente.');
      }
      throw launchErr;
    }
    
    const page = context.pages().length > 0 ? context.pages()[0] : await context.newPage();
    page.setDefaultTimeout(180000); 

    console.log('[LOGIN] Passo 1: Acessando a página inicial do FGTS Digital...');
    await page.goto('https://fgtsdigital.sistema.gov.br/portal/login', { waitUntil: 'domcontentloaded' });
    
    console.log('[LOGIN] Aguardando para ver se o sistema redireciona automaticamente (Sessão preservada)...');
    try {
        await page.waitForURL(/sso\.acesso\.gov\.br|escolhaPerfil|home/, { timeout: 6000 });
    } catch (e) {
        // Continua na tela de login
    }

    if (page.url().includes('/login')) {
        console.log('[LOGIN] Passo 2: Clicando em "Entrar com gov.br"...');
        const seletoresEntrar = [
            'button:has-text("Entrar com gov.br")',
            'a:has-text("Entrar com gov.br")',
            '.br-button.sign-in',
            'button[title*="gov.br"]'
        ];

        let entrouGov = false;
        for (const sel of seletoresEntrar) {
            try {
                const btn = page.locator(sel).first();
                await btn.waitFor({ state: 'visible', timeout: 3000 });
                await btn.click({ force: true });
                entrouGov = true;
                break;
            } catch (e) {}
        }

        if (!entrouGov) {
            console.log('[LOGIN] Tentando clicar no botão via injeção de JavaScript...');
            entrouGov = await page.evaluate(() => {
                const btns = Array.from(document.querySelectorAll('button, a'));
                const alvo = btns.find(b => b.innerText && b.innerText.toLowerCase().includes('entrar com gov.br'));
                if (alvo) { alvo.click(); return true; }
                return false;
            });
        }

        if (!entrouGov) {
            console.log(`[LOGIN-ERRO] Botão de "Entrar com gov.br" não encontrado. Tirando foto da tela...`);
            await page.screenshot({ path: path.join(process.cwd(), `erro-entrar-${Date.now()}.png`), fullPage: true });
            throw new Error('Não foi possível clicar no botão de Entrar com gov.br na tela inicial.');
        }

        console.log('[LOGIN] Aguardando a tela do Gov.br ou o redirecionamento...');
        await page.waitForURL(/sso\.acesso\.gov\.br|escolhaPerfil|home/, { timeout: 30000 });
    }

    if (page.url().includes('sso.acesso.gov.br')) {
        console.log(`[LOGIN] Passo 3: Estamos no Gov.br. Clicando no botão do certificado digital...`);
        const seletoresCertificado = [
            '#login-certificate',
            'button >> text="Seu certificado digital"',
            'button >> text="Certificado digital"',
            'img[alt*="Certificado"]'
        ];

        let btnClicado = false;
        for (const sel of seletoresCertificado) {
            try {
                const element = page.locator(sel).first();
                await element.waitFor({ state: 'visible', timeout: 10000 });
                await element.click({ force: true });
                btnClicado = true;
                console.log(`[LOGIN] ✅ Botão de certificado clicado com sucesso usando: ${sel}`);
                break;
            } catch (e) {}
        }

        if (!btnClicado) {
            console.log(`[LOGIN-ERRO] Nenhum botão de certificado foi encontrado. Tirando screenshot...`);
            await page.screenshot({ path: path.join(process.cwd(), `erro-login-gov-${Date.now()}.png`), fullPage: true });
            throw new Error('Não foi possível encontrar o botão de Certificado Digital na tela do Gov.br.');
        }

        console.log('[LOGIN] Passo 4: Aguardando o retorno para o FGTS (Se pedir Captcha, resolva!)...');
        await page.waitForURL(/escolhaPerfil|home/, { timeout: 180000 });
        console.log('[LOGIN] SUCESSO! Voltamos para o FGTS Digital com a sessão confiável!');
    } else {
        console.log('[LOGIN] ✅ SESSÃO REAPROVEITADA! Passamos direto pelo login do Gov.br!');
    }

    console.log('[LOGIN] Passo 5: Aguardando a tela de Seleção de Perfil...');
    
    await page.waitForURL(/escolhaPerfil|home/, { timeout: 30000 }).catch(() => {});
    
    if (page.url().includes('escolhaPerfil')) {
        console.log(`[LOGIN] Tela de perfil detectada! Modo Procurador = ${isProcurador}`);
        
        await page.waitForTimeout(3000); 
        
        if (isProcurador) {
            console.log(`[LOGIN] Selecionando 'Procurador' e buscando CNPJ ${cnpjDesejado}...`);
            
            const radioVelho = page.locator('input[value="PROCURADOR_PJ"]');
            if (await radioVelho.count() > 0) {
                await radioVelho.first().click({ force: true }).catch(()=>{});
            } else {
                console.log(`[LOGIN] Usando injeção de teclado para trocar para Procurador no novo menu...`);
                const dropdown = page.locator('text="Meu Perfil"').last();
                await dropdown.click({ force: true }).catch(()=>{});
                await page.waitForTimeout(1000);
                
                await page.keyboard.type('Procurador');
                await page.waitForTimeout(500);
                await page.keyboard.press('Enter');
            }
            
            await page.waitForTimeout(1000); 
            const inputCnpj = page.locator('input[name="cnpjPj"], input[placeholder*="CNPJ"], input[aria-label*="CNPJ"], input[formcontrolname*="cnpj"]');
            await inputCnpj.first().waitFor({ state: 'visible', timeout: 5000 }).catch(()=>{});
            await inputCnpj.first().fill(cnpjDesejado).catch(()=>{});
            
        } else {
            console.log(`[LOGIN] Modo 'Meu Perfil'. Como já é o padrão no modal, apenas confirmaremos...`);
            const radioProprio = page.locator('input[value="MEU_PERFIL"]');
            if (await radioProprio.count() > 0) {
                await radioProprio.first().click({ force: true }).catch(()=>{});
            }
        }

        await page.waitForTimeout(2000); 

        console.log(`[LOGIN] Clicando no botão para confirmar o perfil (Procurando botão Definir)...`);
        const seletoresConfirmar = [
            'button:has-text("Definir")',
            'button:has-text("Selecionar")',
            'button:has-text("Continuar")'
        ];

        let clicouPerfil = false;
        for (const sel of seletoresConfirmar) {
            try {
                const btn = page.locator(sel).first();
                await btn.waitFor({ state: 'visible', timeout: 10000 });
                await btn.evaluate(node => node.click());
                clicouPerfil = true;
                console.log(`[LOGIN] ✅ Botão de perfil clicado com sucesso usando injeção em: ${sel}`);
                break;
            } catch (e) {}
        }

        if (!clicouPerfil) {
            console.log(`[LOGIN-ERRO] Não encontrou o botão de confirmar o perfil (timeout)! Tirando foto...`);
            await page.screenshot({ path: path.join(process.cwd(), `erro-perfil-${Date.now()}.png`), fullPage: true });
        } else {
            console.log(`[LOGIN] Perfil confirmado. Aguardando carregamento do Dashboard (/home)...`);
            await page.waitForTimeout(2000); 
            await page.waitForURL(/home/, { timeout: 15000 }).catch(() => console.log('[LOGIN] Timeout secundário esperando /home, mas o clique foi feito.'));
        }

    } else {
        console.log('[LOGIN] Tela de perfil não apareceu, o sistema entrou direto no Dashboard principal.');
    }

    const urlFgtsCode = page.url();

    console.log('[LOGIN] Passo 6: Aguardando o portal FGTS trocar o Token em background...');
    try {
        await page.waitForResponse(response => 
            response.url().includes('/api/v1/acessogov/token') && response.status() === 200, 
            { timeout: 15000 }
        );
        console.log('[LOGIN] Token capturado pelo navegador com sucesso!');
    } catch (e) {
        console.log('[LOGIN] Aviso: O interceptador do token deu timeout, mas vamos checar os cookies mesmo assim.');
    }

    await page.waitForTimeout(3000); 

    const finalCookies = await context.cookies();
    const jar = newCookieJar();
    jar.set(finalCookies.map(c => `${c.name}=${c.value}; Domain=${c.domain}; Path=${c.path}`));

    const pages = context.pages();
    for (const p of pages) await p.close();
    await context.close();
    if (cleanupFiles) await cleanupFiles();
    
    console.log('[LOGIN] Cookies extraídos! Configurando sessão para chamadas de API (RPA)...');
    const headersApiFgts = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Referer': urlFgtsCode,
        'Origin': 'https://fgtsdigital.sistema.gov.br'
    };

    return { jar, finalUrl: urlFgtsCode, headersApiFgts };

  } catch (error) {
    console.error('[LOGIN-ERRO]', error.message);
    if (context) {
        const pages = context.pages();
        for (const p of pages) await p.close().catch(()=>{});
        await context.close().catch(() => {});
    }
    if (cleanupFiles) await cleanupFiles().catch(() => {});
    throw error;
  }
}

app.post('/rpa/fgts/extrato', requireApiKey, async (req, res) => {
  const { cnpj, cnpjCertificado, pfxBase64, password, payloadBusca } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })
  
  const isProcurador = cnpj !== cnpjCertificado;

  try {
    const { jar, headersApiFgts } = await getCachedOrLogin(cnpj, pfxBase64, password, isProcurador)
    
    const cnpjNum = cnpj.replace(/\D/g,'')
    const empId = `${cnpjNum.substring(0,8)}1`
    console.log(`[FGTS-RPA] Consultando guias para o Empregador ${empId}...`)
    
    const respUsuario = await httpRequest('https://fgtsdigital.sistema.gov.br/cobranca/api/usuario', { method:'GET', jar, headers: headersApiFgts })
    const dadosUsuario = tryParseJson(respUsuario.body)
    
    if (respUsuario.status === 401 || respUsuario.status === 403) {
        console.log(`[CACHE] Sessão do CNPJ ${cnpj} expirou no servidor do FGTS ou perfil não aplicado corretamente. Limpando cache...`);
        sessionCache.delete(cnpj);
        return res.status(401).json({ success: false, errorType: 'SESSION_EXPIRED', error: 'Sessão expirada ou sem permissão de procurador. Tente forçar novo login.' });
    }

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
  const { cnpj, cnpjCertificado, pfxBase64, password } = req.body
  if (!cnpj) return res.status(400).json({ success: false, erro: 'CNPJ obrigatório' })
  
  const isProcurador = cnpj !== cnpjCertificado;

  try {
    const { jar, headersApiFgts } = await getCachedOrLogin(cnpj, pfxBase64, password, isProcurador)
    
    console.log(`[FGTS-RPA] Extraindo Vínculos para o CNPJ ${cnpj}...`)
    const statuses = ['ativo', 'afastado', 'desligado']
    const todosEmpregados = []
    
    for (const st of statuses) {
        const urlVinculos = `https://fgtsdigital.sistema.gov.br/extrato/api/vinculos/${st}/,,,,0,0?num-pagina=1&tam-pagina=1000&campo-ordem=nmTrabalhador&ordem=asc`
        const resp = await httpRequest(urlVinculos, { method: 'GET', jar, headers: headersApiFgts })
        
        if (resp.status === 401 || resp.status === 403) {
            console.log(`[CACHE] Sessão do CNPJ ${cnpj} expirou no servidor do FGTS. Limpando cache...`);
            sessionCache.delete(cnpj);
            return res.status(401).json({ success: false, errorType: 'SESSION_EXPIRED', error: 'Sessão expirada. Tente forçar novo login.' });
        }

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
