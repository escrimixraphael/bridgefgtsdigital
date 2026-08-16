# 1. Usa o Linux super leve com Node.js já instalado
FROM node:20-bookworm-slim

# 2. Define a pasta onde tudo vai acontecer
WORKDIR /app

# 3. Instala o OpenSSL atualizado e bibliotecas base
RUN apt-get update && apt-get install -y openssl libgconf-2-4 libnss3 libnspr4 libxss1 libasound2 libatk-bridge2.0-0 libgtk-3-0 && rm -rf /var/lib/apt/lists/*

# 4. Copia os arquivos de dependência
COPY package*.json ./

# 5. Instala o Node.js
RUN npm install

# 6. O SEGREDO MÁGICO PARA O CLOUD RUN:
# Obriga o Playwright a instalar os navegadores dentro da nossa pasta /app
ENV PLAYWRIGHT_BROWSERS_PATH=/app/pw-browsers

# 7. Baixa os binários do Chromium (agora eles vão ficar em /app/pw-browsers)
RUN npx playwright install --with-deps chromium

# 8. Copia o resto do seu código
COPY . .

# 9. Libera a porta (O Cloud Run usa a variavel $PORT, mas 10000 é nosso backup)
EXPOSE 10000

# 10. Inicia a Bridge
CMD ["node", "server.js"]
