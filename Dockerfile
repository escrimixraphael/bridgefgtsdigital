# 1. Usa o Linux super leve com Node.js já instalado
FROM node:20-bookworm-slim

# 2. Define a pasta onde tudo vai acontecer
WORKDIR /app

# 3. Instala apenas o OpenSSL primeiro
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# 4. A MÁGICA DEFINITIVA ACONTECE AQUI:
# O valor "0" obriga o Playwright a guardar o Chromium DENTRO da pasta do projeto
# Isso tem que ficar ANTES do 'npm install'.
ENV PLAYWRIGHT_BROWSERS_PATH=0

# 5. Copia os arquivos de dependência
COPY package*.json ./

# 6. Agora sim! O npm vai ler a variável acima e instalar o Chromium no lugar exato.
RUN npm install

# 7. Instala as bibliotecas gráficas do Linux necessárias para o Chromium rodar
RUN npx playwright install --with-deps chromium

# 8. Copia o resto do seu código
COPY . .

# 9. Libera a porta
EXPOSE 10000

# 10. Inicia a Bridge
CMD ["node", "server.js"]
