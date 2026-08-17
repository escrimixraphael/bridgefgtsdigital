# Usa a imagem oficial do Node 20
FROM node:20-bullseye

# Atualiza o sistema e instala o OpenSSL (Vital para o seu código que usa execSync)
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Cria e define a pasta de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de dependência e instala os pacotes do Node
COPY package*.json ./
RUN npm install

# Instala os navegadores do Playwright e todas as dependências do sistema necessárias para rodar o Chromium
RUN npx playwright install chromium --with-deps

# Copia o resto do seu código (server.js, etc)
COPY . .

# Expõe a porta que sua API usa
EXPOSE 10000

# Comando para iniciar sua API
CMD ["node", "server.js"]
