# Usa a imagem oficial do Node 22 com Debian 12 (Bookworm)
FROM node:22-bookworm

# Atualiza o sistema e instala o OpenSSL
RUN apt-get update && apt-get install -y curl

# Cria e define a pasta de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de dependência
COPY package*.json ./

# Instala as dependências do Node (Ignorando falhas de scripts pós-instalação se houver)
RUN npm install --ignore-scripts

# Instala o navegador Chromium e suas dependências de sistema
RUN npx playwright install chromium --with-deps

# Copia o resto do seu código
COPY . .

# Expõe a porta que sua API usa
EXPOSE 10000

# Comando para iniciar sua API
CMD ["node", "server.js"]
