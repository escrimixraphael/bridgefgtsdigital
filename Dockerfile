# Usa a imagem oficial do Playwright da Microsoft (já vem com Chromium e Node.js)
FROM mcr.microsoft.com/playwright:v1.44.0-jammy

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos de dependências
COPY package*.json ./

# Instala os pacotes do Node
RUN npm install

# Copia todo o resto do seu código
COPY . .

# Expõe a porta que a Bridge vai rodar
EXPOSE 10000

# Comando para iniciar o servidor
CMD ["node", "server.js"]
