# Usa uma imagem oficial do Node (versão 20) com Debian
FROM node:20-bullseye

# Instala todas as dependências que o Chromium/Chrome precisa para rodar no Linux
RUN apt-get update \
    && apt-get install -y wget gnupg \
    && apt-get install -y libnss3 libnss3-tools libxss1 libasound2 libatk-bridge2.0-0 libgtk-3-0 libgbm-dev \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Configura a pasta de trabalho
WORKDIR /app

# Copia os arquivos de dependência e instala
COPY package*.json ./
RUN npm install

# Copia o resto do código
COPY . .

# Comando para iniciar o seu server.js
CMD ["node", "server.js"]
