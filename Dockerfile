# Usa a imagem padrão e leve do Node.js (Foge do bug da Microsoft no GCP)
FROM node:20-bookworm-slim

# Define a pasta de trabalho dentro do servidor
WORKDIR /app

# Instala o OpenSSL nativo do Linux (Vital para o seu conversor de Certificados PFX)
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copia as informações dos pacotes
COPY package*.json ./

# Instala as dependências do Node (express, playwright, etc)
RUN npm install

# MÁGICA: Pede para o Playwright baixar APENAS o Chromium e instalar as dependências gráficas do Linux
RUN npx playwright install --with-deps chromium

# Copia o resto do seu código (server.js, etc)
COPY . .

# Expõe a porta para o Google Cloud
EXPOSE 10000

# Comando para iniciar o servidor
CMD ["node", "server.js"]
