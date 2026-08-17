# 1. Usa o Linux super leve com Node.js já instalado
FROM node:20-bookworm-slim

# 2. Define a pasta onde tudo vai acontecer
WORKDIR /app

# 3. Instala apenas o OpenSSL primeiro
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# 4. A MÁGICA DEFINITIVA ACONTECE AQUI:
ENV PLAYWRIGHT_BROWSERS_PATH=0
# Estas três linhas são OBRIGATÓRIAS para o Playwright conseguir acessar a rede no Cloud Run Gen2
ENV DBUS_FATAL_WARNINGS=0
ENV DISABLE_WAYLAND=1
ENV NO_UPDATE_NOTIFIER=true

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
