FROM mcr.microsoft.com/playwright:v1.44.0-jammy

# Instala o curl e openssl na marra
RUN apt-get update && apt-get install -y curl openssl

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 10000
CMD ["npm", "start"]
