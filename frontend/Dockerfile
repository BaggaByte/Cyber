FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

# Assuming it's a Next.js app in development mode for the sentinel-frontend based on the compose file.
CMD ["npm", "run", "dev"]
