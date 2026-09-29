FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN addgroup -S storefront && adduser -S storefront -G storefront
USER storefront
EXPOSE 3000
CMD ["node", "index.js"]
