FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ENV VITE_API_BASE_URL=/api/v1
RUN npm run build

FROM nginx:stable-alpine
COPY --from=build /app/dist /usr/share/nginx/html
RUN printf '%s\n' \
	'server {' \
	'    listen 80;' \
	'    server_name _;' \
	'    root /usr/share/nginx/html;' \
	'    index index.html;' \
	'    location / {' \
	'        try_files $uri $uri/ /index.html;' \
	'    }' \
	'}' > /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
