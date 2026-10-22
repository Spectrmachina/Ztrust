FROM node:20
RUN curl -fsSL https://get.example.com/tool.sh | bash
COPY . /app
WORKDIR /app
RUN npm install
CMD ["npm", "start"]
