FROM golang:1.22-alpine

WORKDIR /app

# نسخ ملفات Go من مجلد app
COPY app/go.mod app/go.sum ./
RUN go mod download

# نسخ بقية الكود
COPY app/ .

RUN go build -o app

EXPOSE 8080
CMD ["./app"]

