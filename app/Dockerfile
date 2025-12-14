FROM golang:1.22-alpine

WORKDIR /app

# نسخ ملف go.mod فقط (لا نفترض وجود go.sum)
COPY app/go.mod ./
RUN go mod download

# نسخ كود التطبيق
COPY app/ .

RUN go build -o app

EXPOSE 8080
CMD ["./app"]

