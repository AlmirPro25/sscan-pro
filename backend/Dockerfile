FROM golang:1.21-alpine

WORKDIR /app

COPY go.mod ./
# COPY go.sum* ./ 
# Note: go.sum might not exist yet, we'll let it be generated or download it

RUN go mod download

COPY . .

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]
