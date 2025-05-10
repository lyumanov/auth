FROM golang:1.23.5

RUN apt-get update && apt-get install -y postgresql-client

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

CMD ["go", "run", "./cmd/main.go"]