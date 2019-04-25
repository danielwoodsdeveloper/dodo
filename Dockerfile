# Build
FROM golang:latest AS build

COPY main.go /go/src/dodo/main.go

WORKDIR /go/src/dodo

RUN go get -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux go install .

# Run
FROM alpine:latest

COPY --from=build /go/bin/dodo .

RUN mkdir store

EXPOSE 6060

ENTRYPOINT [ "./dodo" ]