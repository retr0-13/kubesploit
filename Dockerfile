FROM golang:1.14.15-alpine3.13 as builder


# Build the Docker image first
#  > sudo docker build -t merlin .

# To start the Merlin Server, run
#  > sudo docker run -it -p 443:443 --mount type=bind,src=/tmp,dst=/go/src/github.com/Ne0nd0g/merlin/data merlin


RUN mkdir /src
ADD . /src
WORKDIR /src


RUN apk update && apk upgrade && apk add bash && apk add vim && go get github.com/mitchellh/gox
# RUN gox -ldflags "-s -w" -osarch linux/386 -output "merlin"
RUN go build cmd/merlinserver/main.go
#FROM alpine:latest
#COPY --from=builder /src/merlin /app/
#WORKDIR /app

#ENTRYPOINT ["bash -c /src/merlin"]
