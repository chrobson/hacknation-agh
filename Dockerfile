FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/asi ./cmd/asi

# nmap is installed from the distribution at build time (NPSL); this image is
# built locally and not published.
FROM alpine:3.22
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata
COPY --from=build /out/asi /usr/local/bin/asi
COPY signatures /etc/asi/signatures
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "-c", "asi migrate && exec asi serve"]
