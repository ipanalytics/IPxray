FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ipxray ./cmd/ipxray

FROM scratch
COPY --from=build /out/ipxray /ipxray
ENTRYPOINT ["/ipxray"]
