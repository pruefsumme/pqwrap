FROM golang:1.27.2-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /pqwrap .

FROM scratch
COPY --from=build /pqwrap /pqwrap
COPY config/pqwrap.yaml /etc/pqwrap/pqwrap.yaml
USER 65532:65532
EXPOSE 443
ENTRYPOINT ["/pqwrap", "-config", "/etc/pqwrap/pqwrap.yaml"]
