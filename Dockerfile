FROM golang:1.8.3 as build
COPY . /go/src/github.com/coyove/goflyway
WORKDIR /go/src/github.com/coyove/goflyway
RUN go install

FROM scratch
COPY --from=build /go/bin/goflyway
COPY goflyway.conf
EXPOSE 8102 8100 8101
ENTRYPOINT ["/goflyway"]
