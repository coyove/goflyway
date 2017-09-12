FROM golang:1.8.3 as build
COPY . /build
WORKDIR /build
RUN CGO_ENABLED=0 make build
ENTRYPOINT ["bash"]

FROM scratch
COPY --from=build /build/build/goflyway /goflyway
EXPOSE 8102 8100 8101
ENTRYPOINT ["/goflyway"]
