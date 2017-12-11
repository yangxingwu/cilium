# Stage: build
FROM cilium/build as build
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH="${GOROOT}/bin:${PATH}"
WORKDIR /go/src/github.com/cilium/cilium
ADD . .
RUN make build

# Final stage: cilium
FROM cilium/runtime
LABEL maintainer="maintainer@cilium.io"
COPY --from=build \
     /go/src/github.com/cilium/cilium/daemon/cilium-agent \
     /go/src/github.com/cilium/cilium/plugins/cilium-docker/cilium-docker \
     /go/src/github.com/cilium/cilium/cilium/cilium \
     /go/src/github.com/cilium/cilium/monitor/cilium-node-monitor \
     /usr/bin/
COPY --from=build \
     /go/src/github.com/cilium/cilium/plugins/cilium-cni/cilium-cni \
     /opt/cni/bin/

# bash completion
RUN mkdir -p /root && \
    echo ". /etc/profile.d/bash_completion.sh" >> /root/.bashrc && \
    cilium completion bash >> /root/.bashrc && \
    groupadd -f cilium

ENV PATH="/usr/local/clang+llvm/bin:$PATH"
ENV INITSYSTEM="SYSTEMD"

CMD ["/usr/bin/cilium"]
