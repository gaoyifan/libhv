#include "hloop.h"
#include "hsocket.h"
#include "hlog.h"
#include <linux/netfilter_ipv4.h>

#define FLOW_CONTROL_THRESHOLD (8 * 1024 * 1024) // 8MB
#define INET_ADDRSTRLEN 16
static char proxy_host[64] = "0.0.0.0";
static int proxy_port = 1080;

static int backend_ssl = 0;

static void flow_control_on_write(hio_t* io, const void* buf, int bytes) {
    if (!io) return;
    hio_t* upstream_io = hio_get_upstream(io);
    if (hio_write_bufsize(io) < FLOW_CONTROL_THRESHOLD) {
        hio_read(upstream_io);
    }
}

static void flow_control_on_read(hio_t* io, void* buf, int bytes) {
    hio_t* upstream_io = hio_get_upstream(io);
    if (hio_write_bufsize(upstream_io) + bytes >= FLOW_CONTROL_THRESHOLD) {
        hio_del(io, HV_READ);
    }
    if (upstream_io) {
        hio_write(upstream_io, buf, bytes);
    }
}

// hloop_create_tcp_server -> on_accept -> hio_setup_tcp_upstream

static void on_accept(hio_t* io) {
    struct sockaddr_in origAddr = {0};
    int origAddrLen = sizeof(origAddr);
    char upstream_host[INET_ADDRSTRLEN];
    int upstream_port;
    if (getsockopt(hio_fd(io), SOL_IP, SO_ORIGINAL_DST, &origAddr, &origAddrLen) == 0) {
        inet_ntop(AF_INET, &(origAddr.sin_addr), upstream_host, INET_ADDRSTRLEN);
        upstream_port = ntohs(origAddr.sin_port);
        printf("on_accept %s:%d\n", upstream_host, upstream_port);
        fflush(stdout);
        hio_t* upstream_io = hio_setup_tcp_upstream(io, upstream_host, upstream_port, backend_ssl);
        hio_setcb_write(io, flow_control_on_write);
        hio_setcb_write(upstream_io, flow_control_on_write);
        hio_setcb_read(io, flow_control_on_read);
        hio_setcb_read(upstream_io, flow_control_on_read);
        hio_set_max_read_bufsize(io, FLOW_CONTROL_THRESHOLD);
        hio_set_max_read_bufsize(upstream_io, FLOW_CONTROL_THRESHOLD);
        hio_set_max_write_bufsize(io, FLOW_CONTROL_THRESHOLD * 2);
        hio_set_max_write_bufsize(upstream_io, FLOW_CONTROL_THRESHOLD * 2);
    }
    else {
        hio_close(io);
        printf("getsockopt failed");
    }
}

int main(int argc, char** argv) {
    hlog_disable();
    if (argc < 1) {
        printf("argc:%d\n", argc);
        printf("Usage: %s listen_port\n", argv[0]);
        return -10;
    }
    proxy_port = atoi(argv[1]);
    printf("listen on %s:%d\n", proxy_host, proxy_port);

    hloop_t* loop = hloop_new(0);
    hio_t* listenio = hloop_create_tcp_server(loop, proxy_host, proxy_port, on_accept);
    if (listenio == NULL) {
        return -20;
    }
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
