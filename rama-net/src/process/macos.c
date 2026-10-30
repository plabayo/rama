#include <arpa/inet.h>
#include <errno.h>
#include <libproc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>

// Keep this record in sync with SocketInfo in macos.rs. The SDK's much larger
// socket_fdinfo (including its unions) never crosses the C/Rust boundary.
struct rama_net_socket_info {
    uint8_t address[16];
    uint32_t scope;
    uint16_t port;
    uint8_t version;
    uint8_t protocol;
};

_Static_assert(sizeof(struct rama_net_socket_info) == 24, "SocketInfo size");
_Static_assert(offsetof(struct rama_net_socket_info, scope) == 16, "SocketInfo.scope");
_Static_assert(offsetof(struct rama_net_socket_info, port) == 20, "SocketInfo.port");
_Static_assert(offsetof(struct rama_net_socket_info, version) == 22, "SocketInfo.version");
_Static_assert(offsetof(struct rama_net_socket_info, protocol) == 23, "SocketInfo.protocol");

// 1: endpoint (`*out` fully written), 0: irrelevant or closed descriptor,
// negative errno: failure. `out` must be valid for writes of one record.
int rama_net_pid_socket(int pid, int fd, struct rama_net_socket_info *out) {
    struct socket_fdinfo info;

    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    if (size <= 0) {
        int error = errno;
        if (error == EBADF || error == ENOENT) {
            return 0;
        }

        return -(error ? error : EIO);
    }
    if (size != sizeof(info)) {
        return -EIO;
    }

    const struct socket_info *socket = &info.psi;
    if (socket->soi_family != AF_INET && socket->soi_family != AF_INET6) {
        return 0;
    }

    const struct in_sockinfo *in;
    memset(out, 0, sizeof(*out));

    if (socket->soi_kind == SOCKINFO_TCP && socket->soi_protocol == IPPROTO_TCP) {
        if (socket->soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) {
            return 0;
        }

        in = &socket->soi_proto.pri_tcp.tcpsi_ini;
        out->protocol = 6;
    } else if (socket->soi_kind == SOCKINFO_IN && socket->soi_protocol == IPPROTO_UDP) {
        in = &socket->soi_proto.pri_in;
        out->protocol = 17;
    } else {
        return 0;
    }

    out->port = ntohs((uint16_t)in->insi_lport);
    if (!out->port) {
        return 0;
    }

    if (socket->soi_family == AF_INET) {
        out->version = 4;
        memcpy(out->address, &in->insi_laddr.ina_46.i46a_addr4, 4);
    } else {
        out->version = 6;
        out->scope = in->insi_v6.in6_ifindex;
        memcpy(out->address, &in->insi_laddr.ina_6, 16);
    }

    return 1;
}
