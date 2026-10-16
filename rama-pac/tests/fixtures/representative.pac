// A synthetic small enterprise PAC: local/intranet bypass, private IPv4,
// a vendor exception, and ordered primary/backup proxies for other traffic.
// Literal IPv4 input exercises isInNet without external DNS timing.
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example")) {
        return "DIRECT";
    }
    if (/^[0-9.]+$/.test(host) &&
        (isInNet(host, "10.0.0.0", "255.0.0.0") ||
         isInNet(host, "192.168.0.0", "255.255.0.0"))) {
        return "DIRECT";
    }
    if (shExpMatch(host, "*.vendor.example") &&
        shExpMatch(url, "https://*")) {
        return "PROXY vendor-proxy.corp.example:8080; DIRECT";
    }
    return "PROXY proxy.corp.example:8080; PROXY backup.corp.example:8080; DIRECT";
}
