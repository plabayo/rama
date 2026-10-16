pub(crate) const SCRIPT: &str = include_str!("../fixtures/representative.pac");

// Equal weight for five routing paths; deliberately no external DNS or HTTP.
pub(crate) const CASES: [(&str, &str); 5] = [
    ("http://printer/status", "DIRECT"),
    ("https://wiki.corp.example/docs", "DIRECT"),
    ("http://10.23.4.5/status", "DIRECT"),
    (
        "https://updates.vendor.example/download",
        "PROXY vendor-proxy.corp.example:8080; DIRECT",
    ),
    (
        "https://www.example.com/news",
        "PROXY proxy.corp.example:8080; PROXY backup.corp.example:8080; DIRECT",
    ),
];
