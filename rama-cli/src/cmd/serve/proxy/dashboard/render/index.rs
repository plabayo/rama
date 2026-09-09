use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_index(
    session: &str,
) -> impl IntoHtml + IntoResponse {
    let session_signal = ("'", session, "'");
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width,initial-scale=1"
            ),
            title!("Rama Proxy Inspector"),
            link!(
                rel = "icon",
                r#type = "image/svg+xml",
                href = "/assets/rama-logo.svg"
            ),
            link!(rel = "stylesheet", href = "/assets/style.css"),
            script!(r#type = "module", src = "/assets/datastar.js"),
            script!(r#type = "module", src = "/assets/har.js"),
            script!(r#type = "module", src = "/assets/details.js"),
            script!(r#type = "module", src = "/assets/live.js"),
            script!(r#type = "module", src = "/assets/preferences.js"),
            script!(r#type = "module", src = "/assets/control.js"),
        ),
        body!(
            "data-inspector-session" = session,
            "data-signals:session" = session_signal,
            "data-signals:search" = "''",
            "data-signals:connection_id" = "''",
            "data-signals:user_agent" = "''",
            "data-signals:endpoint" = "''",
            "data-signals:method" = "''",
            "data-signals:status" = "''",
            "data-signals:protocol" = "''",
            "data-signals:websocket_direction" = "'ingress'",
            "data-signals:websocket_kind" = "'text'",
            "data-signals:websocket_payload" = "''",
            "data-init" = "@get('/events')",
            header!(
                class = "topbar",
                a!(
                    class = "brand",
                    href = "/",
                    "data-inspector-focus" = "overview",
                    img!(
                        class = "mark",
                        src = "/assets/rama-logo.svg",
                        alt = "Rama noodle logo"
                    ),
                    h1!("Rama Proxy Inspector")
                ),
                div!(
                    class = "header-actions",
                    a!(class = "ca-link", href = "/ca.pem", "MITM CA"),
                    div!(
                        class = "inspection-controls",
                        button!(
                            r#type = "button",
                            class = "ghost inspection-pause",
                            "data-indicator:inspection_busy" = "",
                            "data-attr:disabled" = "$inspection_busy",
                            "data-on:click" = "@post('/api/inspection/pause')",
                            span!(class = "button-spinner", "aria-hidden" = "true"),
                            span!(class = "inspection-action-label", "Pause inspector")
                        ),
                        button!(
                            r#type = "button",
                            class = "inspection-resume",
                            "data-indicator:inspection_busy" = "",
                            "data-attr:disabled" = "$inspection_busy",
                            "data-on:click" = "@post('/api/inspection/resume')",
                            span!(class = "button-spinner", "aria-hidden" = "true"),
                            span!(class = "inspection-action-label", "Resume inspector")
                        )
                    ),
                    span!(
                        id = "connection-status",
                        class = "live-pill is-connecting",
                        role = "status",
                        "aria-live" = "polite",
                        span!(class = "pulse"),
                        span!("data-live-label" = "", "connecting")
                    )
                ),
            ),
            div!(
                id = "har-notice",
                class = "notice",
                role = "status",
                "aria-live" = "polite",
                hidden = ""
            ),
            iframe!(
                name = "har-download",
                class = "har-download",
                title = "HAR download"
            ),
            main!(
                section!(
                    class = "filter-panel",
                    div!(
                        class = "filter-head",
                        div!(h2!("Filters"), p!("Narrow this inspector session")),
                        button!(
                            r#type = "button",
                            class = "ghost clear-filters",
                            "data-reset-preferences" = "",
                            "data-on:click" = "$search = ''; $connection_id = ''; $user_agent = ''; $endpoint = ''; $method = ''; $status = ''; $protocol = ''; @post('/api/filter/reset')",
                            "Reset filters"
                        )
                    ),
                    div!(
                        class = "filters",
                        label!(
                            class = "filter-search",
                            span!("Headers & payload"),
                            input!(
                                r#type = "search",
                                placeholder = "Search URL, header, fingerprint or payload…",
                                "data-persist-filter" = "search",
                                "data-bind:search" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-endpoint",
                            span!("Endpoint"),
                            input!(
                                r#type = "search",
                                placeholder = "api.example.com",
                                "data-persist-filter" = "endpoint",
                                "data-bind:endpoint" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-user-agent",
                            span!("User agent"),
                            input!(
                                r#type = "search",
                                placeholder = "Chromium, curl…",
                                "data-persist-filter" = "user_agent",
                                "data-bind:user_agent" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-connection",
                            span!("Connection"),
                            input!(
                                r#type = "search",
                                inputmode = "numeric",
                                placeholder = "#42",
                                "data-persist-filter" = "connection_id",
                                "data-bind:connection_id" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-method",
                            span!("Method"),
                            select!(
                                "data-bind:method" = "",
                                "data-persist-filter" = "method",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All methods"),
                                option!(value = "GET", "GET"),
                                option!(value = "POST", "POST"),
                                option!(value = "PUT", "PUT"),
                                option!(value = "PATCH", "PATCH"),
                                option!(value = "DELETE", "DELETE"),
                                option!(value = "CONNECT", "CONNECT"),
                            )
                        ),
                        label!(
                            class = "filter-status",
                            span!("Status"),
                            select!(
                                "data-bind:status" = "",
                                "data-persist-filter" = "status",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All statuses"),
                                option!(value = display(StatusQuery::Pending), "Pending"),
                                [
                                    StatusQuery::Informational,
                                    StatusQuery::Success,
                                    StatusQuery::Redirection,
                                    StatusQuery::ClientError,
                                    StatusQuery::ServerError,
                                ]
                                .into_iter()
                                .map(|status| option!(value = display(status), display(status))),
                            )
                        ),
                        label!(
                            class = "filter-protocol",
                            span!("Protocol"),
                            select!(
                                "data-bind:protocol" = "",
                                "data-persist-filter" = "protocol",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All protocols"),
                                option!(value = "http", "HTTP"),
                                option!(value = "https", "HTTPS"),
                                option!(value = "ws", "WS"),
                                option!(value = "wss", "WSS"),
                                option!(value = "other", "Other"),
                            )
                        ),
                    ),
                    details!(
                        class = "mitm-scope",
                        summary!(
                            div!(
                                strong!("MITM domain scope"),
                                span!(
                                    "Choose which new connections are inspected; deny always wins"
                                )
                            ),
                            span!(class = "scope-summary", "Shared by all dashboards")
                        ),
                        div!(
                            class = "scope-editor",
                            label!(
                                span!("MITM scope"),
                                select!(
                                    id = "mitm-mode",
                                    option!(value = "all", "All eligible hosts"),
                                    option!(value = "selected", "Selected hosts only"),
                                    option!(value = "none", "No hosts")
                                )
                            ),
                            label!(
                                span!("Allow domains"),
                                textarea!(
                                    id = "mitm-allow",
                                    rows = "2",
                                    placeholder = "example.com, *.internal.test",
                                    "data-mitm-policy" = "allow"
                                ),
                                small!(
                                    "When non-empty, unmatched domains pass through without inspection."
                                )
                            ),
                            label!(
                                span!("Deny domains"),
                                textarea!(
                                    id = "mitm-deny",
                                    rows = "2",
                                    placeholder = "accounts.example.com",
                                    "data-mitm-policy" = "deny"
                                ),
                                small!(
                                    "Plain domains include subdomains; prefix = for an exact host. Deny overrides allow."
                                )
                            ),
                            div!(
                                class = "scope-actions",
                                span!(
                                    id = "mitm-policy-status",
                                    role = "status",
                                    "aria-live" = "polite"
                                ),
                                button!(
                                    r#type = "button",
                                    class = "ghost",
                                    "data-apply-mitm-policy" = "",
                                    "Apply scope"
                                )
                            )
                        )
                    ),
                ),
                PreEscaped(CONTROL_HTML),
                section!(
                    id = "live",
                    class = "live-shell",
                    span!(id = "live-heartbeat", hidden = "", "data-sequence" = ""),
                    p!("Connecting…")
                ),
            ),
            dialog!(
                id = "clear-captures-dialog",
                class = "confirm-dialog",
                h2!("Clear captured traffic?"),
                p!(
                    "This removes every connection, request, response, and encrypted capture file from this inspector process. Active traffic can appear again immediately."
                ),
                div!(
                    class = "dialog-actions",
                    button!(
                        r#type = "button",
                        class = "ghost",
                        "data-close-clear" = "",
                        "Cancel"
                    ),
                    button!(
                        r#type = "button",
                        class = "danger",
                        "data-confirm-clear" = "",
                        "data-on:click" = "@post('/api/captures/clear')",
                        "Clear captured traffic"
                    )
                )
            ),
        ),
    )
}

#[cfg(test)]
pub(in crate::cmd::serve::proxy::dashboard) fn escape_js_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
}
