BEGIN;

CREATE TABLE IF NOT EXISTS "public-ua-profiles" (
  uastr TEXT PRIMARY KEY,
  h1_settings JSON,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  h1_headers_navigate JSON,
  h1_headers_fetch JSON,
  h1_headers_xhr JSON,
  h1_headers_form JSON,
  h1_headers_ws JSON,
  h2_settings JSON,
  h2_headers_navigate JSON,
  h2_headers_fetch JSON,
  h2_headers_xhr JSON,
  h2_headers_form JSON,
  h2_headers_ws JSON,
  tls_client_hello JSON,
  tls_ws_client_config_overwrites JSON,
  js_web_apis JSON,
  source_info JSON
);

CREATE TABLE IF NOT EXISTS "ua-profiles" (
  uastr TEXT PRIMARY KEY,
  h1_settings JSON,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  h1_headers_navigate JSON,
  h1_headers_fetch JSON,
  h1_headers_xhr JSON,
  h1_headers_form JSON,
  h1_headers_ws JSON,
  h2_settings JSON,
  h2_headers_navigate JSON,
  h2_headers_fetch JSON,
  h2_headers_xhr JSON,
  h2_headers_form JSON,
  h2_headers_ws JSON,
  tls_client_hello JSON,
  tls_ws_client_config_overwrites JSON,
  js_web_apis JSON,
  source_info JSON
);

COMMIT;
