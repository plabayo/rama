<?php
/**
 * PHP front controller for the rama-fastcgi-php **gateway** example.
 *
 * The rama gateway terminates HTTPS, converts the request to FastCGI, and
 * forwards every URL here. This file echoes back a JSON document describing
 * what php-fpm observed — proving the round trip preserves method, path,
 * query string, headers, and request body.
 *
 * No routing: rama is the gateway, this is the application.
 */

header('Content-Type: application/json');

$headers = [];
foreach ($_SERVER as $name => $value) {
    if (strpos($name, 'HTTP_') === 0) {
        // Convert HTTP_X_CUSTOM → x-custom (lowercase, dashes).
        $headers[strtolower(str_replace('_', '-', substr($name, 5)))] = $value;
    }
}

$body = file_get_contents('php://input');

echo json_encode([
    'source'           => 'php',
    'method'           => $_SERVER['REQUEST_METHOD'] ?? null,
    'request_uri'      => $_SERVER['REQUEST_URI'] ?? null,
    'script_name'      => $_SERVER['SCRIPT_NAME'] ?? null,
    'script_filename'  => $_SERVER['SCRIPT_FILENAME'] ?? null,
    'query_string'     => $_SERVER['QUERY_STRING'] ?? null,
    'server_protocol'  => $_SERVER['SERVER_PROTOCOL'] ?? null,
    'gateway'          => $_SERVER['GATEWAY_INTERFACE'] ?? null,
    'https'            => $_SERVER['HTTPS'] ?? null,
    'remote_addr'      => $_SERVER['REMOTE_ADDR'] ?? null,
    'headers'          => $headers,
    'body'             => $body,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
