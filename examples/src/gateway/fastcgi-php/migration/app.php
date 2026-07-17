<?php
/**
 * PHP application for the rama-fastcgi-php **migration** example.
 *
 * This file intentionally implements *all four* routes the demo exercises:
 *
 *   /api/health    ← unreachable: rama serves this natively in Rust
 *   /api/version   ← unreachable: rama serves this natively in Rust
 *   /api/users     ← reached via FastCGI fallback
 *   /              ← reached via FastCGI fallback (catch-all)
 *
 * Every payload carries `"source": "php"` so the test script can assert which
 * side of the migration boundary actually handled the request.
 */

header('Content-Type: application/json');

$path = $_SERVER['REQUEST_URI'] ?? '/';
// Strip query string for routing.
$path = strtok($path, '?');

switch ($path) {
    case '/api/health':
        echo json_encode([
            'status' => 'ok',
            'source' => 'php',
            'note'   => 'You should never see this — rama serves /api/health natively.',
        ]) . "\n";
        break;
    case '/api/version':
        echo json_encode([
            'version' => '0.0.0',
            'source'  => 'php',
            'note'    => 'You should never see this — rama serves /api/version natively.',
        ]) . "\n";
        break;
    case '/api/users':
        echo json_encode([
            'users'  => ['alice', 'bob', 'carol'],
            'source' => 'php',
        ]) . "\n";
        break;
    default:
        echo json_encode([
            'message' => 'hello from the legacy PHP backend',
            'path'    => $path,
            'source'  => 'php',
        ]) . "\n";
        break;
}
