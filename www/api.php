<?php
session_start();

// This endpoint receives requests and sends back responses with cookies
header('Content-Type: application/json');

$action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : 'unknown');
$count = isset($_POST['count']) ? $_POST['count'] : (isset($_GET['count']) ? $_GET['count'] : 0);

// Return session data (this proves cookies were sent)
$response = [
    'status' => 'success',
    'action' => $action,
    'count' => intval($count),
    'timestamp' => time(),
    'session_id' => session_id(),
    'cookies_received' => [
        'auth_token' => isset($_COOKIE['auth_token']) ? 'present' : 'missing',
        'user_id' => isset($_COOKIE['user_id']) ? $_COOKIE['user_id'] : 'missing',
        'session_secret' => isset($_COOKIE['session_secret']) ? 'present' : 'missing'
    ],
    'message' => 'Request processed with cookies via SSLv3'
];

echo json_encode($response, JSON_PRETTY_PRINT);
?>
