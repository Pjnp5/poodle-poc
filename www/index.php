<?php
// Start session and set session cookie
session_start();

// Set session data
$_SESSION['username'] = 'admin';
$_SESSION['role'] = 'administrator';
$_SESSION['login_time'] = time();

// Generate a realistic JWT-like auth token (base64 encoded JSON)
$token_payload = array(
    'user_id' => 1337,
    'username' => 'admin',
    'role' => 'administrator',
    'issued_at' => time(),
    'expires_at' => time() + 3600
);
$token_json = json_encode($token_payload);
$auth_token = base64_encode($token_json) . '.' . bin2hex(openssl_random_pseudo_bytes(16));

// Set authentication cookies (these are what we'll try to steal)
// Note: secure flag set to false to work with self-signed certs in PoC environment
setcookie('auth_token', $auth_token, time() + 3600, '/', '', false, false);
setcookie('user_id', '1337', time() + 3600, '/', '', false, false);
setcookie('session_secret', bin2hex(openssl_random_pseudo_bytes(20)), time() + 3600, '/', '', false, false);

// Store the auth_token for display
$_SESSION['auth_token'] = $auth_token;

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POODLE PoC - Vulnerable Server (SSLv3)</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #d9534f; }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover { background: #0056b3; }
        .log {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 10px;
            margin-top: 20px;
            max-height: 200px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 12px;
        }
        code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>WARNING: POODLE PoC - Vulnerable SSLv3 Server</h1>

        <div class="warning">
            <strong>Warning:</strong> This server is intentionally vulnerable to POODLE attack!<br>
            Protocol: <strong>SSLv3 ONLY</strong><br>
            Cipher: <strong>CBC mode (vulnerable)</strong>
        </div>

        <div class="info">
            <h3>Cookies Set:</h3>
            <ul>
                <li><code>auth_token</code>: <?php echo htmlspecialchars(substr($_SESSION['auth_token'], 0, 50)) . '...'; ?></li>
                <li><code>user_id</code>: 1337</li>
                <li><code>session_secret</code>: (40 random hex chars)</li>
                <li><code>PHPSESSID</code>: <?php echo session_id(); ?></li>
            </ul>
            <p style="margin-top: 10px; font-size: 12px;">
                <strong>Auth Token Decoded:</strong><br>
                <?php
                    $parts = explode('.', $_SESSION['auth_token']);
                    $decoded = json_decode(base64_decode($parts[0]), true);
                    echo 'User: ' . $decoded['username'] . '<br>';
                    echo 'Role: ' . $decoded['role'] . '<br>';
                    echo 'Expires: ' . date('Y-m-d H:i:s', $decoded['expires_at']);
                ?>
            </p>
        </div>

        <h3>Current Session Info:</h3>
        <p>
            Username: <strong><?php echo $_SESSION['username']; ?></strong><br>
            Role: <strong><?php echo $_SESSION['role']; ?></strong><br>
            Login Time: <strong><?php echo date('Y-m-d H:i:s', $_SESSION['login_time']); ?></strong>
        </p>

        <h3>Generate Traffic (for POODLE attack):</h3>
        <p>Click the button below to send repeated HTTPS requests with cookies:</p>
        <button onclick="startRequests()">Start Sending Requests</button>
        <button onclick="stopRequests()">Stop Requests</button>
        <button onclick="clearLog()">Clear Log</button>

        <div class="log" id="log"></div>
    </div>

    <script>
        let intervalId = null;
        let requestCount = 0;

        function log(message) {
            const logDiv = document.getElementById('log');
            const timestamp = new Date().toLocaleTimeString();
            logDiv.innerHTML += `[${timestamp}] ${message}<br>`;
            logDiv.scrollTop = logDiv.scrollHeight;
        }

        function startRequests() {
            if (intervalId) {
                log('[WARNING] Already running!');
                return;
            }

            log('[INFO] Started sending requests...');

            // Send requests every 2 seconds
            intervalId = setInterval(() => {
                requestCount++;
                fetch('/api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'action=heartbeat&count=' + requestCount,
                    credentials: 'include'  // Include cookies
                })
                .then(response => response.json())
                .then(data => {
                    log(`[REQUEST] #${requestCount} - Response: ${data.status}`);
                })
                .catch(error => {
                    log(`[ERROR] Request #${requestCount} - Error: ${error.message}`);
                });
            }, 2000);
        }

        function stopRequests() {
            if (intervalId) {
                clearInterval(intervalId);
                intervalId = null;
                log('[INFO] Stopped sending requests');
            } else {
                log('[WARNING] No requests running');
            }
        }

        function clearLog() {
            document.getElementById('log').innerHTML = '';
            requestCount = 0;
        }

        // Auto-start on page load
        log('[INFO] Page loaded. Cookies have been set.');
        log('[INFO] Check cookies in browser DevTools (Application > Cookies)');
        log('[INFO] Click "Start Sending Requests" to generate traffic for POODLE attack');
    </script>
</body>
</html>
