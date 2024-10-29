<?php
// RADIUS server details
$radius_server = '192.168.15.254';  // Your RADIUS server IP
$radius_secret = 'jazenetworks'; // RADIUS shared secret
$radius_port = 1812; // Default port for RADIUS

// Firebox shared secret for generating signature
$shared_secret = 'jazenetworks';

// Get the form data
$username = $_POST['username'];
$password = $_POST['password'];
$ts = $_POST['ts'];
$sn = $_POST['sn'];
$mac = $_POST['mac'];
$redirect = $_POST['redirect'];

// Function to authenticate with RADIUS
function authenticateWithRadius($username, $password, $server, $secret, $port) {
    $radius = radius_auth_open();
    radius_add_server($radius, $server, $port, $secret, 5);
    radius_create_request($radius, RADIUS_ACCESS_REQUEST);
    radius_put_attr($radius, RADIUS_USER_NAME, $username);
    radius_put_attr($radius, RADIUS_USER_PASSWORD, $password);
    
    $result = radius_send_request($radius);
    return ($result == RADIUS_ACCESS_ACCEPT);
}

$success = authenticateWithRadius($username, $password, $radius_server, $radius_secret, $radius_port) ? 1 : 0;
$sess_timeout = $success ? 1200 : 0; // 20-minute session timeout if successful
$idle_timeout = $success ? 600 : 0;  // 10-minute idle timeout if successful

// Generate the signature (SHA1 hash)
$sig = sha1($ts . $sn . $mac . $success . $sess_timeout . $idle_timeout . $shared_secret);

// Build the access decision URL
$decision_url = "http://10.10.0.1:4106/wgcgi.cgi?action=hotspot_auth&ts=$ts&success=$success&sess_timeout=$sess_timeout&idle_timeout=$idle_timeout&sig=$sig&redirect=" . urlencode($redirect);

// Redirect the user to the decision URL
header("Location: $decision_url");
exit();
?>
