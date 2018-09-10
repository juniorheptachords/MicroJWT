<?php
include("MicroJWT.php");

$microJwt = new MicroJWT("adamngoodsecret", "HS256");

$data = array("username"=>"johndoe"); // An array of datas
$expiration = 24 * 60 * 60; // Expiration set for 24h

$token = $microJwt->encode($data, $expiration);

echo($token);
echo'<br/>';

$decoded = $microJwt->decode($token);

var_dump($decoded);
echo'<br/>';
