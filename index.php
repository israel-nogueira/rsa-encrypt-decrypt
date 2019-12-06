<?

include("./resa.class.php");

$getkey 			= rsa::createSSLKey();
$encryptPrivateSSL  = rsa::encryptPrivateSSL("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",$getkey[0]);
$encryptPublicSSL   = rsa::encryptPublicSSL("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",$getkey[1]);

echo rsa::decryptPrivateSSL($encryptPublicSSL,$getkey[0]);
echo rsa::decryptPublicSSL($encryptPrivateSSL,$getkey[1]);