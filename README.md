## CLASSE PHP CRYPTA/DECRYPTA MENSAGENS CHAVE ASSIMÉTRICAS RSA 

    
    include("./resa.class.php");
    $getkey 			= rsa::createSSLKey();
    $encryptPrivateSSL  = rsa::encryptPrivateSSL("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",$getkey[0]);
    $encryptPublicSSL   = rsa::encryptPublicSSL("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",$getkey[1]);

## DecryptPrivateSSL(encryptPublicSSL)

    echo rsa::decryptPrivateSSL($encryptPublicSSL,$getkey[0]);

## decryptPublicSSL(encryptPrivateSSL)

    echo rsa::decryptPublicSSL($encryptPrivateSSL,$getkey[1]);