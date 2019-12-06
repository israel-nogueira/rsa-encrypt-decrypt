<?
class rsa {
	public function __construct() {}

	#####################################################
	#  CRIAMOS CHAVES PUBLICA E PROIVADA E RETORNAMOS 
	#####################################################
	public static function createSSLKey() {
			$ssl_config = array(
										"config" 			=> __DIR__."/openssl.cnf",
										'private_key_bits'	=> 2048,
										'default_md' 		=> "sha256",
								);
			$_CHAVE_LINK		=		openssl_pkey_new($ssl_config);
										openssl_pkey_export($_CHAVE_LINK, $_CHAVE_PRIVADA,NULL,$ssl_config);
			$_CHAVE_PUBLICA		=		openssl_pkey_get_details($_CHAVE_LINK);
			$_CHAVE_PUBLICA		=		$_CHAVE_PUBLICA["key"];
			return [$_CHAVE_PRIVADA,$_CHAVE_PUBLICA];
	}

	#############################################################
	#  DECRYPTA UMA MENSAGEM CRYPTADA POR UMA CHAVE PRIVADA 
	#############################################################
	public function decryptPrivateSSL($data,$privateKey) {
		if ( $privateKey === null) {
			throw new Exception("Não foi possível descriptografar: nenhuma chave privada foi fornecida.");
		}
		$privateKey = openssl_pkey_get_private( $privateKey, null);
		if (!$privateKey) {
			throw new Exception('OpenSSL: Não foi possível obter a chave privada para descriptografia.');
		}
		$success = openssl_private_decrypt(base64_decode($data), $decryptedData, $privateKey);
		openssl_free_key($privateKey);
		if (!$success) {
			throw new Exception("A descriptografia falhou. Verifique se você está usando uma chave PRIVADA válida.");
		}
		return $decryptedData;
	}
	#############################################################
	#  DECRYPTA UMA MENSAGEM CRYPTADA POR UMA CHAVE PUBLICA 
	#############################################################
	public function decryptPublicSSL($data,$publicKey) {
		$publicKey = openssl_pkey_get_public($publicKey);
		if (!$publicKey) {
			throw new Exception('OpenSSL: Não foi possível obter a chave publica para descriptografia.');
		}
		$success = openssl_public_decrypt(base64_decode($data), $decryptedData, $publicKey);
		openssl_free_key($publicKey);
		if (!$success) {
			throw new Exception("A descriptografia falhou. Verifique se você está usando uma chave PUBLICA e se ela está correta.");
		}
		return $decryptedData;
	}
	#####################################################
	#  ENCRYPTA MENSAGEM RSA VIA CHAVE PÚBLICA
	#####################################################
	public static function encryptPublicSSL($_MENSAGEM,$publicKey) { 
		$publicKey = openssl_pkey_get_public($publicKey);
		if (!$publicKey) { throw new Exception("OpenSSL: Não foi possível obter a chave pública para criptografia.");}
		$success = openssl_public_encrypt($_MENSAGEM, $encryptedData, $publicKey);
		openssl_free_key($publicKey);
		if (!$success) { throw new Exception("Falha na criptografia. Verifique se você está usando uma chave PUBLIC.");}
		return base64_encode($encryptedData);
	}
	#############################################################
	#  ENCRYPTA MENSAGEM RSA VIA CHAVE PRIVADA 
	#############################################################	
	public static function encryptPrivateSSL($_MENSAGEM,$privateKey) { 
		$privateKey = openssl_pkey_get_private( $privateKey);
		if (!$privateKey) { throw new Exception("OpenSSL: Não foi possível obter a chave pública para criptografia.");}
		$success = openssl_private_encrypt($_MENSAGEM, $encryptedData, $privateKey);
		openssl_free_key($privateKey);
		if (!$success) { throw new Exception("Falha na criptografia. Verifique se você está usando uma chave PRIVADA.");}
		return base64_encode($encryptedData);
	}
}