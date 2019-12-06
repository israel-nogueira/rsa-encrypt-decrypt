<?php
/**
* Class and Function List:
* Function list:
* - __construct()
* - fixKeyArgument()
* - create()
* - getPublicKeyFile()
* - getPrivateKeyFile()
* - setPassword()
* - encrypt()
* - base64Encrypt()
* - decrypt()
* - base64Decrypt()
* Classes list:
* - RSA
*/

class RSA {
	const MINIMUM_KEY_SIZE = 128;
	const DEFAULT_KEY_SIZE = 2048;
	protected $publicKeyFile;
	protected $privateKeyFile;
	protected $password;
	public function __construct($publicKeyFile, $privateKeyFile = null, $password = null) {
		$this->publicKeyFile = $this->fixKeyArgument($publicKeyFile);
		$this->privateKeyFile = $this->fixKeyArgument($privateKeyFile);
		$this->password = $password;
	}

	public function fixKeyArgument($keyFile) {
		if (strpos($keyFile, '/') === 0) {
			return 'file://' . $keyFile;
		}
		return $keyFile;
	}
	public function create($keySize = null, $overwrite = false) {
		$keySize = intval($keySize);
		if ($keySize < self::MINIMUM_KEY_SIZE) {
			$keySize = self::DEFAULT_KEY_SIZE;
		}

		if (!$overwrite) {
			if ((strpos($this->publicKeyFile, 'file://') === 0 && file_exists($this->publicKeyFile)) || (strpos($this->privateKeyFile, 'file://') === 0 && file_exists($this->privateKeyFile))) {
				throw new Exception('OpenSSL: Chaves existentes encontradas. Remova as chaves ou passe $overwrite == true.');
			}
		}

		$resource = openssl_pkey_new(array(
			'private_key_bits' => $keySize,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		));

		$publicKey = openssl_pkey_get_details($resource) ['key'];
		if (strpos($this->publicKeyFile, 'file://') === 0) {
			$bytes = file_put_contents($this->publicKeyFile, $publicKey);
		}
		else {
			$this->publicKeyFile = $publicKey;
			$bytes = strlen($publicKey);
		}
		if (strlen($publicKey) < 1 || $bytes != strlen($publicKey)) {
			throw new Exception("OpenSSL: Erro ao escrever a PublicKey.");
		}

		$privateKey = '';
		openssl_pkey_export($resource, $privateKey, $this->password);
		if (strpos($this->privateKeyFile, 'file://') === 0) {
			$bytes = file_put_contents($this->privateKeyFile, $privateKey);
		}
		else {
			$this->privateKeyFile = $privateKey;
			$bytes = strlen($privateKey);
		}
		if (strlen($privateKey) < 1 || $bytes != strlen($privateKey)) {
			throw new Exception("OpenSSL: Erro ao escrever a PrivateKey.");
		}

		openssl_pkey_free($resource);

		return true;
	}
	public function getPublicKeyFile() {
		return $this->publicKeyFile;
	}
	public function getPrivateKeyFile() {
		return $this->privateKeyFile;
	}
	public function setPassword($password) {
		$this->password = $password;
	}

	public function encrypt($data) {
		$publicKey = openssl_pkey_get_public($this->publicKeyFile);

		if (!$publicKey) {
			throw new Exception("OpenSSL: Não foi possível obter a chave pública para criptografia. O local está correto? Essa chave requer uma senha?");
		}

		$success = openssl_public_encrypt($data, $encryptedData, $publicKey);
		openssl_free_key($publicKey);
		if (!$success) {
			throw new Exception("Falha na criptografia. Verifique se você está usando uma chave PUBLIC.");
		}

		return $encryptedData;
	}
	public function base64Encrypt($data) {
		return base64_encode($this->encrypt($data));
	}
	public function decrypt($data) {
		if ($this->privateKeyFile === null) {
			throw new Exception("Não foi possível descriptografar: nenhuma chave privada foi fornecida.");
		}

		$privateKey = openssl_pkey_get_private($this->privateKeyFile, $this->password);
		if (!$privateKey) {
			throw new Exception('OpenSSL: Não foi possível obter a chave privada para descriptografia. O local está correto? Se essa chave exigir uma senha, você forneceu a senha correta?');
		}

		$success = openssl_private_decrypt($data, $decryptedData, $privateKey);
		openssl_free_key($privateKey);
		if (!$success) {
			throw new Exception("A descriptografia falhou. Verifique se você está usando uma chave PRIVADA e se ela está correta.");
		}

		return $decryptedData;
	}
	public function base64Decrypt($data) {
		return $this->decrypt(base64_decode($data));
	}
}


