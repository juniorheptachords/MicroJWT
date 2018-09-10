<?php

/**
 * MicroJWT (μJWT)
 */
class MicroJWT {

	/**
	 * @var string Secret
	 */
	protected $secret;

	/**
	 * @var numeric date Expiration date
	 */
	protected $headers;


	/**
	 * Constructor
	 *
	 * @param string $secret The secret used to hash
	 * @param string $algo Either HS256 or HS384 or HS512
	 */
	public function __construct( $secret, $algo) {
		$this->secret = $secret;
		$this->headers = array("alg"=>$algo, "typ"=>"JWT");
	}

	/**
	 * Gets the API client to perform raw API calls.
     *
	 * @param array $datas
	 * @param int $expiration
	 *
	 * @return string The token
	 */
	public function encode($datas, $expiration = null) {
		$payload = $datas;

		if(!empty($expiration) && is_int($expiration)){
			date_default_timezone_set("UTC");
			$payload["exp"] = time() + $expiration;
		}

		$base64_headers = $this->base64UrlEncode(json_encode($this->headers));
		$base64_payload = $this->base64UrlEncode(json_encode($payload));
        $signature = $this->sign($base64_headers . '.' . $base64_payload);

        $token = $base64_headers . '.' . $base64_payload . '.' . $signature;

		return json_encode($token);
	}

    /**
     * Decode the token
     *
     * @param string $token The token
     *
     * @return array Array with headers and payload
     */
	public function decode($token) {

        // Check if token is valid
        if(!$this->verify($token)){
            return false;
        }

        $token = json_decode($token);

        // Split the token
        $token = explode(".", $token);

		$base64_headers = $token[0];
		$base64_payload = $token[1];
		$signature = $token[2];

        $headers = json_decode($this->base64UrlDecode($base64_headers),true);
        $payload = json_decode($this->base64UrlDecode($base64_payload),true);

        return array("headers" => $headers, "payload" => $payload);
	}

    /**
     * Check if the token is valid
     *
     * @param string $token The token
     */
	public function verify($token) {
        $token = json_decode($token);

        // Split the token
		$token = explode(".", $token);

		$base64_headers = $token[0];
		$base64_payload = $token[1];
		$signature = $token[2];

        // Recreate the signature with the secret to compare it with the given signature
        $signature_check = $this->sign($base64_headers . '.' . $base64_payload);

        // Decode payload to get the expiration from it
        $payload = json_decode($this->base64UrlDecode($base64_payload),true);

        if(isset($payload["exp"]) && ! empty($payload["exp"])){
            return time() < $payload["exp"] && hash_equals($signature, $signature_check);
        }else{
            return hash_equals($signature, $signature_check);
        }
	}

	/**
	 * Encode a string with URL-safe Base64.
	 *
	 * @param string $input The string you want encoded
	 *
	 * @return string The base64 encode of what you passed in
	 */
	protected function base64UrlEncode($input){
		return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
	}

    /**
	 * Decode a string with URL-safe Base64.
	 *
	 * @param string $input A Base64 encoded string
	 *
	 * @return string A decoded string
	 */
	protected function base64UrlDecode($input)
	{
		$remainder = strlen($input) % 4;
		if ($remainder) {
			$padlen = 4 - $remainder;
			$input .= str_repeat('=', $padlen);
		}
		return base64_decode(strtr($input, '-_', '+/'));
	}

    /**
	 * Sign a string with the secret and the algorithm set in the constructor
	 *
	 * @param string $msg The string to sign
	 *
	 * @return string The signed string
	 */
	protected function sign($msg)
	{
		$methods = array(
			'HS256' => 'sha256',
			'HS384' => 'sha384',
			'HS512' => 'sha512',
		);
		if (empty($methods[$this->headers["alg"]])) {
			throw new DomainException('Algorithm not supported');
		}
		return hash_hmac($methods[$this->headers["alg"]], $msg, $this->secret);
	}
}
?>
