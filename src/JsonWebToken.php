<?php
namespace Anthonycv\JwtManager;

use \Firebase\JWT\JWT;
use Carbon\Carbon;

/**
 * Class JsonWebToken.
 *
 * @package stormwind\jwt
 */
class JsonWebToken
{
    /**
     * @var string      Secret key for encrypt the tokens.
     */
    private $key;
    /**
     * @var string      Algorithm for encrypt the tokens.
     */
    private $hash;

    /**
     * @var array       Default claims.
     */
    private $claims = [
        "jti" => null,
        "iat" => null,
        "nbf" => null,
    ];

    /**
     * JsonWebToken constructor
     *
     * @param $rawOrClaims      string|array  token enconded or custom claims.
     * @param string $key       Secret key for encrypt the tokens.
     * @param string $hash      Algorithm for encrypt the tokens.
     */
    public function __construct($rawOrClaims, $key = 'Secret Key', $hash = 'HS384')
    {
        $this->hash = $hash;
        $this->key = $key;

        if (is_array($rawOrClaims)) {
            $this->setRequireClaims();
            $this->claims = array_merge($this->claims, $rawOrClaims);

        }
        elseif (is_string($rawOrClaims)) {
            $this->claims = $this->decode($rawOrClaims);
        }
    }

    /**
     * Set default claims with default values.
     */
    private function setRequireClaims()
    {

        $date = Carbon::now();

        $this->claims = [
            "jti" => jtiGenerate(),
            "iat" => $date->timestamp,
            "nbf" => $date->timestamp,
        ];

    }

    /**
     * Get claims as attribute
     *
     * @param $value            Name of claims to get, if vlaue is 'claims' return all claims
     * @return array|mixed      Get claim or array with all claims
     */
    public function __get($value)
    {
        if (in_array($value, array_keys($this->claims))) {
            return ($this->claims[$value])?$this->claims[$value]:$this->claims;
        }elseif ($value == "claims"){
            return $this->claims;
        }
    }

    /**
     * Set claim values
     *
     * @param $key      Name of claim to set.
     * @param $value    Value of claim to set.
     */
    public function __set($key, $value)
    {
        $this->claims[$key] = $value;
    }

    /**
     * Encode token.
     *
     * @return string       Token enconded.
     */
    public function issue()
    {
        return JWT::encode($this->claims, $this->key, $this->hash);
    }

    /**
     * Decode and validate token.
     *
     * @param $raw
     * @return array
     */
    public function decode($raw)
    {

        return (array) JWT::decode($raw, $this->key, [$this->hash]);

    }



}