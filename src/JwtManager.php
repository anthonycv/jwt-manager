<?php
namespace Anthonycv\JwtManager;

use Carbon\Carbon;
use Exception;
use Predis\Client;

/**
 * Class JwtManager
 *
 * @package Stormwind\Jwt
 */
class JwtManager
{

    /**
     * @var Client      Class cache driver (Redis).
     */
    private $_redis;
    /**
     * @var array       Configuration param for Client (Redis).
     */
    private $redisConf;

    /**
     * @var bool        Enable and disable refresh token option.
     */
    private $enableRefresh;
    /**
     * @var int         Minutues of duration of common token.
     */
    private $expCommon;
    /**
     * @var int         Minutues of duration of refresh token.
     */
    private $expRefresh;

    /**
     * @var stdClass    Token decoded.
     */
    private $jwt;
    /**
     * @var string      Id of token in whitelist.
     */
    private $jwtId;
    /**
     * @var string      Secret key for encrypt the tokens.
     */
    private $key;
    /**
     * @var string      Algorithm for encrypt the tokens.
     */
    private $hash;


    /**
     * JwtManager constructor.
     *
     * @param bool $enableRefresh          Refresh token option if true, generate a refresh token.
     * @param string $key                  Secret key for encrypt the tokens.
     * @param string $hash                 Algorithm for encrypt the tokens.
     * @param int $expCommon               Minutues of duration of common token.
     * @param int $expRefresh              Minutues of duration of refresh token.
     */
    public function __construct($enableRefresh = true, $key = 'Secret Key', $hash = 'HS384', $expCommon = 9980, $expRefresh = 15)
    {

        $this->redisConf = [
            "host" => "redis",
            "port" => 6379
        ];

        $this->_redis = new Client($this->redisConf);

        $this->enableRefresh = $enableRefresh;
        $this->expCommon = $expCommon;
        $this->expRefresh = $expRefresh;
        $this->jwt = null;
        $this->jwtId = null;
        $this->key = $key;
        $this->hash = $hash;
        $this->jwtId = 'jti';
    }


    /**
     * Generate tokens, set default and custom claims and add to whitelist, if refresh token option is enable then create
     * refresh token, relationated to the common token.
     *
     * @param array $claims          custom claims (uid is required).
     * @return array|string          common and refresh tokens encoded.
     *
     * @throws Exception             uid claim is null or not exist.
     */
    public function issue($claims = array())
    {

        try{

            if (!key_exists('uid', $claims) AND empty($claim['uid'])){
                throw new Exception('uid claim is required');
            }
            $jwtCommon = new JsonWebToken(($claims)?$claims:null, $this->key, $this->hash);

            $date = Carbon::createFromTimestamp($jwtCommon->iat);

            $jwtCommon->exp = $date->addMinutes($this->expCommon)->timestamp;

            if($this->enableRefresh) {

                $jwtRefresh = new JsonWebToken(($claims)?$claims:null, $this->key, $this->hash);

                $date = Carbon::createFromTimestamp($jwtCommon->iat);

                $jwtRefresh->exp = $date->addMinutes($this->expRefresh)->timestamp;

                $jwtRefresh->rtt = $jwtCommon->jti;

                $jwtCommon->rti = $jwtRefresh->jti;

            }

            $raws = [];

            $raws['common'] = $jwtCommon->issue();

            if ($this->enableRefresh){
                $raws['refresh'] = $jwtRefresh->issue();
            }

            $this->addWhiteList($raws);

            return $raws;

        }catch (Exception $e) {

            return 'Error: ' . $e->getMessage();

        }
    }

    /**
     * Decode a token into a object for access the claims use the name claim like attribute, exmaple: $token->jti.
     *
     * @param $raw                   token encoded.
     * @param $hash                  hash for decrypt.
     * @return JwtCommon|string
     *
     * @throws Exception             structure wrong of token.
     */
    public function decode($raw, $hash = null)
    {
        try{

            $hash = ($hash)?$hash:$this->hash;

            $this->jwt = new JsonWebToken($raw, $this->key, $hash);

//            echo "<pre>";
//            print_r($this->jwt);
//            echo "</pre>";
//            die(".as..");

            return $this->jwt;

        }catch (Exception $e) {

            return 'Error: ' . $e->getMessage();

        }

    }


    /**
     * Add to the white list a token.
     *
     * @param $raws                     token encoded.
     * @return bool|string
     *
     * @throws Exception                Throws of decode function.
     */
    private function addWhiteList($raws)
    {

        foreach ($raws as $raw) {

            $this->decode($raw);

            $this->_redis->set($this->jwt->{$this->jwtId}, $raw);

        }

        return true;

    }


    /**
     * Validate a token exist in the white list and the format.
     *
     * @param $raw               token encoded
     * @return array             status = valid or invalid ; message = in case status is invalid contains a error message.
     *
     * @throws Exception         Tokens is not in whitelist - referent between token is not valid.
     */
    public function validate($raw)
    {

        try{

            $reponse = $this->decode($raw);

            if(is_string($reponse)){
                throw new Exception($reponse);
            }

            if (empty($this->_redis->get($this->jwt->{$this->jwtId}) OR is_string($reponse))){;
                throw new Exception('Error: jwt no whitelisted');
            }

            return true;

        }catch (Exception $e) {

            return $e->getMessage();

        }
    }


    /**
     * Remove a token from the white list.
     *
     * @param $raw              encoded token.
     * @return bool|string
     *
     * @throws Exception                Throws of decode function.
     */
    public function removeWhiteList($raw)
    {

        $response = $this->decode($raw);
        $this->_redis->del($this->jwt->{$this->jwtId});

        if(is_object($response)){
            return true;
        }else{
            return $response;
        }


    }


}