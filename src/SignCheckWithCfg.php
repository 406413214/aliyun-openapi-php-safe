<?php

namespace Heroin\Aliyun\Wsgsvr;

class SignCheckWithCfg {

    public function __construct($cfg)
    {
        ConfigParser::instance($cfg);
    }

    public function DoSignCheck($input, $appKey, $sign)
    {
        if(gettype($input) !== "string" || gettype($appKey) !== "string" || gettype($sign) != "string" || $input === "" || $appKey === "" || $sign === "")
            throw new WsgException("", WsgException::ErrInputData);
        $cf = ConfigParser::instance(NULL);
        if($cf === NULL)
            return FALSE;
        $appSecret = $cf->GetSecret($appKey);
        if($appSecret === FALSE)
            return FALSE;
        return WsgUtil::checkHmacsha1($appSecret, $input, $sign);
    }

    public function SimSignCheck($input, $appKey, $sign, &$isSim)
    {
        if(gettype($input) !== "string" || gettype($appKey) != "string" || gettype($sign) != "string" || gettype($isSim) != "boolean" || $input === "" || $appKey === "" || $sign === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $cf = ConfigParser::instance(NULL);
        if($cf === NULL)
            return FALSE;
        $appSecret = $cf->GetSecret($appKey);
        if($appSecret === FALSE)
            return FALSE;
        $sim = substr($sign,0,1);
        if($sim !== "0")
        {
            $isSim = true;
        }
        else
        {
            $isSim = false;
        }
        $sign = substr($sign, 1);
        $input = $sim . $input;
        return WsgUtil::checkHmacsha1($appSecret, $input, $sign);
    }

    public function AtlasSignCheck($input, $appKey, $sign)
    {
        if(gettype($input) !== "string" || gettype($appKey) != "string" || gettype($sign) != "string" || $input === "" || $appKey === "" || $sign === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $cf = ConfigParser::instance(NULL);
        if($input && $appKey && $sign && $cf)
        {
            $secret = $cf->GetSecret($appKey);
            $plain = $input . "&" . $secret;
            $version = substr($sign, 0, 9);
            $iv = $cf->GetSecret("iv");
            $content = $version . $plain;
            $atlasSecret = $cf->GetSecret(substr($content, 1, 8));
            $res = WsgUtil::aesCbcEncrypt($atlasSecret, $iv, substr($content,9));
            $encrypted = base64_encode($res);
            return WsgUtil::checkHmacsha1($secret, $encrypted, substr($sign, 9));
        }
        else
            return FALSE;
    }
} 