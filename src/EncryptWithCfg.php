<?php

namespace Heroin\Aliyun\Wsgsvr;

class EncryptWithCfg {

    public function __construct($cfg)
    {
        ConfigParser::instance($cfg);
    }

    public function Encrypt($appKey, $data)
    {
        if(gettype($appKey) !== "string" || gettype($data) != "string" || $appKey === "" || $data === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $cf = ConfigParser::instance(NULL);
        if($cf === NULL)
            return FALSE;
        $appSecret = $cf->GetSecret($appKey);
        if($appSecret === FALSE)
            return FALSE;
        $iv = WsgUtil::getIV($appSecret);
        $res = WsgUtil::aesCbcEncrypt($iv,$iv, $data);
        return base64_encode($res);
    }

    public function Decrypt($appKey, $data)
    {
        if(gettype($appKey) !== "string" || gettype($data) != "string" || $appKey === "" || $data === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $cf = ConfigParser::instance(NULL);
        if($cf === NULL)
            return FALSE;
        $appSecret = $cf->GetSecret($appKey);
        if($appSecret === FALSE)
            return FALSE;
        $iv = WsgUtil::getIV($appSecret);
        $data = base64_decode($data);
        if($data === FALSE)
        {
            throw new WsgException("", WsgException::ErrDecodeBase64);
        }
        $res = WsgUtil::aesCbcDecrypt($iv, $iv, $data);
        return $res;
    }

    public function AtlasDecrypt($content)
    {
        if($content === null || gettype($content) !== "string")
           throw new WsgException("param error", WsgException::ErrInputData);
        if($content && strlen($content) > 9)
        {
            $cf = ConfigParser::instance(NULL);
            if($cf === NULL)
            {
                throw new WsgException("", WsgException::ErrNoCfgLoaded);
            }
            $secret = $cf->GetSecret(substr($content, 1, 8));
            if($secret === false)
            {
                throw new WsgException("", WsgException::ErrNoSuchKey);
            }
            $iv = $cf->GetSecret("iv");
            if($iv === false)
            {
                throw new WsgException("", WsgException::ErrNoSuchKey);
            }
            $data = base64_decode(substr($content, 9));
            if($data)
            {
                $res = WsgUtil::aesCbcDecrypt($secret,$iv, $data);
                return $res;
            }
            else
                throw new WsgException("", WsgException::ErrDecodeBase64);
        }
        else
        {
            throw new WsgException("param error", WsgException::ErrInputData);
        }
    }
} 