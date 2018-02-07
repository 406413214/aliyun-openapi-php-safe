<?php

namespace Heroin\Aliyun\Wsgsvr;

class Encrypt
{
    public static function Encrypt($appSecret, $data)
    {
        if($appSecret === null || gettype($appSecret) !== "string" || gettype($data) != "string" || $data === "" || $appSecret === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $iv = WsgUtil::getIV($appSecret);
        $res = WsgUtil::aesCbcEncrypt($iv,$iv, $data);
        return base64_encode($res);
    }

    public static function Decrypt($appSecret, $data)
    {
        if($appSecret === null || gettype($appSecret) !== "string" || gettype($data) != "string" || $data === "" || $appSecret === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        $iv = WsgUtil::getIV($appSecret);
        $data = base64_decode($data);
        if($data === FALSE)
        {
            throw new WsgException("", WsgException::ErrDecodeBase64);
        }
        $res = WsgUtil::aesCbcDecrypt($iv, $iv, $data);
        return $res;
    }

}

?>