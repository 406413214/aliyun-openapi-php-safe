<?php

namespace Heroin\Aliyun\Wsgsvr;

class SignCheck {

    public static function DoSignCheck($input, $appSecret, $sign)
    {
        if(gettype($input) !== "string" || gettype($appSecret) != "string" || gettype($sign) != "string" || $input === "" || $appSecret === "" || $sign === "")
            throw new WsgException("param error", WsgException::ErrInputData);
        return WsgUtil::checkHmacsha1($appSecret, $input, $sign);
    }

    public static function SimSignCheck($input, $appSecret, $sign, &$isSim)
    {
        if(gettype($input) !== "string" || gettype($appSecret) != "string" || gettype($sign) != "string" || gettype($isSim) != "boolean" || $input === "" || $appSecret === "" || $sign === "")
            throw new WsgException("param error", WsgException::ErrInputData);
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

}

?>