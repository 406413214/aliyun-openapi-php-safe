<?php

namespace Heroin\Aliyun\Wsgsvr;

class WsgUtil {

    public static function aesCbcEncrypt($key, $iv, $input) {
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $input = WsgUtil::pkcs5_pad($input, $size);
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($td, $key, $iv);
        $data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $data;
    }

    function pkcs5_pad ($text, $blocksize) {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    public static function aesCbcDecrypt($key, $iv, $data) {
        $decrypted = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            $key,
            $data,
            MCRYPT_MODE_CBC,
            $iv
        );
        if($decrypted === false)
            throw new WsgException("", WsgException::ErrDataDecrypt);
        $res = WsgUtil::pkcs5_unpad($decrypted);
        if($res === false)
            throw new WsgException("", WsgException::ErrDataDecrypt);
        return $res;
    }

    public static function pkcs5_unpad($text) {
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text)) return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
            return false;
        return substr($text, 0, -1 * $pad);
    }

    static function str2hex($string)
    {
        $hex="";
        for ($i=0; $i < strlen($string); $i++)
        {
            $t = dechex(ord($string[$i]));
            if(strlen($t) == 1)
                $t = "0". $t;
            $hex .= $t;
        }
        return $hex;
    }

    public static function getIV($appSecret)
    {
        $res = md5($appSecret, TRUE);
        $res2 =  WsgUtil::str2hex($res);
        return substr($res2, 0, 16);
    }

    public static function checkHmacsha1($appSecret, $input, $sign)
    {
        $res = hash_hmac("sha1", $input, $appSecret, TRUE);
        $res = WsgUtil::str2hex($res);
        return $sign == $res;
    }
}


?>