<?php

namespace Heroin\Aliyun\Wsgsvr;

class ConfigParser {

    private $tab = NULL;

    static $ins = NULL;

    private function __construct()
    {}

    public static function instance($cfg)
    {
        if(self::$ins == NULL)
        {
            if(is_readable($cfg) === false)
                throw new WsgException("", WsgException::ErrNoCfgLoaded);
            $insTmp = new ConfigParser();
            if(false === $insTmp->Load($cfg))
            {
                throw new WsgException("", WsgException::ErrNoCfgLoaded);
            }
            else
                self::$ins = $insTmp;
        }
        return self::$ins;
    }

    private function Load($cfg)
    {
        $handle = fopen($cfg, "rb");
        if ($handle) {
            $this->tab = array();
            while (!feof($handle)) {
                $buffer = fgets($handle, 4096);
                $buffer = trim($buffer);
                if($buffer && $buffer[0] != '#' && $buffer[0] != '!')
                {
                    $buffer = str_replace("\=", "\n", $buffer);
                    $pos = strpos($buffer, "=");
                    if($pos)
                    {
                        $key = substr($buffer,0,$pos);
                        $value = substr($buffer, $pos+1);
                        $key = str_replace("\n", "=", $key);
                        $value = str_replace("\n", "=", $value);
                        $this->tab[$key] = $value;
                    }
                }
            }
            fclose($handle);
            return TRUE;
        }
        return FALSE;
    }

    public function GetSecret($key)
    {
        $secret = "wsgliu@#";
        $value = $this->tab[$key];
        if($value)
        {
            $value = base64_decode($value);
            if($value === FALSE)
                throw new WsgException("", WsgException::ErrCfgDecrypt);
            return $this->decrypt($value, $secret, $secret);
        }
        else
            throw new WsgException("", WsgException::ErrNoSuchKey);
    }

    function decrypt($str, $key, $iv)
    {
        $str = mcrypt_decrypt(MCRYPT_DES, $key, $str, MCRYPT_MODE_ECB, $iv);
        if($str === FALSE)
            throw new WsgException("", WsgException::ErrCfgDecrypt);
        $res =  WsgUtil::pkcs5_unpad($str);
        if($res === FALSE)
            throw new WsgException("", WsgException::ErrCfgDecrypt);
        return $res;
    }

}