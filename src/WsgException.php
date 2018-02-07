<?php

namespace Heroin\Aliyun\Wsgsvr;

class WsgException extends \Exception
{

    const ErrInputData = 2;
    const ErrNoSuchKey = 3;
    const ErrNoCfgLoaded = 5;
    const ErrDecodeBase64 = 6;
    const ErrDataDecrypt = 7;
    const ErrCfgDecrypt = 8;

    public function __construct($message, $code = 0) {
        parent::__construct($message, $code);
    }

    public function __toString() {
        return __CLASS__.':['.$this->code.']:'.$this->message.'\n';
    }
}