<?php

class ImdJWT
{
    /**
     * Encodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the data to encode
     * @return string the encoded data
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    public static function base64UrlEncode($data)
    {
        $encoded = strtr(base64_encode($data), '+/', '-_');
        $encoded = trim($encoded, '=');

        return $encoded;
    }

    /**
     * The signature returned by OpenSSL is an ASN.1 sequence that contains additional information. You have to remove the extra data before concatenation.
     * DER = Distinguished Encoding Rules
     *
     * @param string $signature
     * @return string
     */
    public static function opensslRemoveDERExtraData(string $signature) : string
    {
        $partLength = 64;
        $hex = \unpack('H*', $signature)[1];
        if ('30' !== \mb_substr($hex, 0, 2, '8bit')) { // SEQUENCE
            throw new \RuntimeException();
        }
        if ('81' === \mb_substr($hex, 2, 2, '8bit')) { // LENGTH > 128
            $hex = \mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = \mb_substr($hex, 4, null, '8bit');
        }
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Rl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $R = self::retrievePositiveInteger(\mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R = \str_pad($R, $partLength, '0', STR_PAD_LEFT);
        $hex = \mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if ('02' !== \mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Sl = \hexdec(\mb_substr($hex, 2, 2, '8bit'));
        $S = self::retrievePositiveInteger(\mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S = \str_pad($S, $partLength, '0', STR_PAD_LEFT);

        return \pack('H*', $R . $S);
    }

    private static function retrievePositiveInteger(string $data): string
    {
        while ('00' === \mb_substr($data, 0, 2, '8bit') && \mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = \mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }
}

$headers = [
    'alg' => $appleSettings['algorithm'],
    'kid' => $appleSettings['keyIdentifier'],
];
$claims = [
    'iss' => $appleSettings['teamId'],
    'iat' => time(),
    'exp' => time() + DAY,
    'aud' => $appleSettings['audience'],
    'sub' => $appleSettings['clientId'],
];
$data = ImdJWT::base64UrlEncode(json_encode($headers)) . '.' . ImdJWT::base64UrlEncode(json_encode($claims));
$signature = '';
openssl_sign($data, $signature, $appleSettings['privateKey'], OPENSSL_ALGO_SHA256);
$signature = ImdJWT::opensslRemoveDERExtraData($signature);
$signature = ImdJWT::base64UrlEncode($signature);

$clientSecret = $data . '.' . $signature;
echo $clientSecret;
exit;
