<?php

namespace Sheerwater\HMACRestfulAuthenticator;

use Sheerwater\HMACRestfulAuthenticator\Models\ApiKeyPair;
use Config, Controller, DateInterval, DateTime, SS_HTTPRequest;

class HMACRestfulAuthenticator
{

    /**
     * The API name is used in various places in the HMAC authenticator:
     *
     *    - The Authorization header, in the format of 'Authorization: {$api_name} {ApiKey}:{SignedRequest}'
     *    - All API-specific headers, eg 'X-{$api_name}-Date'. It's important that this pattern is used or else
     *      your custom headers are not covered by HMAC point-to-point security
     *
     * You can set the value using Config statics or a config yaml file
     *
     * @var string
     */
    private static $api_name = 'Api';

    /**
     * Allows you to set the {@link $api_name} for use in the Authorization and API-specific headers. Usually you'd
     * set it via a config yml file however, as described at {@link $api_name}.
     *
     * @param string $value
     */
    public static function setApiName($value)
    {
        Config::inst()->update(__CLASS__, 'api_name', $value);
    }

    /**
     * Gets the {@link $api_name} that's used in the Authorization and API-specific headers
     * @return string
     */
    public static function getApiName()
    {
        return Config::inst()->get(__CLASS__, 'api_name');
    }

    /**
     * A helper function for generating the prefix for API-specific headers
     * @return string
     */
    public static function getHeaderPrefix()
    {
        return implode('-', ['X', self::getApiName(), '']);
    }

    public static function authenticate()
    {
        $controller = Controller::curr();
        $request    = $controller->getRequest();

        // Check that the date is within 15 minutes of server time
        $timeToCheck = $request->getHeader(self::getHeaderPrefix() . 'Date') ? : $request->getHeader('Date');
        if (!self::validateRequestTime($timeToCheck)) {
            return false;
        }

        preg_match('`\s*' . self::getApiName() . '\s+([^:]+):(\S+)`', $request->getHeader('Authorization'), $authMatches);
        if (count($authMatches) !== 3) {
            return false;
        }
        // Check with the raw key, or try to base64_decode and convert to hex
        $keys = ApiKeyPair::get()->filter('Key', strtolower($authMatches[1]));
        if (!$keys->count()) {
            $keys = ApiKeyPair::get()->filter('Key', bin2hex(base64_decode($authMatches[1])));
        }

        /** @var ApiKeyPair $apiKey */
        $apiKey = $keys->first();
        if (!($apiKey and $apiKey->exists() and $apiKey->Enabled)) {
            return false;
        }

        $contentMD5 = $request->getHeader('Content-Md5');
        if ($contentMD5 and !self::validateContentIntegrity($contentMD5)) {
            return false;
        }

        if (!self::validateSignedRequest($request, $apiKey->Secret, $authMatches[2])) {
            return false;
        }

        $member = $apiKey->Member();
        if (!($member and $member->exists())) {
            return false;
        }

        // All tests pass; log the member in and return it
        $member->logIn();

        return $member;
    }

    /**
     * Validates a user-/request-provided date against specification RFC 2616. This avoids the client using values that
     * are invalid but still work with strtotime, such as 'now' or '-1 minute'. Also checks that the time is within
     * 15 minutes of server time.
     *
     * @param string $time The time passed in the request's HTTP header
     *
     * @return bool
     */
    private static function validateRequestTime($time)
    {
        $dateTimePatterns = [
            // Matches RFC 822: Sun, 06 Nov 1994 08:49:37 GMT
            DateTime::RFC822,
            // Matches RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
            DateTime::RFC850,
            // Matches ANSI C's asctime(): Sun Nov  6 08:49:37 1994
            'D M d H:i:s Y'
        ];

        foreach ($dateTimePatterns as $pattern) {
            $dt = DateTime::createFromFormat($pattern, $time);
            if ($dt) {
                break;
            }
        }

        $timeThreshold = new DateInterval('PT15M'); // 15 minutes
        $futureLimit   = new DateTime();
        $pastLimit     = new DateTime();
        $futureLimit->add($timeThreshold);
        $pastLimit->sub($timeThreshold);

        return (isset($dt) and $dt <= $futureLimit and $dt >= $pastLimit);
    }

    /**
     * Filters all headers for ones starting with 'X-Api-'. All keys are converted to lowercase. You can change
     * 'Api' by setting the HMACRestfulAuthenticator::$apiName config.
     *
     * @param string[] $headers An array of HTTP headers to filter
     *
     * @return string[]
     */
    private static function getCanonicalHeaders(Array $headers)
    {
        $out       = [];
        $prefix    = self::getHeaderPrefix();
        $prefixLen = strlen($prefix);

        foreach ($headers as $k => $v) {
            if (substr($k, 0, $prefixLen) == $prefix) {
                $out[strtolower($k)] = $v;
            }
        }

        return $out;
    }

    /**
     * Validates the content of the request body against a user-provided MD5 hash
     *
     * @param string $md5 This can be raw or base64 encoded
     * @param mixed  $body
     *
     * @return bool
     */
    private static function validateContentIntegrity($md5, $body = null)
    {
        // Fall back
        if ($body === null) {
            $request = Controller::curr()->getRequest();
            $body    = $request->getBody();
        }
        $bodyHash = md5($body);

        return $bodyHash === $md5 or $bodyHash === bin2hex(base64_decode($md5));
    }

    /**
     * This is a simple associative array implode function, with sensible defaults for HTTP headers
     *
     * @param string[] $headers
     * @param string   $glue
     * @param string   $separator
     *
     * @return string
     */
    private static function implodeHeaders(Array $headers, $glue = ': ', $separator = "\n")
    {
        $out = [];
        foreach ($headers as $k => $v) {
            $out[] = $k . $glue . $v;
        }

        return implode($separator, $out);
    }

    /**
     * Rebuilds a string-to-sign from the request parameters, and compares it against the user-provided hash
     *
     * @param SS_HTTPRequest $request
     * @param string         $secret
     * @param string         $hashToCompare This can be raw or base64 encoded
     *
     * @return bool
     */
    private static function validateSignedRequest(SS_HTTPRequest $request, $secret, $hashToCompare)
    {
        // Recreate the string-to-sign according to the standard AWS HMAC method
        $verb        = $request->httpMethod();
        $contentMD5  = $request->getHeader('Content-Md5');
        $contentType = $request->getHeader('Content-Type');
        $date        = $request->getHeader(self::getHeaderPrefix() . 'Date') ? '' : $request->getHeader('Date');
        $headers     = self::getCanonicalHeaders($request->getHeaders());
        $resource    = $request->getURL();
        $strToSign   = $verb . "\n"
            . $contentMD5 . "\n"
            . $contentType . "\n"
            . $date . "\n"
            . self::implodeHeaders($headers) . "\n"
            . $resource;

        // Sign the string an compare it to the provided hash
        $signedString = hash_hmac('sha1', $strToSign, $secret);

        return $signedString === $hashToCompare || $signedString === base64_decode($hashToCompare);
    }
}
