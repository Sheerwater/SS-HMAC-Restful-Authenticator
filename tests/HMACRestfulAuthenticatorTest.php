<?php

namespace Sheerwater\HMACRestfulAuthenticator\Tests;

use Sheerwater\HMACRestfulAuthenticator\Models\ApiKeyPair;
use Sheerwater\HMACRestfulAuthenticator\HMACRestfulAuthenticator;
use Config, Controller, Director, SS_HTTPRequest, DataObject, TestOnly, Member;
use ReflectionMethod;

class HMACRestfulAuthenticatorTest extends \SapphireTest
{
    protected $extraDataObjects = [
        'Sheerwater\HMACRestfulAuthenticator\Tests\TestApiObject'
    ];
    protected static $fixture_file = 'HMACRestfulAuthenticatorFixture.yml';

    private $oldApiName;

    public function setUpOnce()
    {
        parent::setUpOnce();

        // Reset the API name in case the current site configuration has changed it
        $this->oldApiName = HMACRestfulAuthenticator::getApiName();
        HMACRestfulAuthenticator::setApiName('Api');

        Config::inst()->update('Director', 'rules', [
            'TestController' => 'Sheerwater\HMACRestfulAuthenticator\Tests\TestController'
        ]);
    }

    public function tearDownOnce()
    {
        parent::tearDownOnce();

        // Reset the API name in case there are user tests relying on it
        HMACRestfulAuthenticator::setApiName($this->oldApiName);
    }

    public function testApiName()
    {
        HMACRestfulAuthenticator::setApiName('Test');
        $this->assertEquals('Test', HMACRestfulAuthenticator::getApiName(),
            'Either GetApiName or SetApiName are not working correctly');
        HMACRestfulAuthenticator::setApiName('Api');
    }

    public function testGetHeaderPrefix()
    {
        HMACRestfulAuthenticator::setApiName('Test');
        $this->assertEquals('X-Test-', HMACRestfulAuthenticator::getHeaderPrefix(),
            'GetHeaderPrefix is not building the header prefix correctly');
        HMACRestfulAuthenticator::setApiName('Api');
    }

    public function testAuthenticate()
    {
        $member = Member::get()->filter('Email', 'test')->first();
        /** @var ApiKeyPair $key */
        $key = $member->KeyPairs()->first();

        // Successful GET request
        $getDate        = date(DATE_RFC850);
        $getRequestSTS  =
            'GET' . "\n" .
            "\n" .
            "\n" .
            $getDate . "\n" .
            'x-api-user: 54' . "\n" .
            'x-api-device: 23' . "\n" .
            'TestController';
        $getRequestSign = hash_hmac('sha1', $getRequestSTS, $key->Secret);
        $getResponse    = Director::test(
            'TestController',
            null, null,
            'GET',
            null,
            array(
                'Date'          => $getDate,
                'X-Api-User'    => '54',
                'X-Api-Device'  => '23',
                'Authorization' => 'Api ' . base64_encode(hex2bin($key->Key)) . ':' . base64_encode(hex2bin($getRequestSign))
            )
        );
        $this->assertEquals(200, $getResponse->getStatusCode(), 'Authenticate failed on a valid GET request');

        // Successful POST request with body content
        $postDate        = date(DATE_RFC822);
        $postContent     = json_encode(['Title' => 'test']);
        $postRequestSTS  =
            'POST' . "\n" .
            md5($postContent) . "\n" .
            'application/json' . "\n" .
            "\n" .
            'x-api-user: 54' . "\n" .
            'x-api-device: 23' . "\n" .
            'x-api-date: ' . $postDate . "\n" .
            'TestController';
        $postRequestSign = hash_hmac('sha1', $postRequestSTS, $key->Secret);
        $postResponse    = Director::test(
            'TestController',
            null, null,
            'POST',
            $postContent,
            [
                'Content-Md5'   => md5($postContent),
                'Content-Type'  => 'application/json',
                'Date'          => date(DATE_RFC850, strtotime('-45 seconds')),
                'X-Api-User'    => '54',
                'X-Api-Device'  => '23',
                'X-Api-Date'    => $postDate,
                'Authorization' => 'Api ' . $key->Key . ':' . $postRequestSign
            ]
        );
        $this->assertEquals(201, $postResponse->getStatusCode(), 'Authenticate failed on a valid POST request');

        // Invalid POST request (body does not match the hash provided, eg the payload has been tampered with)
        $postResponse = Director::test(
            'TestController',
            null, null,
            'POST',
            $postContent . ' ',
            [
                'Content-Md5'   => md5($postContent),
                'Content-Type'  => 'application/json',
                'Date'          => date(DATE_RFC850, strtotime('-45 seconds')),
                'X-Api-User'    => '54',
                'X-Api-Device'  => '23',
                'X-Api-Date'    => $postDate,
                'Authorization' => 'Api ' . $key->Key . ':' . $postRequestSign
            ]
        );
        $this->assertEquals(401, $postResponse->getStatusCode(), 'Authenticate succeeded on an invalid POST request');
    }

    public function testValidateRequestTime()
    {
        $method = $this->getPrivateTestMethod();

        // Testing valid dates, equal to server time
        $failMessage = 'ValidateRequestTime is not accepting all valid date-time formats';
        $this->assertTrue($method->invoke(null, date(DATE_RFC850)), $failMessage);
        $this->assertTrue($method->invoke(null, date(DATE_RFC822)), $failMessage);
        $this->assertTrue($method->invoke(null, date('D M j G:i:s Y')), $failMessage);

        // Testing invalid date/time formats
        $failMessage = 'ValidateRequestTime is not failing on invalid date-time formats';
        $this->assertFalse($method->invoke(null, date(DATE_ISO8601)), $failMessage);
        $this->assertFalse($method->invoke(null, 'now'), $failMessage);
        $this->assertFalse($method->invoke(null, ''), $failMessage);

        // Test valid date formats that are offset from server time
        $failMessage = 'ValidateRequestTime offset threshold is too small';
        $this->assertTrue($method->invoke(null, date(DATE_RFC822, strtotime('+5 minutes'))), $failMessage);
        $this->assertTrue($method->invoke(null, date(DATE_RFC822, strtotime('-5 minutes'))), $failMessage);
        $this->assertTrue($method->invoke(null, date(DATE_RFC822, strtotime('+15 minutes'))), $failMessage);
        $this->assertTrue($method->invoke(null, date(DATE_RFC822, strtotime('-15 minutes'))), $failMessage);
        $failMessage = 'ValidateRequestTime offset theshold is too large';
        $this->assertFalse($method->invoke(null, date(DATE_RFC822, strtotime('+16 minutes'))), $failMessage);
        $this->assertFalse($method->invoke(null, date(DATE_RFC822, strtotime('-16 minutes'))), $failMessage);
    }

    public function testGetCanonicalHeaders()
    {
        $dateToUse       = date(DATE_RFC822);
        $testHeaders     = array(
            'Content-Type' => 'text/plain',
            'Content-Md5'  => md5('test content'),
            'X-Api-Date'   => $dateToUse,
            'X-Api-UserID' => '54'
        );
        $expectedHeaders = array(
            'x-api-date'   => $dateToUse,
            'x-api-userid' => '54'
        );

        $method = $this->getPrivateTestMethod();
        $this->assertEquals($method->invoke(null, $testHeaders), $expectedHeaders,
            'GetCanonicalHeaders is not filtering headers correctly');
    }

    public function testValidateContentIntegrity()
    {
        $contentToTest = http_build_query(array(
            'param1' => 'value1',
            'param2' => 'value2',
            'param3' => 'value3'
        ));
        $testMd5       = md5($contentToTest);

        $method = $this->getPrivateTestMethod();
        $this->assertTrue($method->invoke(null, $testMd5, $contentToTest),
            'Validation failed for a correct MD5 hash');
        $this->assertTrue($method->invoke(null, base64_encode(hex2bin($testMd5)), $contentToTest,
            'Validation failed for a correct base64-encoded MD5 hash'));
        $this->assertFalse($method->invoke(null, md5($contentToTest . ' '), $contentToTest,
            'Validation passed for an invalid MD5 hash'));
    }

    public function testImplodeHeaders()
    {
        $input = array(
            'Accepts'        => '*/*',
            'Content-Type'   => 'text/plain',
            'Content-Length' => '54'
        );

        $defaultExpectedOutput =
            'Accepts: */*' . "\n" .
            'Content-Type: text/plain' . "\n" .
            'Content-Length: 54';
        $customExpectedOutput  = 'Accepts=*/*|Content-Type=text/plain|Content-Length=54';

        $method = $this->getPrivateTestMethod();
        $this->assertEquals($method->invoke(null, $input), $defaultExpectedOutput,
            'ImplodeHeaders failed with default parameters');
        $this->assertEquals($method->invoke(null, $input, '=', '|'), $customExpectedOutput,
            'ImplodeHeaders failed with custom parameters');
    }

    public function testValidateSignedRequest()
    {
        $secret = hash('sha1', microtime());
        $method = $this->getPrivateTestMethod();

        $validGetDate    = date(DATE_RFC850, strtotime('-15 minutes'));
        $validGetRequest = new SS_HTTPRequest('GET', 'test/url');
        $validGetRequest->addHeader('Date', $validGetDate);
        $validGetRequest->addHeader('X-Api-User', '54');
        $validGetRequest->addHeader('X-Api-Device', '23');
        $validGetRequestSTS  =
            'GET' . "\n" .
            "\n" .
            "\n" .
            $validGetDate . "\n" .
            'x-api-user: 54' . "\n" .
            'x-api-device: 23' . "\n" .
            'test/url';
        $validGetRequestSign = hash_hmac('sha1', $validGetRequestSTS, $secret);
        $this->assertTrue($method->invoke(null, $validGetRequest, $secret, $validGetRequestSign),
            'ValidateSignedRequest failed on a valid GET request');

        $postBody    = http_build_query([
            'param1' => 'value1',
            'param2' => 'value2'
        ]);
        $postBodyMd5 = base64_encode(hex2bin(md5($postBody)));

        $validPostDate = date(DATE_RFC850, strtotime('+15 minutes'));

        $validPostRequest = new SS_HTTPRequest('POST', 'test/url');
        $validPostRequest->addHeader('Content-Md5', $postBodyMd5);
        $validPostRequest->addHeader('Content-Type', 'application/x-www-form-urlencoded');
        $validPostRequest->addHeader('Date', $validPostDate);
        $validPostRequest->addHeader('X-Api-User', '54');
        $validPostRequest->addHeader('X-Api-Device', '23');
        $validPostRequestSTS  =
            'POST' . "\n" .
            $postBodyMd5 . "\n" .
            'application/x-www-form-urlencoded' . "\n" .
            $validPostDate . "\n" .
            'x-api-user: 54' . "\n" .
            'x-api-device: 23' . "\n" .
            'test/url';
        $validPostRequestSign = hash_hmac('sha1', $validPostRequestSTS, $secret);
        $this->assertTrue($method->invoke(null, $validPostRequest, $secret, $validPostRequestSign),
            'ValidateSignedRequest failed on a valid POST request');

        $validPostRequest->addHeader('Content-Md5', md5($postBody . ' '));
        $this->assertFalse($method->invoke(null, $validPostRequest, $secret, $validPostRequestSign),
            'ValidateSignedRequest passed on an invalid POST request');
    }

    /**
     * Assuming the convention that test classes are named by the class name they're testing followed by 'Test', this
     * function returns the name of the class that's being tested.r
     * @return string
     */
    private function getTestClassName()
    {
        return 'Sheerwater\HMACRestfulAuthenticator\HMACRestfulAuthenticator';
    }

    /**
     * Assuming the convention that test methods are named 'get' followed by the name of the function they're testing,
     * this function returns the name of this function (removing 'get' and converting the first letter to lowercase).
     *
     * @param int $farBack
     *
     * @return string
     */
    private function getTestMethodName($farBack = 1)
    {
        $backtrace    = debug_backtrace();
        $functionName = substr($backtrace[$farBack]['function'], 4);

        return strtolower(substr($functionName, 0, 1)) . substr($functionName, 1);
    }

    /**
     * Given a method name and a class name, uses Reflection to obtain a reference to a class's method. Useful for
     * testing protected and private methods.
     *
     * @param string $methodName Defaults to the class name returned by {@link getTestClassName}
     * @param null   $className  Defaults to the method name returned by {@link getTestMethodName}
     *
     * @return ReflectionMethod
     */
    private function getPrivateTestMethod($methodName = null, $className = null)
    {
        $method = new ReflectionMethod($className ? : $this->getTestClassName(), $methodName ? : $this->getTestMethodName(2));
        $method->setAccessible(true);

        return $method;
    }
}

/**
 * A sample dataobject that can be used when testing the Restful API. It needs to give Read and Create access whenevel
 * the current user is valid.
 *
 * Class TestApiObject
 */
class TestApiObject extends DataObject implements TestOnly
{
    private static $db = array(
        'Title' => 'Varchar'
    );
    static $api_access = true;

    public function canRead($member = null)
    {
        return Member::currentUserID() > 0;
    }

    public function canCreate($member = null)
    {
        return Member::currentUserID() > 0;
    }
}

class TestController extends Controller
{
    public function index()
    {
        $member = HMACRestfulAuthenticator::authenticate();
        if (!($member and $member->exists())) {
            $this->httpError(403, 'Authentication failed.');
        }
    }
}
