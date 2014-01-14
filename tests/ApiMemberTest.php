<?php

namespace Sheerwater\HMACRestfulAuthenticator\Tests;

use FieldList, Member;

class ApiMemberTest extends \SapphireTest
{
    public function testExtension()
    {
        $this->assertTrue(Member::has_extension('Sheerwater\HMACRestfulAuthenticator\Extensions\ApiMember'),
            'Member doesn\'t have ApiMember extension');

        /** @var Member $member */
        $member = singleton('Member');

        $this->assertEquals($member->has_many('KeyPairs'), 'Sheerwater\HMACRestfulAuthenticator\Models\ApiKeyPair',
            'KeyPairs relationship on Member is missing or invalid');
    }

    public function testGetCMSFields()
    {
        $member = Member::create();
        // Write the member so the has_many fields are processed by the scaffolder
        $member->write();

        /** @var FieldList $fields */
        $fields = $member->getCMSFields();
        $tab    = $fields->fieldByName('Root.KeyPairs');
        $this->assertInstanceOf('Tab', $tab,
            'KeyPairs tab should exist when the HMAC Restful Authenticator is present');
    }
}
