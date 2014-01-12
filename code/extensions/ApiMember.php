<?php

namespace Sheerwater\HMACRestfulAuthenticator\Extensions;

use DataExtension;

class ApiMember extends DataExtension
{
    private static $has_many = [
        'KeyPairs' => 'Sheerwater\HMACRestfulAuthenticator\Models\ApiKeyPair'
    ];
}
