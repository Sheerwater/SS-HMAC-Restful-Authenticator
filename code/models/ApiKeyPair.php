<?php

namespace Sheerwater\HMACRestfulAuthenticator\Models;

use Member;

/**
 * Class ApiKeyPair
 *
 * Represents an API Key and Secret
 *
 * @property string Key
 * @property string Secret
 * @property bool   Enabled
 * @method Member Member
 */
class ApiKeyPair extends \DataObject
{
    private static $singular_name = 'API Keypair';
    private static $plural_name = 'keypairs';

    private static $db = [
        'Title'   => 'Varchar',
        'Key'     => 'Varchar',
        'Secret'  => 'Varchar',
        'Enabled' => 'Boolean'
    ];

    private static $has_one = [
        'Member' => 'Member'
    ];
    private static $indexes = [
        'Key' => [
            'type'  => 'unique',
            'value' => '"Key"'
        ]
    ];

    public function getCMSFields()
    {
        $fields = parent::getCMSFields();

        $title = $fields->dataFieldByName('Title');
        if ($title) {
            $title->setTitle('Name');

            if (!$this->exists()) {
                $title->setDescription("'Save' to generate API key pair.");
            }
        }

        if (!$this->exists()) {
            $fields->removeFieldsFromTab('Root.Main', [
                'Key',
                'Secret'
            ]);
        } else {
            $fields->makeFieldReadonly('Key');
            $fields->makeFieldReadonly('Secret');
        }

        return $fields;
    }

    /**
     * Generates a new random hash of the specified type
     *
     * @param string $type Defaults to MD5
     *
     * @return string
     */
    private function generateKey($type = 'md5')
    {
        return strtolower(hash($type, microtime()));
    }

    public function onBeforeWrite()
    {
        parent::onBeforeWrite();

        while (trim($this->Key) == false || $this->Key == $this->Secret) {
            $key = $this->generateKey();
            if (!static::get()->filter('Key', $key)->count()) {
                $this->Key = $key;
            }
        }
        while (trim($this->Secret) == false) {
            $secret = $this->generateKey('sha1');
            if (!static::get()->filter('Secret', $secret)->count()) {
                $this->Secret = $secret;
            }
        }
    }
} 
