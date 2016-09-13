<?php
/**
 *
 * EveSSO - An phpBB extension adding EVE Online SSO authentication to your forum.
 *
 * @copyright (c) 2015 Jordy Wille (http://github.com/cyerus)
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace imperialdreams\evesso\core;

use OAuth\OAuth2\Service\Evesso as EveSsoOauthProvider;
use phpbb\auth\provider\oauth\service\base;
use phpbb\auth\provider\oauth\service\exception;
use phpbb\config\config;
use phpbb\request\request_interface;


/**
 * EVE Online SSO / OAuth2 service
 *
 * @package auth
 * @property $service_provider EveSsoOauthProvider
 */
class evesso extends base
{
    /**
     * phpBB config
     *
     * @var config
     */
    protected $config;

    /**
     * phpBB request
     *
     * @var request_interface
     */
    protected $request;

    /**
     * Constructor
     *
     * @param config $config
     * @param request_interface $request
     */
    public function __construct(config $config, request_interface $request)
    {
        $this->config = $config;
        $this->request = $request;

        global $user;
        $user->add_lang_ext('imperialdreams/evesso', 'evesso');

        require_once(dirname(__DIR__).DIRECTORY_SEPARATOR.'service'.DIRECTORY_SEPARATOR.'Evesso.php');
    }

    /**
     * {@inheritdoc}
     */
    public function get_service_credentials()
    {
        return array(
            'key'		=> $this->config['auth_oauth_evesso_key'],
            'secret'	=> $this->config['auth_oauth_evesso_secret'],
        );
    }

    /**
     * {@inheritdoc}
     */
    public function perform_auth_login()
    {
        if (!($this->service_provider instanceof EvessoOauthProvider))
        {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }

        // This was a callback request from EVE Online SSO, get the token
        $this->service_provider->requestAccessToken($this->request->variable('code', ''));

        // Send a request to /verify to determine user information
        $result = json_decode($this->service_provider->request('https://login.eveonline.com/oauth/verify'), true);

        // Return the CharacterOwnerHash is this is unique for each character on each account.
        // If a character is transferred, the CharacterOwnerHash is newly generated.
        return $result['CharacterOwnerHash'];
    }

    /**
     * {@inheritdoc}
     */
    public function perform_token_auth()
    {
        if (!($this->service_provider instanceof EvessoOauthProvider))
        {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }

        // Send a request to /verify to determine user information
        $result = json_decode($this->service_provider->request('https://login.eveonline.com/oauth/verify'), true);

        // Return the CharacterOwnerHash is this is unique for each character on each account.
        // If a character is transferred, the CharacterOwnerHash is newly generated.
        return $result['CharacterOwnerHash'];
    }
}
