<?php

namespace App\Auth;
require_once './Session.php';
use App\Auth\Session;

class MicrosoftAuth {

  private static $DOMAIN = 'microsoft';

  /**
   * Configuration array for oauth client
   * @var Array
   */
  private $config;

  /**
   * The client Id as listed in Microsoft App portal
   * @var String
   */
  private $clientId;

  /**
   * The client secret
   * @var String
   */
  private $clientSecret;

  /**
   * The redirect URI for the microsoft oauth to
   * go to after auth.
   * @var String
   */
  private $redirectUri;

  /**
   * The oauth authorization url to call
   * @var String
   */
  private $urlAuthorize;

  /**
   * The oauth access token url to call
   * @var String
   */
  private $urlAccessToken;

  /**
   * Scopes to include in oauth request
   * @var String
   */
  private $scopes;

  /**
   * Url to redirect to after logout
   * @var String
   */
  private $logout_url;

  /**
   * Not supported
   * @var String
   */
  private $urlResourceOwnerDetails;

  /**
   * The oauth provider class
   * @var [type]
   */
  private $provider;

  /**
   * Url to redirect to after successful authentication
   * @var String
   */
  private $auth_success_url;

  public function __construct($config) {
    $this->init($config);
  }

  private function init($config) {
    if(!isset($config)) {
      throw new \Exception('Config is not valid.');
    }
    if(!isset($config['clientId'])) {
      throw new \Exception('clientId is invalid.');
    }
    if(!isset($config['clientSecret'])) {
      throw new \Exception('clientSecret is invalid.');
    }
    if(!isset($config['redirectUri'])) {
      throw new \Exception('redirectUri is invalid.');
    }
    if(!isset($config['urlAuthorize'])) {
      throw new \Exception('urlAuthorize is invalid.');
    }
    if(!isset($config['urlAccessToken'])) {
      throw new \Exception('urlAccessToken is invalid.');
    }
    if(!isset($config['scopes'])) {
      throw new \Exception('scopes is invalid.');
    }
    if(!isset($config['logout_url'])) {
      throw new \Exception('logout_url is invalid.');
    }
    if(!isset($config['urlResourceOwnerDetails'])) {
      // do nothing at this point; not supported.
    }

    $this->config = $config;
    $this->clientId = $config['clientId'];
    $this->clientSecret = $config['clientSecret'];
    $this->redirectUri = $config['redirectUri'];
    $this->urlAuthorize = $config['urlAuthorize'];
    $this->urlAccessToken = $config['urlAccessToken'];
    $this->scopes = $config['scopes'];
    $this->logout_url = $config['logout_url'];

    // not supported; set default empty value for now.
    $this->config['urlResourceOwnerDetails'] = '';
    $this->urlResourceOwnerDetails = '';

    $this->provider = new \League\OAuth2\Client\Provider\GenericProvider(
        $this->config
    );

    // Let the session know that we are restricting auth
    // to microsoft domains
    Session::set_logout_url($this->logout_url, self::$DOMAIN);
  }

  public static function auth_failure() {
    return Session::auth_failure(
      'There was an error during Microsoft authentication.', 
      self::$DOMAIN
    );
  }

  public static function logout() {
    return Session::logout(self::$DOMAIN);
  }

  public function authenticate($request) {
    if (!$request->has('code')) {
      // Retrieve the authorization url
      return $this->provider->getAuthorizationUrl();
    } else {

      $accessToken = $this->provider->getAccessToken('authorization_code', [
          'code' => $request->input('code')
      ]);

      $client = new \GuzzleHttp\Client();

      $response = $client->request(
        'GET', 
        'https://graph.microsoft.com/v1.0/me',[
          'headers' => [
            'Authorization' => 'Bearer ' . $accessToken->getToken(),
            'Content-Type' => 'application/json;odata.metadata=minimal;odata.streaming=true'
        ]
      ]);

      $body = $response->getBody();
      
      $statusCode = $response->getStatusCode();
      if($statusCode >= 200 && $statusCode < 400) {
        if(isset($body)) {
          $obj = json_decode($body);

          return Session::login($obj->displayName, $obj->mail, self::$DOMAIN);
        
        }            
      }

      // Redirect to error page
      return Session::get_auth_failure_url(self::$DOMAIN);
    }
  }
}

?>