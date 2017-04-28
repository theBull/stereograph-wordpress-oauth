<?php

namespace App\Auth;
require_once '../../vendor/google/apiclient-services/src/Google/Service/People.php';
require_once '../../vendor/google/apiclient/src/Google/Client.php';
require_once './Session.php';

use Google_Client;
use Google_Service_People;
use App\Auth\Session;

/**
 * This class performs a basic oauth authentication
 * using Google sign in and upon calling the handle_auth
 * method, retrieves the user's profile and sets session
 * variables for use throughout an application.
 */
class GoogleAuth {

  private static $DOMAIN = 'google';

  /**
   * Google auth client
   * @var Google_Client
   */
  public $client;

  /**
   * Config json filepath
   * @var String
   */
  public $config_json;

  /**
   * The URI to redirect to after succesful oauth
   * @var String
   */
  public $redirect_uri;

  /**
   * The authorization url
   * @var String
   */
  public $auth_url;

  /**
   * Logout url to redirect to after logout
   * @var String
   */
  public $logout_url;

  /**
   * The name of the application as listed in the Google
   * app Dashboard.
   * @var String
   */
  public $application_name;

  /**
   * The developer hash key available in the Google
   * App Credentials dashboard.
   * @var String
   */
  public $developer_key;

  /**
   * Scopes to request in the oauth request.
   * @var [type]
   */
  public $scope;

  /**
   * Url to redirect to upon successful authentication
   * @var String
   */
  public $auth_success_url;

  public function __construct($config) {
    // Eventually we can extend the scope to handle different
    // values or multiple values. For now, this class only
    // supports user profile information.
    $config['scope'] = Google_Service_People::USERINFO_PROFILE;

    $this->init($config);
  }

  private function init($config) {
    
echo 'blar';
if(!isset($config)) {
      throw new \Exception('Config is not valid.');
    }
    if(!isset($config['config_json'])) {
      throw new \Exception('Path to config json is invalid.');
    }
    if(!isset($config['application_name'])) {
      throw new \Exception('Application name is invalid.');
    }
    if(!isset($config['developer_key'])) {
      throw new \Exception('Developer Key is invalid.');
    }
    if(!isset($config['scope'])) {
      throw new \Exception('Scope is invalid.');
    }
    if(!isset($config['redirect_uri'])) {
      throw new \Exception('Redirect URL is invalid.');
    }
    if(!isset($config['logout_url'])) {
      throw new \Exception('Logout URL is invalid.');
    }

    $this->client = new Google_Client();
    $this->config_json = $config['config_json'];
    $this->redirect_uri = $config['redirect_uri'];
    $this->application_name = $config['application_name'];
    $this->developer_key = $config['developer_key'];
    $this->scope = $config['scope'];
    $this->logout_url = $config['logout_url'];

    // Let the session know where we want to go on logout.
    Session::set_logout_url($this->logout_url, self::$DOMAIN);

    $this->client->setAuthConfig($this->config_json);
    $this->client->addScope($this->scope);
    $this->client->setApplicationName($this->application_name);
    $this->client->setDeveloperKey($this->developer_key);
    $this->client->setRedirectUri($this->redirect_uri);
    $this->client->setPrompt('select_account');
    $this->auth_url = $this->client->createAuthUrl();
  }

  public static function auth_failure() {
    return Session::auth_failure(
      'There was an error during Google authentication.', 
      self::$DOMAIN
    );
  }

  public static function logout() {
    return Session::logout(self::$DOMAIN);
  }

  public function authenticate($request) {
    if (!$request->has('code')) {

      // User is unauthenticated, send them through the auth process
      return filter_var($this->auth_url, FILTER_SANITIZE_URL);

    } else {
      $code = $request->input('code');

      // process the code received from the auth process
      $token_response = $this->process_code($code);
      
      // Ensure the token response is valid
      Validator::token_response($token_response);
      
      // Process and retrieve the access token
      $raw_token = $this->process_token_response($token_response);

      if(isset($raw_token)) {
        // Handle the token and process the id_token
        $this->handle_id_token($raw_token);
         
        // Create the people service and make requests
        return $this->make_profile_request();

      } else {
        throw new \Exception('Failed to retrieve the access token');
      }
    }
  }

  private function process_code($code) {
    // grab the code from the URL and generate an access token
    $response = $this->client->fetchAccessTokenWithAuthCode($code);

    if(!is_array($response)) {
      throw new \Exception('Token response was invalid.');
    }

    return $response;
  }

  private function process_token_response($token_response) {
    $this->client->setAccessToken($token_response);
    return $this->client->getAccessToken();
  }

  private function handle_id_token($token) {

    try {
      $id_token = $this->client->verifyIdToken($token['id_token']);

      // grab the domain from the id_token
      $email = $id_token['email'];

      // Email is valid, stuff it into the session
      Session::set_email($email, self::$DOMAIN);

    } catch(\Exception $exception) {
      // clear the access token to disable any
      // approved permissions for the user's account
      $this->client->revokeToken();
      
      throw new \Exception('Google Login failed');
    }
  }

  private function make_profile_request() {
    // create the service
    $service = new Google_Service_People($this->client); 
    $results = $service->people->get('people/me');
    
    if(!$results) {
      throw new \Exception('No matching profile results.');
    }
   
    $names = $results->getNames();

    $username;    
    if(is_array($names) && $names[0]) {
      try {
        // Get the user's display name / profile information
        $username = $names[0]->getDisplayName();
      } catch(\Exception $exception) {
        throw new \Exception("Failed to retrieve username.");
      }
    }
      
    // Login. Session handles the redirect
    return Session::login(
      $username, 
      Session::get_email(self::$DOMAIN), 
      self::$DOMAIN
    );
  }
}
?>
