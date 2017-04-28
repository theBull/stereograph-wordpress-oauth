<?php

namespace Zarmada\Auth;

require_once $_SERVER['DOCUMENT_ROOT'] . '/zarmada/auth/Validator.php';
use Zarmada\Auth\Validator;

class Session {
  
  /**
   * Specifies whether to perform a session check
   * to see if a session needs to be created
   * when getting or setting session values; if
   * set to false, it will effectively assume
   * that a session already exists.
   * 
   * @var boolean
   */
  private static $check_session = true;
  private static $supported_domains = ['microsoft', 'google'];

  public static function is_session_started() {
    return isset($_SESSION['SESSION_SET']) &&
      $_SESSION['SESSION_SET'] == true;
  }
 
  /**
   * Authentication mechanism for Google and Microsoft private pages.
   * danny@zarmada.com
   * @return [type] [description]
   */
  public static function protect(
    $domain, $auth_success_url, $auth_failure_url) {  

    try {

      Validator::domain($domain, self::$supported_domains);

      // Set the success and failure URLs
      self::set_auth_success_url($auth_success_url, $domain);
      self::set_auth_failure_url($auth_failure_url, $domain);

      // Set the domain of the current page as
      // the currently active domain.
      self::set_active_domain($domain);

      if(!self::is_logged_in($domain)) {

        $protocol = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://';
        $base_url = $protocol . $_SERVER['HTTP_HOST'];  
        
        // Navigate to the respective auth login url
        header('Location: ' . $base_url .
          "/oauth/public/$domain?" .
          "auth_success_url=$auth_success_url"
        );

      } else {
        // already logged in with one method or the other,
        // verify that the login user's email is correct
        // for the type of page they are attempting to access.
        Validator::email_domain(
          self::get_email($domain), 
          self::$supported_domains
        );
      }

    } catch(\Exception $exception) {
      // Navigate to the authentication failure page
      // if any exceptions are thrown.
      header('Location: ' . self::get_auth_failure_url($domain));
    }
  }

  public static function set_active_domain($domain) {
    Validator::domain($domain, self::$supported_domains);
    self::set("ACTIVE_DOMAIN", $domain);
  }
  public static function get_active_domain() {
    return self::get("ACTIVE_DOMAIN");
  }

  public static function set_auth_success_url($url, $domain) {
    Validator::domain($domain, self::$supported_domains);
    $url = filter_var($url, FILTER_SANITIZE_URL);
    self::set("AUTH_SUCCESS_URL@$domain", $url);
  }
  public static function get_auth_success_url($domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get("AUTH_SUCCESS_URL@$domain");
  }
  public  static function set_auth_failure_url($url, $domain) {
    $valid = Validator::domain($domain, self::$supported_domains);
    if($valid !== false && isset($url) && $url != null) {
      $url = filter_var($url, FILTER_SANITIZE_URL);
    }
    self::set("AUTH_FAILURE_URL@$domain", $url);
  }
  public static function get_auth_failure_url(
    $message = 'An error occured.', $domain
  ) {
    Validator::domain($domain, self::$supported_domains);
    $url = self::get("AUTH_FAILURE_URL@$domain");
    return $url . '?error=' . filter_var($message, FILTER_SANITIZE_URL);
  }
  public static function set_logout_url($url, $domain) {
    Validator::domain($domain, self::$supported_domains);
    $url = filter_var($url, FILTER_SANITIZE_URL);
    self::set("LOGOUT_REDIRECT_URL@$domain", $url);
  }
  public static function get_logout_url($domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get("LOGOUT_REDIRECT_URL@$domain");
  }
  public static function get_logout_href($domain) {
    return "/oauth/public/$domain/logout";
  }
  public static function logout($domain) {
    Validator::domain($domain, self::$supported_domains);
    $logout_url = self::get_logout_url($domain);
    if(!isset($logout_url)) {
      throw new \Exception('Logout redirect url is invalid');
    }

    // reinitialize the settings with blank
    // values for the current domain
    self::set_active_domain(null);
    self::set_is_logged_in(false, $domain);
    self::set_username(null, $domain);
    self::set_email(null, $domain);
    self::set_auth_success_url(null, $domain);
    self::set_auth_failure_url(null, $domain);
    self::set_logout_url(null, $domain);
    session_unset();

    return $logout_url;
  }
  public static function login($username = null, $email = null, $domain) {
    Validator::domain($domain, self::$supported_domains);

    self::set_is_logged_in(true, $domain);

    if($username !== null) {
      self::set_username($username, $domain);  
    }
    if($email !== null) {
      self::set_email($email, $domain);
    }

    $auth_success_url = self::get_auth_success_url($domain);
    if(!isset($auth_success_url)) {
      throw new \Exception('Failed to login. Auth success url invalid.');
    }

    // redirect to the login success page
    return $auth_success_url;
  }
  public static function auth_failure($message = 'An error occurred', $domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get_auth_failure_url($message, $domain);
  }
  public static function is_logged_in($domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get("IS_LOGGED_IN@$domain") === true &&
      self::get_username($domain) !== null &&
      self::get_email($domain) !== null;
  }
  public static function set_is_logged_in($status, $domain) {
    Validator::domain($domain, self::$supported_domains);
    $status = $status !== true ? false : true;
    self::set("IS_LOGGED_IN@$domain", $status);
  }
  public static function get_username($domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get("USERNAME@$domain");
  }
  public static function set_username($username, $domain) {
    Validator::domain($domain, self::$supported_domains);
    self::set("USERNAME@$domain", $username);
  }
  public static function get_email($domain) {
    Validator::domain($domain, self::$supported_domains);
    return self::get("EMAIL@$domain");
  }
  public static function set_email($email, $domain) {
    Validator::domain($domain, self::$supported_domains);
    Validator::email_domain($email, self::$supported_domains);
    self::set("EMAIL@$domain", $email);
  }

  private static function check_session() {
    if (!isset($_SESSION['SESSION_SET']) && 
      session_status() != PHP_SESSION_ACTIVE) {
      session_start();
      self::set('SESSION_SET', true);
    }
  }
  private static function ensure_init($key) {
    if(self::$check_session === true) {
      self::check_session();
    }

    if(!isset($_SESSION[$key])) {
      $_SESSION[$key] = null;
    }
  }
  private static function set($key, $value = null) {
    self::ensure_init($key);
    $_SESSION[$key] = $value;
  }
  private static function get($key) {
    self::ensure_init($key);
    return $_SESSION[$key];
  }
  protected static function set_check_session($check_session) {
    self::$check_session = $check_session;
  }
  public static function existing() {
    $static = new static();
    $static::set_check_session(false);
    return $static;
  }
}

?>
