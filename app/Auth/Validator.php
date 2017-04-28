<?php

namespace Zarmada\Auth;

class Validator {

  public static function domain($domain, $supported_domains) {
    if($domain == null) {
      return;
    }
    if(!in_array($domain, $supported_domains)) {
      throw new \Exception("Authentication domain not supported.");
    }
  }

  public static function email_domain($email, $supported_domains) {
    if($email == null) {
      return;
    }
    
    $supported = false;
    foreach($supported_domains as $supported_domain) {
      if(strpos($email, $supported_domain) ||
        strpos($email, "zarmada.com") ||
        strpos($email, "zarmada.net")) {
        $supported = true;
        break;
      }
    }

    if(!$supported) {
      throw new \Exception("Authentication domain not supported.");
    }
  }

  public static function auth_success_url($redirect_url, $domain) {
    $session_value = Session::get_auth_success_url($domain);
    if (!isset($redirect_url) && !isset($session_value)) {
      throw new \Exception('Auth success URL is invalid.');
    }
    
    // Sanitize the redirect uri passed from the client
    return $session_value ? $session_value : $redirect_url;
  }

  public static function token_response($response) {
    if(array_key_exists("error", $response)) {   
      trigger_error(
        '<h2>Request failed</h2>'
        . '<p><strong>Error: </strong>' . $response['error'] . '</p>'
        . '<p><strong>Error description: </strong>' . $response['error_description'] . '</p>', 
        E_USER_ERROR
      );
    }
  }
}

?>