<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

use Illuminate\Http\Request;
use Illuminate\Http\Response;
echo $_SERVER['DOCUMENT_ROOT'];
require_once '/var/www/html/zarmada/auth/MicrosoftAuth.php';
require_once '/var/www/html/zarmada/auth/GoogleAuth.php';

use Zarmada\Auth\MicrosoftAuth;
use Zarmada\Auth\GoogleAuth;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| This file is where you may define all of the routes that are handled
| by your application. Just tell Laravel the URIs it should respond
| to using a Closure or controller method. Build something great!
|
*/

Route::get('/', function () {
  return view('welcome');
});

Route::get('/microsoft/logout', function(Request $request) {
  return redirect(MicrosoftAuth::logout());
});

Route::get('/microsoft', function (Request $request) {

  try {
    $microsoft = new MicrosoftAuth([
      'clientId'                => '1257b854-705c-405f-8955-1149330eb4f0',
      'clientSecret'            => 'y9c4wjptFtMVLped8VmPwjg',
      'redirectUri'             => 'https://website.zarmada.com/oauth/public/microsoft',
      'urlAuthorize'            => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      'urlAccessToken'          => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      'scopes'                  => 'user.read',
      'logout_url'              => 'https://login.windows.net/common/oauth2/logout?post_logout_redirect_uri=https://website.zarmada.com'
    ]);

    return redirect($microsoft->authenticate($request));

  } catch(\Exception $exception) {
    return redirect(MicrosoftAuth::auth_failure());
  }

});

Route::get('/google', function(Request $request) {
  try {
    $google = new GoogleAuth([
      'application_name'        => 'zarmada-website-153400',
      'redirect_uri'            => 'https://website.zarmada.com/oauth/public/google',
      'config_json'             => $_SERVER['DOCUMENT_ROOT'] . '/oauth/config/google-oauth.json',
      'developer_key'           => 'AIzaSyAaSqPsJ6DhtDU0Zy74MuoKwN2O2XmKyWU',
      'logout_url'              => 'https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=https://website.zarmada.com'
    ]);
    return redirect($google->authenticate($request));
  } catch(\Exception $exception) {
    return redirect(GoogleAuth::auth_failure());
  }
});

Route::get('/google/logout', function(Request $request) {
  return redirect(GoogleAuth::logout());
});
