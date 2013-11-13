<?php
/**
 * This is a wrapper for the PHP-OAuth2 client library.
 */

$php_oauth2_path = libraries_get_path('PHP-OAuth2');
require $php_oauth2_path . '/Client.php';
require $php_oauth2_path . '/GrantType/IGrantType.php';
require $php_oauth2_path . '/GrantType/AuthorizationCode.php';
require $php_oauth2_path . '/GrantType/RefreshToken.php';
require $php_oauth2_path . '/GrantType/ClientCredentials.php';
require $php_oauth2_path . '/GrantType/Password.php';

class OAuth2Client {
  /**
   * Type of the authorization flow (https://drupal.org/node/1958718)
   * Can be: server-side | client-credentials | user-password
   */
  private $authorization_flow = 'server-side';

  /**
   * Id of the client.
   */
  private $client_id = NULL;

  /**
   * The delegate OAuth2\Client object, from PHP-OAuth2 library
   * which actually performs the core functionality of authentication.
   */
  private $client;

  /**
   * The URI that is used to get the token. Something like:
   *   url('oauth2/token', array('absolute' => TRUE));
   */
  private $token_endpoint = NULL;

  /**
   * The URI that is used to get the authorization code
   * (used only on the 'server-side' flow). Something like:
   *   url('oauth2/authorize', array('absolute' => TRUE));
   */
  private $authorization_endpoint = NULL;

  /**
   * The URI to which to redirect and send the authorization code
   * (used only on the 'server-side' flow). Something like:
   *   url('authorize', array('absolute' => TRUE));
   */
  private $redirect_uri = NULL;

  /**
   * Scopes that need to be authorized by the user,
   * separated by a space.
   */
  private $scope = NULL;

  /**
   * Username and password of the user (resource owner).
   * Used only on the user-password flow.
   */
  private $username = NULL;
  private $password = NULL;

  /**
   * Associated array that keeps data about the access token.
   */
  private $token = array(
    'access_token' => NULL,
    'expires_in' => NULL,
    'token_type' => NULL,
    'scope' => NULL,
    'refresh_token' => NULL,
    'expiration_time' => NULL,
  );

  /**
   * $authorization_flow can be:
   *     server-side | client-credentials | user-password
   * The $params argument contains any additional that are needed
   * by the different types of authorization flows.
   */
  public function __construct($authorization_flow, $client_id, $client_secret,
			      $token_endpoint, $params = array()) {
    $this->authorization_flow = $authorization_flow;
    $this->client_id = $client_id;
    $this->client = new OAuth2\Client($client_id, $client_secret);
    $this->token_endpoint = $token_endpoint;

    // set optional variables, if they are provided on the $params
    if (isset($params['authorization_endpoint'])) {
      $this->authorization_endpoint = $params['authorization_endpoint'];
    }
    if (isset($params['redirect_uri'])) {
      $this->redirect_uri = $params['redirect_uri'];
    }
    if (isset($params['scope'])) {
      $this->scope = $params['scope'];
    }
    if (isset($params['username'])) {
      $this->username = $params['username'];
    }
    if (isset($params['password'])) {
      $this->password = $params['password'];
    }

    // get the token data from the session, if it is stored there
    if (isset($_SESSION['oauth2_token'][$this->client_id])) {
      $this->token = $_SESSION['oauth2_token'][$this->client_id];
    }
  }

  public function fetch($url, $params = array()) {
    $this->getAccessToken();
    return $this->client->fetch($url, $params);
  }

  /**
   * Return the access token.
   * If the existing one is expired, get a new one
   * from the authentication server.
   */
  public function getAccessToken() {
    // try to get an existing token
    $expiration_time = $this->token['expiration_time'];
    if ($expiration_time > time()) {
      // the existing token can still be used
      return $this->token['access_token'];
    }

    // get token data
    switch ($this->authorization_flow) {
      case 'server-side':
        $token = $this->get_token_server_side();
        break;
      case 'user-password':
        $token = $this->get_token_user_password();
        break;
      default:
      case 'client-credentials':
        $token = $this->get_token_client_credentials();
        break;
    }
    $token['expiration_time'] =  time() + $token['expires_in'] - 60;

    // store the token (on session as well)
    $this->token = $token;
    $_SESSION['oauth2_token'][$this->client_id] = $token;
    $this->client->setAccessToken($token['access_token']);

    return $token['access_token'];
  }

  private function get_token_client_credentials() {
    $params = array();
    if (isset($this->scope)) {
      $params['scope'] = $this->scope;
    }

    $response = $this->client->getAccessToken(
      $this->token_endpoint,
      'client_credentials',
      $params
    );

    // TODO: error handling

    return $response['result'];
  }

  private function get_token_user_password() {
    // try to get a token using the refresh token
    $token = $this->get_token_refresh_token();
    if ($token) {
      return $token;
    }

    $params = array(
      'username' => $this->username,
      'password' => $this->password,
    );
    if (isset($this->scope)) {
      $params['scope'] = $this->scope;
    }

    $response = $this->client->getAccessToken(
      $this->token_endpoint,
      'password',
      $params
    );

    // TODO: error handling

    return $response['result'];
  }

  private function get_token_refresh_token() {
    $refresh_token = $this->token['refresh_token'];
    if (! $refresh_token) {
      return NULL;
    }

    $response = $this->client->getAccessToken(
      $this->token_endpoint,
      'refresh_token',
      array('refresh_token' => $refresh_token)
    );

    if ($response['code'] != 200) {
      // refresh_token expired or invalid
      return NULL;
    }

    return $response['result'];
  }

  private function get_token_server_side() {
    // try to get a token using the refresh token
    $token = $this->get_token_refresh_token();
    if ($token) {
      return $token;
    }

    if (!isset($_GET['code'])) {
      $extra_params = array(
        'state' => drupal_get_token($this->client_id),
      );
      if ($this->scope) {
        $extra_params['scope'] = $this->scope;
      }
      $auth_url = $this->client->getAuthenticationUrl(
        $this->authorization_endpoint,
        $this->redirect_uri,
        $extra_params);
      header('Location: ' . $auth_url);
      die('Redirect');
    }
    else {
      // check the 'state' parameter, to mittigate CSRF attacks
      if (! drupal_valid_token($_GET['state'], $this->client_id)) {
        drupal_set_message(t('The state does not validate, the received token is not trustable.'), 'error');
        return NULL;
      }

      $response = $this->client->getAccessToken(
        $this->token_endpoint,
        'authorization_code',
        array(
          'code' => $_GET['code'],
          'redirect_uri' => $this->redirect_uri,
        ));

      if ($response['code'] != 200) {
        return NULL;
      }

      return $response['result'];
    }
  }
}
