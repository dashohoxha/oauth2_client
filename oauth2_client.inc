<?php
/**
 * @file
 * A wrapper for the PHP-OAuth2 client library,
 * which makes it suitable to be used in Drupal.
 */

$php_oauth2_path = libraries_get_path('PHP-OAuth2');
require $php_oauth2_path . '/Client.php';
require $php_oauth2_path . '/GrantType/IGrantType.php';
require $php_oauth2_path . '/GrantType/AuthorizationCode.php';
require $php_oauth2_path . '/GrantType/RefreshToken.php';
require $php_oauth2_path . '/GrantType/ClientCredentials.php';
require $php_oauth2_path . '/GrantType/Password.php';

/**
 * The class OAuth2Client is used to get authorization from
 * an oauth2 server. Its only goal is to get an access_token
 * from the oauth2 server, so the only public function
 * (besides the constructor) is getAccessToken().
 *
 * It can use authorization flows: server-side, client-credentials
 * and user-password. The details for each case are passed
 * to the constructor. All the three cases need a client_id,
 * a client_secret, and a token_endpoint. There can be an optional
 * scope as well.
 */
class OAuth2Client {
  /**
   * Type of the authorization flow (https://drupal.org/node/1958718)
   * Can be: server-side | client-credentials | user-password
   */
  protected $auth_flow = 'server-side';

  /**
   * Id of the client.
   */
  protected $client_id = NULL;

  /**
   * The delegate OAuth2\Client object, from PHP-OAuth2 library
   * which actually performs the core functionality of authorization.
   */
  protected $client;

  /**
   * The URI that is used to get the token. Something like:
   *   url('oauth2/token', array('absolute' => TRUE));
   */
  protected $token_endpoint = NULL;

  /**
   * The URI that is used to get the authorization code
   * (used only on the 'server-side' flow). Something like:
   *   url('oauth2/authorize', array('absolute' => TRUE));
   */
  protected $authorization_endpoint = NULL;

  /**
   * The URI to which to redirect and send the authorization code
   * (used only on the 'server-side' flow). Something like:
   *   url('oauth2/authorized', array('absolute' => TRUE));
   */
  protected $redirect_uri = NULL;

  /**
   * Scopes that need to be authorized by the user,
   * separated by a space.
   */
  protected $scope = NULL;

  /**
   * Username and password of the user (resource owner).
   * Used only on the user-password flow.
   */
  protected $username = NULL;
  protected $password = NULL;

  /**
   * Associated array that keeps data about the access token.
   */
  protected $token = array(
    'access_token' => NULL,
    'expires_in' => NULL,
    'token_type' => NULL,
    'scope' => NULL,
    'refresh_token' => NULL,
    'expiration_time' => NULL,
  );

  /**
   * Construct an OAuth2Client object.
   *
   * @param string $auth_flow
   *   Can be: server-side | client-credentials | user-password
   *
   * @param string $client_id
   *   Client ID, as registered on the oauth2 server.
   *
   * @param string $client_secret
   *   Client secret, as registered on the oauth2 server.
   *
   * @param string $token_endpoint
   *   Something like: https://oauth2_server.example.org/oauth2/token
   *
   * @param array $params
   *   Associative array of additional params that are needed
   *   by the different types of authorization flows.
   *   These parameters can be:
   *    - authorization_endpoint :: somethig like:
   *         https://oauth2_server.example.org/oauth2/authorize
   *    - redirect_uri :: something like:
   *         url('oauth2/authorized', array('absolute' => TRUE)) or
   *         https://oauth2_client.example.org/oauth2/authorized
   *    - scope :: requested scopes, separated by a space
   *    - username :: username of the resource owner
   *    - password :: password of the resource owner
   */
  public function __construct($auth_flow, $client_id, $client_secret, $token_endpoint, $params = array()) {
    $this->auth_flow = $auth_flow;
    $this->client_id = $client_id;
    $this->client = new OAuth2\Client($client_id, $client_secret);
    $this->token_endpoint = $token_endpoint;

    // Set optional variables, if they are provided on the $params.
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

    // Get the token data from the session, if it is stored there.
    if (isset($_SESSION['oauth2_token'][$this->client_id])) {
      $this->token = $_SESSION['oauth2_token'][$this->client_id];
    }
  }

  /**
   * Factory method to create a new OAuth2Client object.
   *
   * All the neccessary parameters are given as an associative array.
   *
   * @return OAuth2Client
   *   Returns an OAuth2Client object.
   *
   * @example
   *    $oauth2_client = OAuth2Client::create(array(
   *      'auth_flow' => 'user-password',
   *      'client_id' => 'client1',
   *      'client_secret' => 'secret1',
   *      'token_endpoint' => 'https://oath2_server.example.org/oath2/token',
   *      'username' => 'user1',
   *      'password' => 'passw1',
   *    ));
   */
  public static function create($params) {
    switch ($params['auth_flow']) {
      case 'client-credentials':
        $oauth2_client = new OAuth2Client(
          'client-credentials',
          $params['client_id'],
          $params['client_secret'],
          $params['token_endpoint']
        );
        break;

      case 'user-password':
        $oauth2_client = new OAuth2Client(
          'user-password',
          $params['client_id'],
          $params['client_secret'],
          $params['token_endpoint'],
          array(
            'username' => $params['username'],
            'password' => $params['password'],
          )
        );
        break;

      case 'server-side':
        $oauth2_client = new OAuth2Client(
          'server-side',
          $params['client_id'],
          $params['client_secret'],
          $params['token_endpoint'],
          array(
            'authorization_endpoint' => $params['authorization_endpoint'],
            'redirect_uri' => $params['redirect_uri'],
          )
        );
        break;

      case default:
        $flow = $params['auth_flow'];
        throw new Exception("Unknown flow type: '$flow'");
        break;
    }

    return $oauth2_client;
  }

  /**
   * Get and return an access token.
   *
   * If there is an existing token (stored in session),
   * return that one. But if the existing token is expired,
   * get a new one from the authorization server.
   */
  public function getAccessToken() {
    // Try to get an existing token.
    $expiration_time = $this->token['expiration_time'];
    if ($expiration_time > (time() + 10)) {
      // The existing token can still be used.
      return $this->token['access_token'];
    }

    // Get token data.
    switch ($this->auth_flow) {
      case 'server-side':
        $token = $this->get_token_server_side();
        break;

      case 'user-password':
        $token = $this->get_token_user_password();
        break;

      case default:
      case 'client-credentials':
        $token = $this->get_token_client_credentials();
        break;
    }
    $token['expiration_time'] = REQUEST_TIME + $token['expires_in'];

    // Store the token (on session as well).
    $this->token = $token;
    $_SESSION['oauth2_token'][$this->client_id] = $token;
    $this->client->setAccessToken($token['access_token']);

    // Redirect to the original path (if this is a redirection
    // from the server-side flow).
    if (isset($_SESSION['oauth2_client_destination'])) {
      $destination = $_SESSION['oauth2_client_destination'];
      unset($_SESSION['oauth2_client_destination']);
      unset($_REQUEST['code']);
      unset($_REQUEST['state']);
      drupal_goto($destination, array('query' => $_REQUEST));
    }

    // Return the token.
    return $token['access_token'];
  }

  /**
   * Get an access token with the client-credentials flow.
   *
   * This flow needs only a client_id and a client_secret. These must be
   * registered on the oauth2 server and the server must allow the
   * client-credentials grant type.
   */
  protected function get_token_client_credentials() {
    $params = array();
    if (isset($this->scope)) {
      $params['scope'] = $this->scope;
    }

    $response = $this->client->getAccessToken(
      $this->token_endpoint,
      'client_credentials',
      $params
    );

    if ($response['code'] != 200) {
      throw new Exeption(t('Failed to get an access token with client credentials.'));
    }

    return $response['result'];
  }

  /**
   * Get an access token from the authorization server
   *
   * with the user-password flow. Besides the client_id
   * and the client_secret this flow needs also the username
   * and password of the recourse owner. The client must be
   * registered on the oauth2 server, and the user must have
   * an account in it.
   */
  protected function get_token_user_password() {
    // Try to get a token using the refresh token.
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

    if ($response['code'] != 200) {
      throw new Exeption(t('Failed to get an access token with owner password.'));
    }

    return $response['result'];
  }

  /**
   * Get a new access_token using the refresh_token.
   *
   * This is used for the server-side and user-password
   * flows (not for client-credentials, there is no
   * refresh_token in it).
   * Returns NULL if getting an access_token fails.
   */
  protected function get_token_refresh_token() {
    $refresh_token = $this->token['refresh_token'];
    if (!$refresh_token) {
      return NULL;
    }

    $response = $this->client->getAccessToken(
      $this->token_endpoint,
      'refresh_token',
      array('refresh_token' => $refresh_token)
    );

    if ($response['code'] != 200) {
      // $refresh_token expired or invalid.
      return NULL;
    }

    return $response['result'];
  }

  /**
   * Get an access_token using the server-side (authorization code) flow.
   *
   * This is done in two steps:
   *   - First, a redirection is done to the authorization
   *     endpoint, in order to request an authorization code.
   *   - Second, using this code an access_token is requested.
   */
  protected function get_token_server_side() {
    // Try to get a token using the refresh token.
    $token = $this->get_token_refresh_token();
    if ($token) {
      return $token;
    }

    if (!isset($_GET['code'])) {
      $destination = drupal_get_destination();
      $destination = $destination['destination'];
      $_SESSION['oauth2_client_destination'] = $destination;

      $extra_params['state'] = drupal_get_token($this->client_id);
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
      // Check the 'state' parameter, to mittigate CSRF attacks.
      if (!drupal_valid_token($_GET['state'], $this->client_id)) {
        throw new Exception(t('The state does not validate, the received token is not trustable.'));
      }

      $response = $this->client->getAccessToken(
        $this->token_endpoint,
        'authorization_code',
        array(
          'code' => $_GET['code'],
          'redirect_uri' => $this->redirect_uri,
        ));

      if ($response['code'] != 200) {
        throw new Exception(t('Failed to get an access token with authorization code.'));
      }

      return $response['result'];
    }
  }
}
