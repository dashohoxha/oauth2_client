<?php
namespace OAuth2;

/**
 * @file
 * class OAuth2\Client
 */

/**
 * The class OAuth2\Client is used to get authorization from
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
class Client {
  /**
   * Unique identifier of an OAuth2\Client object.
   */
  protected $id = NULL;

  /**
   * Associative array of the parameters that are needed
   * by the different types of authorization flows.
   *  - auth_flow :: server-side | client-credentials | user-password
   *  - client_id :: Client ID, as registered on the oauth2 server
   *  - client_secret :: Client secret, as registered on the oauth2 server
   *  - token_endpoint :: something like:
   *       https://oauth2_server.example.org/oauth2/token
   *  - authorization_endpoint :: somethig like:
   *       https://oauth2_server.example.org/oauth2/authorize
   *  - redirect_uri :: something like:
   *       url('oauth2/authorized', array('absolute' => TRUE)) or
   *       https://oauth2_client.example.org/oauth2/authorized
   *  - scope :: requested scopes, separated by a space
   *  - username :: username of the resource owner
   *  - password :: password of the resource owner
   */
  protected $params = array(
    'auth_flow' => NULL,
    'client_id' => NULL,
    'client_secret' => NULL,
    'token_endpoint' => NULL,
    'authorization_endpoint' => NULL,
    'redirect_uri' => NULL,
    'scope' => NULL,
    'username' => NULL,
    'password' => NULL,
  );

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
   * Construct an OAuth2\Client object.
   *
   * @param array $params
   *   Associative array of the parameters that are needed
   *   by the different types of authorization flows.
   */
  public function __construct($params = NULL, $id = NULL) {
    if ($params) $this->params = $params + $this->params;

    if (!$id) {
      $id = md5($this->params['token_endpoint']
            . $this->params['client_id']
            . $this->params['auth_flow']);
    }
    $this->id = $id;

    // Get the token data from the session, if it is stored there.
    if (isset($_SESSION['oauth2_token'][$this->id])) {
      $this->token = $_SESSION['oauth2_token'][$this->id] + $this->token;
    }
  }

  /**
   * Get and return an access token.
   *
   * If there is an existing token (stored in session),
   * return that one. But if the existing token is expired,
   * get a new one from the authorization server.
   */
  public function getAccessToken() {
    // Check wheather the existing token has expired.
    // We take the expiration time to be shorter by 10 sec
    // in order to account for any delays during the request.
    // Usually a token is valid for 1 hour, so making
    // the expiration time shorter by 10 sec is insignificant.
    // However it should be kept in mind during the tests,
    // where the expiration time is much shorter.
    $expiration_time = $this->token['expiration_time'];
    if ($expiration_time > (time() + 10)) {
      // The existing token can still be used.
      return $this->token['access_token'];
    }

    try {
      // Try to use refresh_token.
      $token = $this->getTokenRefreshToken();
    }
    catch (\Exception $e) {
      // Get a token.
      switch ($this->params['auth_flow']) {
        case 'client-credentials':
          $token = $this->getToken(array(
                     'grant_type' => 'client_credentials',
                     'scope' => $this->params['scope'],
                   ));
          break;

        case 'user-password':
          $token = $this->getToken(array(
                     'grant_type' => 'password',
                     'username' => $this->params['username'],
                     'password' => $this->params['password'],
                     'scope' => $this->params['scope'],
                   ));
          break;

        case 'server-side':
          $token = $this->getTokenServerSide();
          break;

        default:
          throw new \Exception(t('Unknown authorization flow "!auth_flow". Suported values for auth_flow are: client-credentials, user-password, server-side.',
              array('!auth_flow' => $this->params['auth_flow'])));
          break;
      }
    }
    $token['expiration_time'] = REQUEST_TIME + $token['expires_in'];

    // Store the token (on session as well).
    $this->token = $token;
    $_SESSION['oauth2_token'][$this->id] = $token;

    // Redirect to the original path (if this is a redirection
    // from the server-side flow).
    $this->redirectToOriginalPath();

    // Return the token.
    return $token['access_token'];
  }

  /**
   * Get a new access_token using the refresh_token.
   *
   * This is used for the server-side and user-password
   * flows (not for client-credentials, there is no
   * refresh_token in it).
   */
  protected function getTokenRefreshToken() {
    if (!$this->token['refresh_token']) {
      throw new \Exception(t('There is no refresh_token.'));
    }
    return $this->getToken(array(
        'grant_type' => 'refresh_token',
        'refresh_token' => $this->token['refresh_token'],
      ));
  }

  /**
   * Get an access_token using the server-side (authorization code) flow.
   *
   * This is done in two steps:
   *   - First, a redirection is done to the authentication
   *     endpoint, in order to request an authorization code.
   *   - Second, using this code, an access_token is requested.
   *
   * There are lots of redirects in this case and this part is the most
   * tricky and difficult to understand of the oauth2_client, so let
   * me try to explain how it is done.
   *
   * Suppose that in the controller of the path 'test/xyz'
   * we try to get an access_token:
   *     $client = oauth2_client_load('server-side-test');
   *     $access_token = $client->getAccessToken();
   * or:
   *     $client = new OAuth2\Client(array(
   *         'token_endpoint' => 'https://oauth2_server/oauth2/token',
   *         'client_id' => 'client1',
   *         'client_secret' => 'secret1',
   *         'auth_flow' => 'server-side',
   *         'authorization_endpoint' => 'https://oauth2_server/oauth2/authorize',
   *         'redirect_uri' => 'https://oauth2_client/oauth2/authorized',
   *       ));
   *     $access_token = $client->getAccessToken();
   *
   * From getAccessToken() we come to this function, getTokenServerSide(),
   * and since there is no $_GET['code'], we redirect to the authentication
   * url, but first we save the current path in the session:
   *     $_SESSION['oauth2_client_destination'] = 'test/xyz';
   *
   * Once the authentication and authorization is done on the server,
   * we are redirected by the server to the redirect uri:
   * 'oauth2/authorized'.  In the controller of this path we find out
   * that $_SESSION['oauth2_client_destination'] exists, and we
   * redirect to the saved path, 'test/xyz', passing along the query
   * parameters sent by the server (which include 'code', 'state', and
   * maybe other parameters as well.)
   *
   * Now the code: $access_token = $client->getAccessToken(); is
   * called again and we come back for a second time to the function
   * getTokenServerSide(). However this time we do have a
   * $_GET['code'], so we get a token from the server and return it.
   *
   * Inside the function getAccessToken() we save the returned token
   * in session and then, since the session variable 'oauth2_client_destination'
   * exists, we delete it and make another redirect to 'test/xyz'.
   * This third redirect is in order to have in browser the original url,
   * because from the last redirect we have something like this:
   * 'test/xyz?code=8557&state=3d7dh3&....'
   *
   * This time we come again for a third time to the code
   *     $access_token = $client->getAccessToken();
   * But this time we have a valid token already saved in session,
   * so the $client can find and return it without having to redirect etc.
   */
  protected function getTokenServerSide() {
    if (!isset($_GET['code'])) {
      $this->saveDrupalDestination();
      drupal_goto($this->getAuthenticationUrl());
    }
    else {
      $this->checkStateParameter();
      return $this->getToken(array(
          'grant_type' => 'authorization_code',
          'code' => $_GET['code'],
          'redirect_uri' => $this->params['redirect_uri'],
        ));
    }
  }

  /**
   * Save the destination to redirect after getting the token.
   */
  protected function saveDrupalDestination() {
    $destination = drupal_get_destination();
    $destination = $destination['destination'];
    $_SESSION['oauth2_client_destination'] = $destination;
  }

  /**
   * Redirect to the original path (if this is a redirection
   * from the server-side flow).
   */
  protected function redirectToOriginalPath() {
    if (isset($_SESSION['oauth2_client_destination'])) {
      $destination = $_SESSION['oauth2_client_destination'];
      unset($_SESSION['oauth2_client_destination']);
      unset($_REQUEST['code']);
      unset($_REQUEST['state']);
      drupal_goto($destination, array('query' => $_REQUEST));
    }
  }

  /**
   * Check the 'state' parameter, to mittigate CSRF attacks.
   */
  protected function checkStateParameter() {
    if (!drupal_valid_token($_GET['state'], $this->id)) {
      throw new \Exception(t('The state does not validate, the received token is not trustable.'));
    }
  }

  /**
   * Return the authentication url (used in case of the server-side flow).
   */
  public function getAuthenticationUrl() {
    $query_params = array(
      'response_type' => 'code',
      'client_id'     => $this->params['client_id'],
      'redirect_uri'  => $this->params['redirect_uri'],
      'state' => drupal_get_token($this->id)
    );
    if ($this->params['scope']) {
      $query_params['scope'] = $this->params['scope'];
    }
    $endpoint = $this->params['authorization_endpoint'];
    return $endpoint . '?' . http_build_query($query_params);
  }

  /**
   * Get and return an access token for the grant_type given in $params.
   */
  protected function getToken($data) {
    if (isset($data['scope']) and $data['scope'] == NULL) {
      unset($data['scope']);
    }

    $client_id = $this->params['client_id'];
    $client_secret = $this->params['client_secret'];
    $token_endpoint = $this->params['token_endpoint'];

    $options = array(
      'method' => 'POST',
      'data' => http_build_query($data),
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => 'Basic ' . base64_encode("$client_id:$client_secret"),
      ),
    );
    $result = drupal_http_request($token_endpoint, $options);

    if ($result->code != 200) {
      throw new \Exception(
        t("Failed to get an access token of grant_type !grant_type.\nError: !result_error",
          array(
            '!grant_type' => $data['grant_type'],
            '!result_error' => $result->error,
          ))
      );
    }

    return (Array) json_decode($result->data);
  }
}
