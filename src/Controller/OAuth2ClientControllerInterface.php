<?php

namespace Drupal\oauth2_client\Controller;

interface OAuth2ClientControllerInterface {

  /**
   * Callback for path oauth2/authorized.
   *
   * An authorized request in server-side flow
   * will be redirected here (having variables
   * 'code' and 'state').
   */
  public function redirectUrlPage();
}
