<?php

namespace Jiorpilla\SsoClientBundle\Security;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Turns verified SSO claims into your app's user. Implement it to sync users into your
 * own database; key them by $claims->sub, which never changes (emails can).
 *
 * Called after every SSO login, and for every request on the bearer-token API firewall.
 */
interface SsoUserProviderInterface
{
    public function loadOrCreateUser(SsoClaims $claims): UserInterface;
}
