<?php

namespace Jiorpilla\SsoClientBundle\Event;

use Jiorpilla\SsoClientBundle\Model\SsoClaims;

/**
 * Dispatched when the SSO reports, server to server, that a user signed out.
 *
 * The bundle already ends that user's sessions in this app on their next request. Listen
 * to this event to do more, such as revoking API tokens or clearing caches.
 */
final readonly class SsoBackchannelLogoutEvent
{
    public function __construct(
        public ?string $sub,
        public ?string $sid,
        public SsoClaims $claims,
    ) {
    }
}
