<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Contract\Client;

use Heptacom\AdminOpenAuth\Contract\OAuthRuleScope;
use Heptacom\AdminOpenAuth\Contract\RedirectBehaviour;
use Heptacom\AdminOpenAuth\Contract\User;
use Shopware\Core\Framework\Struct\Struct;

abstract class ClientContract extends Struct
{
    abstract public function getLoginUrl(?string $state, RedirectBehaviour $behaviour): string;

    abstract public function getUser(string $state, string $code, RedirectBehaviour $behaviour): User;

    public function prepareOAuthRuleScope(OAuthRuleScope $scope): void
    {
        // by default, do nothing
    }
}
