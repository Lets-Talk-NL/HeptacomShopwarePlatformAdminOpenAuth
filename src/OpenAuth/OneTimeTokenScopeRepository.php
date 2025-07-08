<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\OpenAuth;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final readonly class OneTimeTokenScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        private ScopeRepositoryInterface $decorated,
    ) {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $this->decorated->getScopeEntityByIdentifier($identifier);
    }

    public function finalizeScopes(array $scopes, $grantType, ClientEntityInterface $clientEntity, $userIdentifier = null, ?string $authCodeId = null): array
    {
        if ($grantType === 'heptacom_admin_open_auth_one_time_token') {
            $grantType = 'password';
        }

        return $this->decorated->finalizeScopes($scopes, $grantType, $clientEntity, $userIdentifier, $authCodeId);
    }
}
