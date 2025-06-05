<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1749144978ChangeTokenRequirements extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1749144978;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(
            'UPDATE `heptacom_admin_open_auth_user_token` SET `access_token` = \'\' WHERE `access_token` IS NULL'
        );

        $connection->executeStatement(
            'ALTER TABLE `heptacom_admin_open_auth_user_token`
                CHANGE COLUMN `access_token` `access_token` MEDIUMTEXT NOT NULL,
                CHANGE COLUMN `refresh_token` `refresh_token` MEDIUMTEXT NULL;'
        );
    }

    public function updateDestructive(Connection $connection): void
    {
    }
}
