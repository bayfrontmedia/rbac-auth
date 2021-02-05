<?php

/**
 * @package rbac-auth
 * @link https://github.com/bayfrontmedia/rbac-auth
 * @author John Robinson <john@bayfrontmedia.com>
 * @copyright 2021 Bayfront Media
 */

namespace Bayfront\RBAC\Migrations\v1;

use Bayfront\RBAC\MigrationInterface;
use PDO;

/**
 * Database migration for RBAC Auth v1.0.0
 */
class Schema implements MigrationInterface
{

    protected $pdo;

    public function __construct(PDO $pdo)
    {
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo = $pdo;
    }

    public function up(): void
    {

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_users` (
            `id` varchar(36) NOT NULL,
            `login` varchar(255) NOT NULL,
            `password` varchar(255) NOT NULL,
            `salt` varchar(32) NOT NULL,
            `firstName` varchar(120) DEFAULT NULL,
            `lastName` varchar(120) DEFAULT NULL,
            `companyName` varchar(120) DEFAULT NULL,     
            `email` varchar(255) DEFAULT NULL,
            `attributes` json DEFAULT NULL,
            `enabled` tinyint(1) NOT NULL DEFAULT 0,
            `createdAt` datetime NOT NULL DEFAULT current_timestamp(),
            `updatedAt` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            PRIMARY KEY (`id`),            
            UNIQUE (`login`))");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_user_meta` (
            `userId` varchar(36) NOT NULL,
            `metaKey` varchar(255) NOT NULL,
            `metaValue` longtext DEFAULT NULL,
            PRIMARY KEY (`userId`,`metaKey`),
            CONSTRAINT `del_user_meta` FOREIGN KEY (`userId`) REFERENCES `rbac_users` (`id`) ON DELETE CASCADE)");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_groups` (
            `id` varchar(36) NOT NULL,
            `name` varchar(255) NOT NULL,
            `attributes` json DEFAULT NULL,
            `createdAt` datetime NOT NULL DEFAULT current_timestamp(),
            `updatedAt` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            PRIMARY KEY (`id`),
            UNIQUE (`name`))");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_roles` (
            `id` varchar(36) NOT NULL,
            `name` varchar(255) NOT NULL,
            `attributes` json DEFAULT NULL,
            `enabled` tinyint(1) NOT NULL DEFAULT 0,
            `createdAt` datetime NOT NULL DEFAULT current_timestamp(),
            `updatedAt` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            PRIMARY KEY (`id`),
            UNIQUE (`name`))");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_permissions` (
            `id` varchar(36) NOT NULL,
            `name` varchar(255) NOT NULL,
            `description` varchar(255) DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE (`name`))");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_role_permissions` (
            `roleId` varchar(36) NOT NULL,
            `permissionId` varchar(36) NOT NULL,
            PRIMARY KEY (`roleId`,`permissionId`),
            CONSTRAINT `fk_role_permissions` FOREIGN KEY (`roleId`) REFERENCES `rbac_roles` (`id`) ON DELETE CASCADE,
            CONSTRAINT `fk_permission_roles` FOREIGN KEY (`permissionId`) REFERENCES `rbac_permissions` (`id`) ON DELETE CASCADE)");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_group_users` (
            `groupId` varchar(36) NOT NULL,
            `userId` varchar(36) NOT NULL,
            PRIMARY KEY (`groupId`,`userId`),
            CONSTRAINT `fk_user_groups` FOREIGN KEY (`groupId`) REFERENCES `rbac_groups` (`id`) ON DELETE CASCADE,
            CONSTRAINT `fk_group_users` FOREIGN KEY (`userId`) REFERENCES `rbac_users` (`id`) ON DELETE CASCADE)");

        $this->pdo->query("CREATE TABLE IF NOT EXISTS `rbac_role_users` (
            `roleId` varchar(36) NOT NULL,
            `userId` varchar(36) NOT NULL,
            PRIMARY KEY (`roleId`,`userId`),
            CONSTRAINT `fk_user_roles` FOREIGN KEY (`roleId`) REFERENCES `rbac_roles` (`id`) ON DELETE CASCADE,
            CONSTRAINT `fk_role_users` FOREIGN KEY (`userId`) REFERENCES `rbac_users` (`id`) ON DELETE CASCADE)");

    }

    public function down(): void
    {

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_role_users`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_group_users`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_role_permissions`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_permissions`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_roles`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_groups`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_user_meta`");

        $this->pdo->query("DROP TABLE IF EXISTS `rbac_users`");

    }

}