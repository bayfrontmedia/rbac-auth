<?php

/**
 * @package rbac-auth
 * @link https://github.com/bayfrontmedia/rbac-auth
 * @author John Robinson <john@bayfrontmedia.com>
 * @copyright 2021 Bayfront Media
 */

namespace Bayfront\RBAC;

use PDO;

interface MigrationInterface
{

    public function __construct(PDO $pdo);

    public function up(): void;

    public function down(): void;

}