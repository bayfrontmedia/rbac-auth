<?php

/**
 * @package rbac-auth
 * @link https://github.com/bayfrontmedia/rbac-auth
 * @author John Robinson <john@bayfrontmedia.com>
 * @copyright 2021 Bayfront Media
 */

namespace Bayfront\RBAC;

use Bayfront\ArrayHelpers\Arr;
use Bayfront\RBAC\Exceptions\AuthenticationException;
use Bayfront\RBAC\Exceptions\InvalidGrantException;
use Bayfront\RBAC\Exceptions\InvalidGroupException;
use Bayfront\RBAC\Exceptions\InvalidKeysException;
use Bayfront\RBAC\Exceptions\InvalidMetaException;
use Bayfront\RBAC\Exceptions\InvalidPermissionException;
use Bayfront\RBAC\Exceptions\InvalidRoleException;
use Bayfront\RBAC\Exceptions\InvalidUserException;
use Bayfront\RBAC\Exceptions\LoginExistsException;
use Bayfront\RBAC\Exceptions\NameExistsException;
use Bayfront\StringHelpers\Str;
use Exception;
use PDO;
use PDOException;

class Auth
{

    /** @var PDO $pdo */

    protected $pdo;

    protected $pepper;

    public function __construct(PDO $pdo, string $pepper = '')
    {

        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Throw exceptions

        $this->pdo = $pdo;

        $this->pepper = $pepper;

    }

    /*
     * ############################################################
     * Groups
     * ############################################################
     */

    protected $valid_group_keys = [
        'name',
        'attributes',
    ];

    protected $required_group_keys = [
        'name'
    ];

    /**
     * Does group ID exist.
     *
     * @param string $id
     *
     * @return bool
     */

    public function groupIdExists(string $id): bool
    {

        $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_groups WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Does group name exist.
     *
     * @param string $name
     * @param string|null $exclude_id
     *
     * @return bool
     */

    public function groupNameExists(string $name, string $exclude_id = NULL): bool
    {

        if (NULL === $exclude_id) {

            $stmt = $this->pdo->prepare("SELECT 1 
                FROM rbac_groups
                WHERE name = :name");

            $stmt->execute([
                'name' => $name
            ]);

        } else {

            $stmt = $this->pdo->prepare("SELECT 1 
                FROM rbac_groups 
                WHERE name = :name AND id != :id");

            $stmt->execute([
                'name' => $name,
                'id' => $exclude_id
            ]);

        }

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Get all groups.
     *
     * @return array
     */

    public function getGroups(): array
    {

        $groups = $this->pdo->query("SELECT * FROM rbac_groups ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

        foreach ($groups as $k => $group) {

            if (NULL !== $group['attributes']) {

                $groups[$k]['attributes'] = json_decode($group['attributes'], true);

            }

        }

        return $groups;

    }

    /**
     * Get group.
     *
     * @param string $id
     *
     * @return array
     *
     * @throws InvalidGroupException
     */

    public function getGroup(string $id): array
    {

        $stmt = $this->pdo->prepare("SELECT * FROM rbac_groups WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        $group = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$group) {

            throw new InvalidGroupException('Unable to get group: group ID (' . $id . ') does not exist');

        }

        if (NULL !== $group['attributes']) {

            $group['attributes'] = json_decode($group['attributes'], true);

        }

        return $group;

    }

    /**
     * Create a group.
     *
     * @param array $group
     *
     * @return string (Group ID)
     *
     * @throws InvalidKeysException
     * @throws NameExistsException
     *
     * @noinspection SqlInsertValues
     */

    public function createGroup(array $group): string
    {

        $invalid = Arr::except($group, $this->valid_group_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to create group: invalid keys');

        }

        if (Arr::isMissing($group, $this->required_group_keys)) {

            throw new InvalidKeysException('Unable to create group: missing required keys');

        }

        // If name exists in this organization

        if ($this->groupNameExists($group['name'])) {

            throw new NameExistsException('Unable to create group: name (' . $group['name'] . ') already exists');

        }

        $group['id'] = Str::uuid();

        // Convert arrays

        if (isset($group['attributes']) && NULL !== $group['attributes']) {

            $group['attributes'] = json_encode((array)$group['attributes']);

        }

        $sql = sprintf("INSERT INTO rbac_groups (%s) VALUES (%s)",
            implode(', ', array_keys($group)),
            implode(', ', array_fill(0, count($group), '?')));

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute(array_values($group));

        return $group['id'];

    }

    /**
     * Update group.
     *
     * @param string $id
     * @param array $group
     *
     * @return void
     *
     * @throws InvalidGroupException
     * @throws InvalidKeysException
     * @throws NameExistsException
     *
     * @noinspection DuplicatedCode
     */

    public function updateGroup(string $id, array $group): void
    {

        $invalid = Arr::except($group, $this->valid_group_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to update group: invalid keys');

        }

        $existing_group = $this->getGroup($id);

        $updated_group = array_merge($existing_group, $group);

        if ($existing_group === $updated_group) { // No updates to be made

            return;

        }

        // If updating the name, check it does not exist

        if (isset($group['name']) && $this->groupNameExists($group['name'], $id)) {

            throw new NameExistsException('Unable to create group: name (' . $group['name'] . ') already exists');

        }

        // Convert arrays, preserving preexisting attributes

        if (isset($updated_group['attributes']) && NULL !== $updated_group['attributes']) {

            $group['attributes'] = json_encode((array)$updated_group['attributes']);

        }

        $sql = "UPDATE rbac_groups SET" . " ";

        $placeholders = [];

        foreach ($group as $k => $v) {

            $sql .= $k . '=?, ';

            $placeholders[] = $v;

        }

        $sql = rtrim($sql, ', ') . ' WHERE id = ?';

        $placeholders[] = $id;

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute($placeholders);

    }

    /**
     * Delete group.
     *
     * @param string $id
     *
     * @return bool (If group existed)
     */

    public function deleteGroup(string $id): bool
    {

        $stmt = $this->pdo->prepare("DELETE FROM rbac_groups WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return $stmt->rowCount() > 0;

    }

    /**
     * Get all users in group.
     *
     * @param string $group_id
     *
     * @return array
     */

    public function getGroupUsers(string $group_id): array
    {

        $stmt = $this->pdo->prepare("SELECT
            ru.id, ru.login, ru.firstName, ru.lastName, ru.companyName, ru.email, ru.attributes, ru.enabled, ru.createdAt, ru.updatedAt
            FROM rbac_users AS ru 
            LEFT JOIN rbac_group_users AS rgu ON ru.id = rgu.userId 
            WHERE rgu.groupId = :group_id
            ORDER BY ru.createdAt");

        $stmt->execute([
            'group_id' => $group_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /**
     * Does group have user(s).
     *
     * @param string $group_id
     * @param string|array $user_id
     *
     * @return bool
     */

    public function groupHasUser(string $group_id, $user_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getGroupUsers($group_id), 'id'), (array)$user_id)) == count((array)$user_id);
    }

    /**
     * Enable all users in group.
     *
     * @param string $group_id
     *
     * @return void
     */

    public function enableGroupUsers(string $group_id): void
    {

        $users = Arr::pluck($this->getGroupUsers($group_id), 'id');

        $in = '';

        foreach ($users as $user) {

            $in .= "'" . $user . "', ";

        }

        $in = rtrim($in, ', ');

        $sql = "UPDATE rbac_users SET enabled = 1 WHERE id IN (" . $in . ")";

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute();

    }

    /**
     * Disable all users in group.
     *
     * @param string $group_id
     *
     * @return void
     */

    public function disableGroupUsers(string $group_id): void
    {

        $users = Arr::pluck($this->getGroupUsers($group_id), 'id');

        $in = '';

        foreach ($users as $user) {

            $in .= "'" . $user . "', ";

        }

        $in = rtrim($in, ', ');

        $sql = "UPDATE rbac_users SET enabled = 0 WHERE id IN (" . $in . ")";

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute();

    }

    /*
    * ############################################################
    * Permissions
    * ############################################################
    */

    protected $valid_permission_keys = [
        'name',
        'description'
    ];

    protected $required_permission_keys = [
        'name'
    ];

    /**
     * Does permission ID exist.
     *
     * @param string $id
     *
     * @return bool
     */

    public function permissionIdExists(string $id): bool
    {

        $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_permissions WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Does permission name exist.
     *
     * @param string $name
     * @param string|null $exclude_id
     *
     * @return bool
     */

    public function permissionNameExists(string $name, string $exclude_id = NULL): bool
    {

        if (NULL === $exclude_id) {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_permissions WHERE name = :name");

            $stmt->execute([
                'name' => $name
            ]);

        } else {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_permissions WHERE name = :name AND id != :id");

            $stmt->execute([
                'name' => $name,
                'id' => $exclude_id
            ]);

        }

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Get all permissions.
     *
     * @return array
     */

    public function getPermissions(): array
    {
        return $this->pdo->query("SELECT * FROM rbac_permissions ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get permission.
     *
     * @param string $id
     *
     * @return array
     *
     * @throws InvalidPermissionException
     */

    public function getPermission(string $id): array
    {

        $stmt = $this->pdo->prepare("SELECT * FROM rbac_permissions WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        $permission = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$permission) {

            throw new InvalidPermissionException('Unable to get permission: permission ID (' . $id . ') does not exist');

        }

        return $permission;

    }

    /**
     * Create permission.
     *
     * @param array $permission
     *
     * @return string (Permission ID)
     *
     * @throws InvalidKeysException
     * @throws NameExistsException
     *
     * @noinspection SqlInsertValues
     */

    public function createPermission(array $permission): string
    {

        $invalid = Arr::except($permission, $this->valid_permission_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to create permission: invalid keys');

        }

        if (Arr::isMissing($permission, $this->required_permission_keys)) {

            throw new InvalidKeysException('Unable to create permission: missing required keys');

        }

        if ($this->permissionNameExists($permission['name'])) {

            throw new NameExistsException('Unable to create permission: name (' . $permission['name'] . ') already exists');

        }

        $permission['id'] = Str::uuid();

        $sql = sprintf("INSERT INTO rbac_permissions (%s) VALUES (%s)",
            implode(', ', array_keys($permission)),
            implode(', ', array_fill(0, count($permission), '?')));

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute(array_values($permission));

        return $permission['id'];

    }

    /**
     * Update permission.
     *
     * @param string $id
     * @param array $permission
     *
     * @return void
     *
     * @throws InvalidKeysException
     * @throws InvalidPermissionException
     * @throws NameExistsException
     *
     * @noinspection DuplicatedCode
     */

    public function updatePermission(string $id, array $permission): void
    {

        $invalid = Arr::except($permission, $this->valid_permission_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to update permission: invalid keys');

        }

        if (!$this->permissionIdExists($id)) {

            throw new InvalidPermissionException('Unable to update permission: permission ID (' . $id . ') does not exist');

        }

        // If updating the name, check that it does not already exist

        if (isset($permission['name']) && $this->permissionNameExists($permission['name'], $id)) {

            throw new NameExistsException('Unable to update permission: name (' . $permission['name'] . ') already exists');

        }

        $sql = "UPDATE rbac_permissions SET" . " ";

        $placeholders = [];

        foreach ($permission as $k => $v) {

            $sql .= $k . '=?, ';

            $placeholders[] = $v;

        }

        $sql = rtrim($sql, ', ') . ' WHERE id = ?';

        $placeholders[] = $id;

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute($placeholders);

    }

    /**
     * Delete permission.
     *
     * @param string $id
     *
     * @return bool (If permission existed)
     */

    public function deletePermission(string $id): bool
    {

        $stmt = $this->pdo->prepare("DELETE FROM rbac_permissions WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return $stmt->rowCount() > 0;

    }

    /**
     * Get all roles with permission.
     *
     * @param string $permission_id
     *
     * @return array
     */

    public function getPermissionRoles(string $permission_id): array
    {

        $stmt = $this->pdo->prepare("SELECT rr.* FROM rbac_roles AS rr
            LEFT JOIN rbac_role_permissions AS rrp ON rr.id = rrp.roleId
            WHERE rrp.permissionId = :permission_id
            ORDER BY rr.name");

        $stmt->execute([
            'permission_id' => $permission_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /*
     * ############################################################
     * Roles
     * ############################################################
     */

    protected $valid_role_keys = [
        'name',
        'attributes',
        'enabled'
    ];

    protected $required_role_keys = [
        'name'
    ];

    /**
     * Does role ID exist.
     *
     * @param string $id
     *
     * @return bool
     */

    public function roleIdExists(string $id): bool
    {

        $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_roles WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Does role name exist.
     *
     * @param string $name
     * @param string|null $exclude_id
     *
     * @return bool
     */

    public function roleNameExists(string $name, string $exclude_id = NULL): bool
    {

        if (NULL === $exclude_id) {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_roles WHERE name = :name");

            $stmt->execute([
                'name' => $name
            ]);

        } else {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_roles WHERE name = :name AND id != :id");

            $stmt->execute([
                'name' => $name,
                'id' => $exclude_id
            ]);

        }

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Get all roles.
     *
     * @return array
     */

    public function getRoles(): array
    {

        $roles = $this->pdo->query("SELECT * FROM rbac_roles ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

        foreach ($roles as $k => $role) {

            if (NULL !== $role['attributes']) {

                $roles[$k]['attributes'] = json_decode($role['attributes'], true);

            }

        }

        return $roles;

    }

    /**
     * Get role.
     *
     * @param string $id
     *
     * @return array
     *
     * @throws InvalidRoleException
     */

    public function getRole(string $id): array
    {

        $stmt = $this->pdo->prepare("SELECT * FROM rbac_roles WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        $role = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$role) {

            throw new InvalidRoleException('Unable to get role: role ID (' . $id . ') does not exist');

        }

        if (NULL !== $role['attributes']) {

            $role['attributes'] = json_decode($role['attributes'], true);

        }

        return $role;

    }

    /**
     * Create role.
     *
     * @param array $role
     *
     * @return string (Role ID)
     *
     * @throws InvalidKeysException
     * @throws NameExistsException
     *
     * @noinspection SqlInsertValues
     */

    public function createRole(array $role): string
    {

        $invalid = Arr::except($role, $this->valid_role_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to create role: invalid keys');

        }

        if (Arr::isMissing($role, $this->required_role_keys)) {

            throw new InvalidKeysException('Unable to create role: missing required keys');

        }

        if ($this->roleNameExists($role['name'])) {

            throw new NameExistsException('Unable to create role: name (' . $role['name'] . ') already exists');

        }

        $role['id'] = Str::uuid();

        // Convert arrays

        if (isset($role['attributes']) && NULL !== $role['attributes']) {

            if (isset($role['attributes']['enabled'])) {
                $role['attributes']['enabled'] = (int)$role['attributes']['enabled'];
            }

            $role['attributes'] = json_encode((array)$role['attributes']);

        }

        $sql = sprintf("INSERT INTO rbac_roles (%s) VALUES (%s)",
            implode(', ', array_keys($role)),
            implode(', ', array_fill(0, count($role), '?')));

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute(array_values($role));

        return $role['id'];

    }

    /**
     * Update role.
     *
     * @param string $id
     * @param array $role
     *
     * @return void
     *
     * @throws InvalidKeysException
     * @throws InvalidRoleException
     * @throws NameExistsException
     *
     * @noinspection DuplicatedCode
     */

    public function updateRole(string $id, array $role): void
    {

        $invalid = Arr::except($role, $this->valid_role_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to update role: invalid keys');

        }

        $existing_role = $this->getRole($id);

        $updated_role = array_merge($existing_role, $role);

        if ($existing_role === $updated_role) { // No updates to be made

            return;

        }

        // If updating the name, check that it does not already exist

        if (isset($role['name']) && $this->roleNameExists($role['name'], $id)) {

            throw new NameExistsException('Unable to update role: name (' . $role['name'] . ') already exists');

        }

        // Convert arrays, preserving preexisting attributes

        if (isset($updated_role['attributes']) && NULL !== $updated_role['attributes']) {

            $role['attributes'] = json_encode((array)$updated_role['attributes']);

        }

        $sql = "UPDATE rbac_roles SET" . " ";

        $placeholders = [];

        foreach ($role as $k => $v) {

            if ($k == 'enabled') {
                $v = (int)$v;
            }

            $sql .= $k . '=?, ';

            $placeholders[] = $v;

        }

        $sql = rtrim($sql, ', ') . ' WHERE id = ?';

        $placeholders[] = $id;

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute($placeholders);

    }

    /**
     * Delete role.
     *
     * @param string $id
     *
     * @return bool (If role existed)
     */

    public function deleteRole(string $id): bool
    {

        $stmt = $this->pdo->prepare("DELETE FROM rbac_roles WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return $stmt->rowCount() > 0;

    }

    /**
     * Get all permissions of role.
     *
     * @param string $role_id
     *
     * @return array
     */

    public function getRolePermissions(string $role_id): array
    {

        $stmt = $this->pdo->prepare("SELECT rp.* FROM rbac_permissions AS rp
            LEFT JOIN rbac_role_permissions AS rrp ON rp.id = rrp.permissionId
            WHERE rrp.roleId = :role_id
            ORDER BY rp.name");

        $stmt->execute([
            'role_id' => $role_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /**
     * Does role have permission(s).
     *
     * @param string $role_id
     * @param string|array $permission_id
     *
     * @return bool
     */

    public function roleHasPermission(string $role_id, $permission_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getRolePermissions($role_id), 'id'), (array)$permission_id)) == count((array)$permission_id);
    }

    /**
     * Get all users with role.
     *
     * @param string $role_id
     *
     * @return array
     */

    public function getRoleUsers(string $role_id): array
    {

        $stmt = $this->pdo->prepare("SELECT
            ru.id, ru.login, ru.firstName, ru.lastName, ru.companyName, ru.email, ru.attributes, ru.enabled, ru.createdAt, ru.updatedAt
            FROM rbac_users AS ru 
            LEFT JOIN rbac_role_users AS rru ON ru.id = rru.userId 
            WHERE rru.roleId = :role_id
            ORDER BY ru.createdAt");

        $stmt->execute([
            'role_id' => $role_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /**
     * Does role have user(s).
     *
     * @param string $role_id
     * @param string|array $user_id
     *
     * @return bool
     */

    public function roleHasUser(string $role_id, $user_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getRoleUsers($role_id), 'id'), (array)$user_id)) == count((array)$user_id);
    }


    /**
     * Enable role.
     *
     * @param string $role_id
     *
     * @return void
     */

    public function enableRole(string $role_id): void
    {

        $stmt = $this->pdo->prepare("UPDATE rbac_roles SET enabled = 1
            WHERE id = :id");

        $stmt->execute([
            'id' => $role_id
        ]);

    }

    /**
     * Disable role.
     *
     * @param string $role_id
     *
     * @return void
     */

    public function disableRole(string $role_id): void
    {

        $stmt = $this->pdo->prepare("UPDATE rbac_roles SET enabled = 0
            WHERE id = :id");

        $stmt->execute([
            'id' => $role_id
        ]);

    }

    /*
     * ############################################################
     * Users
     * ############################################################
     */

    protected $valid_user_keys = [
        'login',
        'password',
        'firstName',
        'lastName',
        'companyName',
        'email',
        'attributes',
        'enabled'
    ];

    protected $required_user_keys = [
        'login',
        'password'
    ];

    /**
     * Return a secure password hash using a plaintext password and user-specific salt.
     *
     * @param string $password (Plaintext password)
     * @param string $salt (User-specific salt)
     *
     * @return string (Hashed password)
     */

    protected function _hashPassword(string $password, string $salt): string
    {

        $salt = hash_hmac('sha512', $salt, $this->pepper); // Database & server supplied

        $salt = hash_hmac('sha512', $salt, $password); // User supplied

        return password_hash($salt . $password, PASSWORD_DEFAULT); // Create a one-way hash, verified using password_verify

    }

    /**
     * Verify a plaintext password and user-specific salt against a hashed password.
     *
     * @param string $password
     * @param string $salt
     * @param string $hashed_password
     *
     * @return bool
     */

    protected function _verifyPassword(string $password, string $salt, string $hashed_password): bool
    {

        $salt = hash_hmac('sha512', $salt, $this->pepper); // Database & server supplied

        $salt = hash_hmac('sha512', $salt, $password); // User supplied

        return (password_verify($salt . $password, $hashed_password));

    }

    /**
     * Create a unique 32 byte user salt
     *
     * @return string
     *
     * @throws Exception
     */

    protected function _createSalt(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Does user ID exist.
     *
     * @param string $id
     *
     * @return bool
     */

    public function userIdExists(string $id): bool
    {

        $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_users WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Does user login exist.
     *
     * @param string $login
     * @param string|null $exclude_id
     *
     * @return bool
     */

    public function userLoginExists(string $login, string $exclude_id = NULL): bool
    {

        if (NULL === $exclude_id) {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_users
                WHERE login = :login");

            $stmt->execute([
                'login' => $login
            ]);

        } else {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_users 
                WHERE login = :login AND id != :id");

            $stmt->execute([
                'login' => $login,
                'id' => $exclude_id
            ]);

        }

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Does user email exist.
     *
     * NOTE:
     * There are no restrictions that prevent duplicate email addresses from being used.
     * It is up to each application to utilize this method to enforce unique emails, if desired.
     *
     * @param string $email
     * @param string|null $exclude_id
     *
     * @return bool
     */

    public function userEmailExists(string $email, string $exclude_id = NULL): bool
    {

        if (NULL === $exclude_id) {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_users
                WHERE email = :email");

            $stmt->execute([
                'email' => $email
            ]);

        } else {

            $stmt = $this->pdo->prepare("SELECT 1 FROM rbac_users 
                WHERE email = :email AND id != :id");

            $stmt->execute([
                'email' => $email,
                'id' => $exclude_id
            ]);

        }

        return ($stmt->fetchColumn()) ? true : false;

    }

    /**
     * Get all users.
     *
     * @return array
     */

    public function getUsers(): array
    {

        $users = $this->pdo->query("SELECT
            id, login, firstName, lastName, companyName, email, attributes, enabled, createdAt, updatedAt
            FROM rbac_users ORDER BY createdAt")->fetchAll(PDO::FETCH_ASSOC);

        foreach ($users as $k => $user) {

            if (NULL !== $user['attributes']) {

                $users[$k]['attributes'] = json_decode($user['attributes'], true);

            }

        }

        return $users;

    }

    /**
     * Get user.
     *
     * @param string $id
     *
     * @return array
     *
     * @throws InvalidUserException
     */

    public function getUser(string $id): array
    {

        $stmt = $this->pdo->prepare("SELECT
            id, login, firstName, lastName, companyName, email, attributes, enabled, createdAt, updatedAt
            FROM rbac_users 
            WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {

            throw new InvalidUserException('Unable to get user: user ID (' . $id . ') does not exist');

        }

        if (NULL !== $user['attributes']) {

            $user['attributes'] = json_decode($user['attributes'], true);

        }

        return $user;

    }

    /**
     * Create user.
     *
     * @param array $user
     *
     * @return string (User ID)
     *
     * @throws InvalidKeysException
     * @throws LoginExistsException
     * @throws Exception
     *
     * @noinspection SqlInsertValues
     */

    public function createUser(array $user): string
    {

        $invalid = Arr::except($user, $this->valid_user_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to create user: invalid keys');

        }

        if (Arr::isMissing($user, $this->required_user_keys)) {

            throw new InvalidKeysException('Unable to create user: missing required keys');

        }

        // If login exists

        if ($this->userLoginExists($user['login'])) {

            throw new LoginExistsException('Unable to create user: login (' . $user['login'] . ') already exists');

        }

        $user['id'] = Str::uuid();

        // Create salt

        $user['salt'] = $this->_createSalt();

        // Hash password

        $user['password'] = $this->_hashPassword($user['password'], $user['salt']);

        // Convert arrays

        if (isset($user['attributes']) && NULL !== $user['attributes']) {

            if (isset($user['attributes']['enabled'])) {
                $user['attributes']['enabled'] = (int)$user['attributes']['enabled'];
            }

            $user['attributes'] = json_encode((array)$user['attributes']);

        }

        $sql = sprintf("INSERT INTO rbac_users (%s) VALUES (%s)",
            implode(', ', array_keys($user)),
            implode(', ', array_fill(0, count($user), '?')));

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute(array_values($user));

        return $user['id'];

    }

    /**
     * Update user.
     *
     * @param string $id
     * @param array $user
     *
     * @return void
     *
     * @throws InvalidKeysException
     * @throws InvalidUserException
     * @throws LoginExistsException
     * @throws Exception
     *
     * @noinspection DuplicatedCode
     */

    public function updateUser(string $id, array $user): void
    {

        $invalid = Arr::except($user, $this->valid_user_keys);

        if (!empty($invalid)) {

            throw new InvalidKeysException('Unable to update user: invalid keys');

        }

        $existing_user = $this->getUser($id);

        $updated_user = array_merge($existing_user, $user);

        if ($existing_user === $updated_user) { // No updates to be made

            return;

        }

        // If updating the login, check it does not already exist

        if (isset($user['login']) && $this->userLoginExists($user['login'], $id)) {

            throw new LoginExistsException('Unable to update user: login (' . $user['login'] . ') already exists');

        }

        if (isset($user['password'])) {

            /*
             * For added security, create a new salt
             * each time the password is updated
             */

            // Create salt

            $user['salt'] = $this->_createSalt();

            // Hash password

            $user['password'] = $this->_hashPassword($user['password'], $user['salt']);

        }

        // Convert arrays, preserving preexisting attributes

        if (isset($updated_user['attributes']) && NULL !== $updated_user['attributes']) {

            $user['attributes'] = json_encode((array)$updated_user['attributes']);

        }

        $sql = "UPDATE rbac_users SET" . " ";

        $placeholders = [];

        foreach ($user as $k => $v) {

            if ($k == 'enabled') {
                $v = (int)$v;
            }

            $sql .= $k . '=?, ';

            $placeholders[] = $v;

        }

        $sql = rtrim($sql, ', ') . ' WHERE id = ?';

        $placeholders[] = $id;

        $stmt = $this->pdo->prepare($sql);

        $stmt->execute($placeholders);

    }

    /**
     * Delete user.
     *
     * @param string $id
     *
     * @return bool (If user existed)
     */

    public function deleteUser(string $id): bool
    {

        $stmt = $this->pdo->prepare("DELETE FROM rbac_users WHERE id = :id");

        $stmt->execute([
            'id' => $id
        ]);

        return $stmt->rowCount() > 0;

    }

    /**
     * Get user permissions.
     *
     * @param string $user_id
     *
     * @return array
     */

    public function getUserPermissions(string $user_id): array
    {

        // Does user exist and is enabled

        try {

            $user = $this->getUser($user_id);

        } catch (InvalidUserException $e) {

            return [];

        }

        if ($user['enabled'] != 1) {

            return [];

        }

        // Get user roles

        $roles = $this->getUserRoles($user_id);

        $permissions = [];

        foreach ($roles as $role) {

            if ($role['enabled'] == 1) {

                $permissions = array_merge($permissions, $this->getRolePermissions($role['id']));

            }

        }

        return array_unique($permissions, SORT_REGULAR); // Remove duplicates

    }

    /**
     * Does user have permission(s).
     *
     * @param string $user_id
     * @param string|array $permission_id
     *
     * @return bool
     */

    public function userHasPermission(string $user_id, $permission_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getUserPermissions($user_id), 'id'), (array)$permission_id)) == count((array)$permission_id);
    }

    /**
     * Get all roles of user.
     *
     * @param string $user_id
     *
     * @return array
     */

    public function getUserRoles(string $user_id): array
    {

        $stmt = $this->pdo->prepare("SELECT rr.* FROM rbac_roles AS rr 
            LEFT JOIN rbac_role_users AS rru ON rr.id = rru.roleId 
            WHERE rru.userId = :user_id
            ORDER BY rr.name");

        $stmt->execute([
            'user_id' => $user_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /**
     * Does user have role(s).
     *
     * @param string $user_id
     * @param string|array $role_id
     *
     * @return bool
     */

    public function userHasRole(string $user_id, $role_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getUserRoles($user_id), 'id'), (array)$role_id)) == count((array)$role_id);
    }

    /**
     * Get all groups of user.
     *
     * @param string $user_id
     *
     * @return array
     */

    public function getUserGroups(string $user_id): array
    {

        $stmt = $this->pdo->prepare("SELECT rg.* FROM rbac_groups AS rg 
            LEFT JOIN rbac_group_users AS rgu ON rg.id = rgu.groupId 
            WHERE rgu.userId = :user_id
            ORDER BY rg.name");

        $stmt->execute([
            'user_id' => $user_id
        ]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);

    }

    /**
     * Is user in group(s).
     *
     * @param string $user_id
     * @param string|array $group_id
     *
     * @return bool
     */

    public function userInGroup(string $user_id, $group_id): bool
    {
        return count(array_intersect(Arr::pluck($this->getUserGroups($user_id), 'id'), (array)$group_id)) == count((array)$group_id);
    }

    /**
     * Enable user.
     *
     * @param string $user_id
     *
     * @return void
     */

    public function enableUser(string $user_id): void
    {

        $stmt = $this->pdo->prepare("UPDATE rbac_users SET enabled = 1
            WHERE id = :id");

        $stmt->execute([
            'id' => $user_id
        ]);

    }

    /**
     * Disable user.
     *
     * @param string $user_id
     *
     * @return void
     */

    public function disableUser(string $user_id): void
    {

        $stmt = $this->pdo->prepare("UPDATE rbac_users SET enabled = 0
            WHERE id = :id");

        $stmt->execute([
            'id' => $user_id
        ]);

    }

    /**
     * Authenticate user using login and password.
     *
     * @param string $login
     * @param string $password
     *
     * @return array (Array from getUser method)
     *
     * @throws AuthenticationException
     */

    public function authenticate(string $login, string $password): array
    {

        $stmt = $this->pdo->prepare("SELECT * FROM rbac_users WHERE login = :login");

        $stmt->execute([
            'login' => $login
        ]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {

            throw new AuthenticationException('Unable to login: user login (' . $login . ') does not exist');

        }

        if ($this->_verifyPassword($password, $user['salt'], $user['password'])) {

            if (NULL !== $user['attributes']) {

                $user['attributes'] = json_decode($user['attributes'], true);

            }

            return Arr::except($user, [ // Omit sensitive columns not included with getUser()
                'password',
                'salt'
            ]);

        }

        throw new AuthenticationException('Unable to login: invalid password for login (' . $login . ')');

    }

    /*
     * ############################################################
     * User meta
     * ############################################################
     */

    /**
     * Set user meta.
     *
     * This method will overwrite any preexisting meta value with the same key.
     *
     * @param string $user_id
     * @param array $meta (Key/value pair of user meta to set)
     *
     * @return void
     *
     * @throws InvalidUserException
     */

    public function setUserMeta(string $user_id, array $meta): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_user_meta 
                SET userId = ?, metaKey = ?, metaValue = ? 
                ON DUPLICATE KEY UPDATE userId = VALUES(userId), metaKey = VALUES(metaKey), metaValue = VALUES(metaValue)");

            foreach ($meta as $k => $v) {

                $stmt->execute([
                    $user_id,
                    $k,
                    $v
                ]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidUserException('Unable to set user meta: user ID (' . $user_id . ') does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Get user meta.
     *
     * @param string $user_id
     * @param string|null $meta_key (Optionally return the value of a single meta key)
     *
     * @return mixed
     *
     * @throws InvalidMetaException
     */

    public function getUserMeta(string $user_id, string $meta_key = NULL)
    {

        if (NULL === $meta_key) { // Return all meta

            $stmt = $this->pdo->prepare("SELECT metaKey, metaValue
                FROM rbac_user_meta
                WHERE userId = :user_id
                ORDER BY metaKey");

            $stmt->execute([
                'user_id' => $user_id
            ]);

            return $stmt->fetchAll(PDO::FETCH_ASSOC);

        }

        $stmt = $this->pdo->prepare("SELECT metaValue 
            FROM rbac_user_meta 
            WHERE userId = :user_id AND metaKey = :meta_key");

        $stmt->execute([
            'user_id' => $user_id,
            'meta_key' => $meta_key
        ]);

        $meta = $stmt->fetchColumn();

        if (!$meta) {

            throw new InvalidMetaException('Unable to get user meta: meta key (' . $meta_key . ') does not exist for user ID (' . $user_id . ')');

        }

        return $meta;

    }

    /**
     * Delete user meta.
     *
     * @param string $user_id
     * @param array|null $meta (Array of meta keys to delete. If NULL, all meta will be deleted for this user.)
     *
     * @return bool (If meta key existed)
     *
     * @throws Exception
     */

    public function deleteUserMeta(string $user_id, array $meta = NULL): bool
    {

        if (NULL === $meta) {

            $stmt = $this->pdo->prepare("DELETE FROM rbac_user_meta
            WHERE userId = :user_id");

            $stmt->execute([
                'user_id' => $user_id
            ]);

            return $stmt->rowCount() > 0;

        } else {

            $count = 0;

            try {

                $this->pdo->beginTransaction();

                $stmt = $this->pdo->prepare("DELETE FROM rbac_user_meta 
                    WHERE userId = ? && metaKey = ?");

                foreach ($meta as $v) {

                    $stmt->execute([
                        $user_id,
                        $v
                    ]);

                    $count += $stmt->rowCount();

                }

                $this->pdo->commit();

                return $count > 0;

            } catch (Exception $e) {

                $this->pdo->rollBack();

                throw $e;

            }

        }

    }

    /**
     * Does user have meta key.
     *
     * @param string $user_id
     * @param string $meta_key
     *
     * @return bool
     */

    public function userHasMeta(string $user_id, string $meta_key): bool
    {

        try {
            $this->getUserMeta($user_id, $meta_key);
        } catch (InvalidMetaException $e) {
            return false;
        }

        return true;

    }

    /*
     * ############################################################
     * Grants
     * ############################################################
     */

    // -------------------- Groups --------------------

    /**
     * Grant group to users.
     *
     * @param string $group_id
     * @param string|array $users (User ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantGroupUsers(string $group_id, $users): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_group_users 
            SET groupId = ?, userId = ?
            ON DUPLICATE KEY UPDATE groupId = VALUES(groupId), userId = VALUES(userId)");

            foreach ((array)$users as $user) {

                $stmt->execute([$group_id, $user]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant group users: user and/or group ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke users from group.
     *
     * If $users is NULL, all users will be revoked from the group.
     *
     * @param string $group_id
     * @param string|array|null $users (User ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokeGroupUsers(string $group_id, $users = NULL): void
    {

        if (NULL === $users) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_group_users
                WHERE groupId = :group_id");

            $stmt->execute([
                'group_id' => $group_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_group_users
                WHERE groupId = ? AND userId = ?");

            foreach ((array)$users as $user) {

                $stmt->execute([$group_id, $user]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Grant groups to user.
     *
     * @param string $user_id
     * @param string|array $groups (Group ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantUserGroups(string $user_id, $groups): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_group_users 
            SET groupId = ?, userId = ?
            ON DUPLICATE KEY UPDATE groupId = VALUES(groupId), userId = VALUES(userId)");

            foreach ((array)$groups as $group) {

                $stmt->execute([$group, $user_id]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant user groups: user and/or group ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke groups from user.
     *
     * If $groups is NULL, all groups will be revoked from the user.
     *
     * @param string $user_id
     * @param string|array|null $groups (Group ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokeUserGroups(string $user_id, $groups = NULL): void
    {

        if (NULL === $groups) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_group_users
                WHERE userId = :user_id");

            $stmt->execute([
                'user_id' => $user_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_group_users
                WHERE groupId = ? AND userId = ?");

            foreach ((array)$groups as $group) {

                $stmt->execute([$group, $user_id]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    // -------------------- Permissions --------------------

    /**
     * Grant permissions to role.
     *
     * @param string $role_id
     * @param string|array $permissions (Permission ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantRolePermissions(string $role_id, $permissions): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_role_permissions 
            SET roleId = ?, permissionId = ?
            ON DUPLICATE KEY UPDATE roleId = VALUES(roleId), permissionId = VALUES(permissionId)");

            foreach ((array)$permissions as $permission) {

                $stmt->execute([$role_id, $permission]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant role permissions: role and/or permission ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke permissions from role.
     *
     * If $permissions is NULL, all permissions will be revoked from the role.
     *
     * @param string $role_id
     * @param string|array|null $permissions (Permission ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokeRolePermissions(string $role_id, $permissions = NULL): void
    {

        if (NULL === $permissions) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_permissions
                WHERE roleId = :role_id");

            $stmt->execute([
                'role_id' => $role_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_permissions WHERE roleId = ? AND permissionId = ?");

            foreach ((array)$permissions as $permission) {

                $stmt->execute([$role_id, $permission]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Grant permission to roles.
     *
     * @param string $permission_id
     * @param string|array $roles (Role ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantPermissionRoles(string $permission_id, $roles): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_role_permissions 
            SET roleId = ?, permissionId = ?
            ON DUPLICATE KEY UPDATE roleId = VALUES(roleId), permissionId = VALUES(permissionId)");

            foreach ((array)$roles as $role) {

                $stmt->execute([$role, $permission_id]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant permission roles: role and/or permission ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke permission from roles.
     *
     * If $roles is NULL, all roles will be revoked from the permission.
     *
     * @param string $permission_id
     * @param string|array|null $roles (Role ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokePermissionRoles(string $permission_id, $roles = NULL): void
    {

        if (NULL === $roles) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_permissions
                WHERE permissionId = :permission_id");

            $stmt->execute([
                'permission_id' => $permission_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_permissions WHERE roleId = ? AND permissionId = ?");

            foreach ((array)$roles as $role) {

                $stmt->execute([$role, $permission_id]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    // -------------------- Roles --------------------

    /**
     * Grant users to role.
     *
     * @param string $role_id
     * @param string|array $users (User ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantRoleUsers(string $role_id, $users): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_role_users 
            SET roleId = ?, userId = ?
            ON DUPLICATE KEY UPDATE roleId = VALUES(roleId), userId = VALUES(userId)");

            foreach ((array)$users as $user) {

                $stmt->execute([$role_id, $user]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant role users: role and/or user ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke users from role.
     *
     * If $users is NULL, all users will be revoked from the role.
     *
     * @param string $role_id
     * @param string|array|null $users (User ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokeRoleUsers(string $role_id, $users = NULL): void
    {

        if (NULL === $users) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_users
                WHERE roleId = :role_id");

            $stmt->execute([
                'role_id' => $role_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_users WHERE roleId = ? AND userId = ?");

            foreach ((array)$users as $user) {

                $stmt->execute([$role_id, $user]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Grant roles to user.
     *
     * @param string $user_id
     * @param string|array $roles (Role ID(s))
     *
     * @return void
     *
     * @throws InvalidGrantException
     */

    public function grantUserRoles(string $user_id, $roles): void
    {

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("INSERT INTO rbac_role_users 
            SET roleId = ?, userId = ?
            ON DUPLICATE KEY UPDATE roleId = VALUES(roleId), userId = VALUES(userId)");

            foreach ((array)$roles as $role) {

                $stmt->execute([$role, $user_id]);

            }

            $this->pdo->commit();

        } catch (PDOException $e) {

            $this->pdo->rollBack();

            throw new InvalidGrantException('Unable to grant user roles: role and/or user ID does not exist');

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

    /**
     * Revoke roles from user.
     *
     * If $roles is NULL, all roles will be revoked from the user.
     *
     * @param string $user_id
     * @param string|array|null $roles (Role ID(s))
     *
     * @return void
     *
     * @throws Exception
     */

    public function revokeUserRoles(string $user_id, $roles = NULL): void
    {

        if (NULL === $roles) { // Revoke all

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_users
                WHERE userId = :user_id");

            $stmt->execute([
                'user_id' => $user_id
            ]);

            return;

        }

        try {

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("DELETE FROM rbac_role_users WHERE roleId = ? AND userId = ?");

            foreach ((array)$roles as $role) {

                $stmt->execute([$role, $user_id]);

            }

            $this->pdo->commit();

        } catch (Exception $e) {

            $this->pdo->rollBack();

            throw $e;

        }

    }

}