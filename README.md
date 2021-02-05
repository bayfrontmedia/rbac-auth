## RBAC Auth

A role-based access control (RBAC) user authentication and authorization library.

This library allows for the management of permissions, roles, users, and groups.

- [License](#license)
- [Author](#author)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)

## License

This project is open source and available under the [MIT License](LICENSE).

## Author

John Robinson, [Bayfront Media](https://www.bayfrontmedia.com)

## Requirements

* PHP >= 7.1.0
* PDO PHP extension

## Installation

```
composer require bayfrontmedia/rbac-auth
```

### Database migration

This library makes use of multiple database tables, which can be installed with a migration.
The `MigrationInterface` classes require a `PDO` instance to be passed to the constructor.

**Example:**

```
use Bayfront\RBAC\Migrations\v1\Schema;

$schema = new Schema($pdo);
$schema->up();
```

To uninstall the database tables, use:

```
use Bayfront\RBAC\Migrations\v1\Schema;

$schema = new Schema($pdo);
$schema->down();
```

### Start using RBAC Auth

A `PDO` instance is required by RBAC Auth.
In addition, an optional server-side "pepper" can be added to the constructor which will be used when hashing user passwords.

**NOTE: If at any time the pepper is lost or changed, all user passwords will be obsolete and unrecoverable.**

```
use Bayfront\RBAC\Auth;

$pdo = new PDO(
    'mysql:host=DB_HOST;dbname=DB_TO_USE',
    'DB_USER',
    'DB_USER_PASSWORD'
);

$auth = new Auth($pdo, 'OPTIONAL_PEPPER');
```

## Usage

**NOTE:** All exceptions thrown by RBAC Auth extend `Bayfront\RBAC\Exceptions\RBACException`, so you can choose to catch exceptions as narrowly or broadly as you like.

### Overview

* Permissions and roles are defined on a global level.
* Each role is granted a collection of permissions.
* Users can belong to multiple roles.
* User permissions become the union of all the permissions granted to the roles to which they are assigned.
* Users can belong to multiple groups. Groups are used to horizontally partition users.

### Enabled/disabled

Users will not inherit any permissions from a disabled role.
If the user is disabled, they will not inherit any permissions from any roles.

### Authentication

Users will always be able to authenticate with a correct username + password. 
If the user is disabled, they will simply have no permissions.

### Public methods

**Groups**

- [groupIdExists](#groupidexists)
- [groupNameExists](#groupnameexists)
- [getGroups](#getgroups)
- [getGroup](#getgroup)
- [createGroup](#creategroup)
- [updateGroup](#updategroup)
- [deleteGroup](#deletegroup)
- [getGroupUsers](#getgroupusers)
- [groupHasUser](#grouphasuser)
- [enableGroupUsers](#enablegroupusers)
- [disableGroupUsers](#disablegroupusers)

**Permissions**

- [permissionIdExists](#permissionidexists)
- [permissionNameExists](#permissionnameexists)
- [getPermissions](#getpermissions)
- [getPermission](#getpermission)
- [createPermission](#createpermission)
- [updatePermission](#updatepermission)
- [deletePermission](#deletepermission)

**Roles**

- [roleIdExists](#roleidexists)
- [roleNameExists](#rolenameexists)
- [getRoles](#getroles)
- [getRole](#getrole)
- [createRole](#createrole)
- [updateRole](#updaterole)
- [deleteRole](#deleterole)
- [getRolePermissions](#getrolepermissions)
- [roleHasPermission](#rolehaspermission)
- [getRoleUsers](#getroleusers)
- [roleHasUser](#rolehasuser)
- [enableRole](#enablerole)
- [disableRole](#disablerole)

**Users**

- [userIdExists](#useridexists)
- [userLoginExists](#userloginexists)
- [userEmailExists](#useremailexists)
- [getUsers](#getusers)
- [getUser](#getuser)
- [createUser](#createuser)
- [updateUser](#updateuser)
- [deleteUser](#deleteuser)
- [getUserPermissions](#getuserpermissions)
- [userHasPermission](#userhaspermission)
- [getUserRoles](#getuserroles)
- [userHasRole](#userhasrole)
- [getUserGroups](#getusergroups)
- [userInGroup](#useringroup)
- [enableUser](#enableuser)
- [disableUser](#disableuser)
- [authenticate](#authenticate)
- [setUserMeta](#setusermeta)
- [getUserMeta](#getusermeta)
- [deleteUserMeta](#deleteusermeta)

**Grants**

- [grantGroupUsers](#grantgroupusers)
- [revokeGroupUsers](#revokegroupusers)
- [grantUserGroups](#grantusergroups)
- [revokeUserGroups](#revokeusergroups)
- [grantRolePermissions](#grantrolepermissions)
- [revokeRolePermissions](#revokerolepermissions)
- [grantPermissionRoles](#grantpermissionroles)
- [revokePermissionRoles](#revokepermissionroles)
- [grantRoleUsers](#grantroleusers)
- [revokeRoleUsers](#revokeroleusers)
- [grantUserRoles](#grantuserroles)
- [revokeUserRoles](#revokeuserroles)

<hr />

### groupIdExists

**Description:**

Does group ID exist.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool)

<hr />

### groupNameExists

**Description:**

Does group name exist.

**Parameters:**

- `$name` (string)
- `$exclude_id = NULL` (string|null)

**Returns:**

- (bool)

<hr />

### getGroups

**Description:**

Get all groups.

**Parameters:**

- None

**Returns:**

- (array)

<hr />

### getGroup

**Description:**

Get group.

**Parameters:**

- `$id` (string)

**Returns:**

- (array)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGroupException`

<hr />

### createGroup

**Description:**

Create a group.

Valid `$group` keys include:

- `name` (string) *required
- `attributes` (array|null)

**Parameters:**

- `$group` (array)

**Returns:**

- (string): Group ID

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### updateGroup

**Description:**

Update group.

Valid `$group` keys include:

- `name` (string)
- `attributes` (array|null)

**Parameters:**

- `$id` (string)
- `$group` (array)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGroupException`
- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### deleteGroup

**Description:**

Delete group.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool): If group existed

<hr />

### getGroupUsers

**Description:**

Get all users in group.

**Parameters:**

- `$group_id` (string)

**Returns:**

- (array)

<hr />

### groupHasUser

**Description:**

Does group have user(s).

**Parameters:**

- `$group_id` (string)
- `$user_id` (string|array)

**Returns:**

- (bool)

<hr />

### enableGroupUsers

**Description:**

Enable all users in group.

**Parameters:**

- `$group_id` (string)

**Returns:**

- (void)

<hr />

### disableGroupUsers

**Description:**

Disable all users in group.

**Parameters:**

- `$group_id` (string)

**Returns:**

- (void)

<hr />

### permissionIdExists

**Description:**

Does permission ID exist.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool)

<hr />

### permissionNameExists

**Description:**

Does permission name exist.

**Parameters:**

- `$name` (string)
- `$exclude_id = NULL` (string|null)

**Returns:**

- (bool)

<hr />

### getPermissions

**Description:**

Get all permissions.

**Parameters:**

- None

**Returns:**

- (array)

<hr />

### getPermission

**Description:**

Get permission.

**Parameters:**

- `$id` (string)

**Returns:**

- (array)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidPermissionException`

<hr />

### createPermission

**Description:**

Create permission.

Valid `$permission` keys include:

- `name` (string) *required
- `description` (string)

**Parameters:**

- `$permission` (array)

**Returns:**

- (string): Permission ID

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### updatePermission

**Description:**

Update permission.

Valid `$permission` keys include:

- `name` (string)
- `description` (string)

**Parameters:**

- `$id` (string)
- `$permission` (array)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\InvalidPermissionException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### deletePermission

**Description:**

Delete permission.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool): If permission existed

<hr />

### roleIdExists

**Description:**

Does role ID exist.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool)

<hr />

### roleNameExists

**Description:**

Does role name exist.

**Parameters:**

- `$name` (string)
- `$exclude_id = NULL` (string|null)

**Returns:**

- (bool)

<hr />

### getRoles

**Description:**

Get all roles.

**Parameters:**

- None

**Returns:**

- (array)

<hr />

### getRole

**Description:**

Get role.

**Parameters:**

- `$id` (string)

**Returns:**

- (array)

**Throws:**

`Bayfront\RBAC\Exceptions\InvalidRoleException`

<hr />

### createRole

**Description:**

Create role.

Valid `$role` keys include:

- `name` (string) *required
- `attributes` (array|null)
- `enabled` (bool)

**Parameters:**

- `$role` (array)

**Returns:**

- (string): Role ID

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### updateRole

**Description:**

Update role.

Valid `$role` keys include:

- `name` (string)
- `attributes` (array|null)
- `enabled` (bool)

**Parameters:**

- `$id` (string)
- `$role` (array)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\InvalidRoleException`
- `Bayfront\RBAC\Exceptions\NameExistsException`

<hr />

### deleteRole

**Description:**

Delete role.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool): If role existed

<hr />

### getRolePermissions

**Description:**

Get all permissions of role.

**Parameters:**

- `$role_id` (string)

**Returns:**

- (array)

<hr />

### roleHasPermission

**Description:**

Does role have permission(s).

**Parameters:**

- `$role_id` (string)
- `$permission_id` (string|array)

**Returns:**

- (bool)

<hr />

### getRoleUsers

**Description:**

Get all users with role.

**Parameters:**

- `$role_id` (string)

**Returns:**

- (array)

<hr />

### roleHasUser

**Description:**

Does role have user(s).

**Parameters:**

- `$role_id` (string)
- `$user_id` (string|array)

**Returns:**

- (bool)

<hr />

### enableRole

**Description:**

Enable role.

**Parameters:**

- `$role_id` (string)

**Returns:**

- (void)

<hr />

### disableRole

**Description:**

Disable role.

**Parameters:**

- `$role_id` (string)

**Returns:**

- (void)

<hr />

### userIdExists

**Description:**

Does user ID exist.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool)

<hr />

### userLoginExists

**Description:**

Does user login exist.

**Parameters:**

- `$login` (string)
- `$exclude_id = NULL` (string|null)

**Returns:**

- (bool)

<hr />

### userEmailExists

**Description:**

Does user email exist.

**NOTE:** There are no restrictions that prevent duplicate email addresses from being used.
It is up to each application to utilize this method to enforce unique emails, if desired.

**Parameters:**

- `$email` (string)
- `$exclude_id = NULL` (string|null)

**Returns:**

- (bool)

<hr />

### getUsers

**Description:**

Get all users.

**Parameters:**

- None

**Returns:**

- (array)

<hr />

### getUser

**Description:**

Get user.

**Parameters:**

- `$id` (string)

**Returns:**

- (array)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidUserException`

<hr />

### createUser

**Description:**

Create user.

Valid `$user` keys include:

- `login` (string) *required
- `password` (string) *required
- `email` (string)
- `attributes` (array|null)
- `enabled` (bool)

**Parameters:**

- `$user` (array)

**Returns:**

- (string): User ID

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\LoginExistsException`
- `Exception`

<hr />

### updateUser

**Description:**

Update user.

Valid `$user` keys include:

- `login` (string)
- `password` (string)
- `email` (string)
- `attributes` (array|null)
- `enabled` (bool)

**Parameters:**

- `$id` (string)
- `$user` (array)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidKeysException`
- `Bayfront\RBAC\Exceptions\InvalidUserException`
- `Bayfront\RBAC\Exceptions\LoginExistsException`
- `Exception`

<hr />

### deleteUser

**Description:**

Delete user.

**Parameters:**

- `$id` (string)

**Returns:**

- (bool): If user existed

<hr />

### getUserPermissions

**Description:**

Get user permissions.

**Parameters:**

- `$user_id` (string)

**Returns:**

- (array)

<hr />

### userHasPermission

**Description:**

Does user have permission(s).

**Parameters:**

- `$user_id` (string)
- `$permission_id` (string|array)

**Returns:**

- (bool)

<hr />

### getUserRoles

**Description:**

Get all roles of user.

**Parameters:**

- `$user_id` (string)

**Returns:**

- (array)

<hr />

### userHasRole

**Description:**

Does user have role(s).

**Parameters:**

- `$user_id` (string)
- `$role_id` (string|array)

**Returns:**

- (bool)

<hr />

### getUserGroups

**Description:**

Get all groups of user.

**Parameters:**

- `$user_id` (string)

**Returns:**

- (array)

<hr />

### userInGroup

**Description:**

Is user in group(s).

**Parameters:**

- `$user_id` (string)
- `$group_id` (string|array)

**Returns:**

- (bool)

<hr />

### enableUser

**Description:**

Enable user.

**Parameters:**

- `$user_id` (string)

**Returns:**

- (void)

<hr />

### disableUser

**Description:**

Disable user.

**Parameters:**

- `$user_id` (string)

**Returns:**

- (void)

<hr />

### authenticate

**Description:**

Authenticate user using login and password.

**Parameters:**

- `$login` (string)
- `$password` (string)

**Returns:**

- (array): Array from `getUser` method

**Throws:**

- `Bayfront\RBAC\Exceptions\AuthenticationException`

<hr />

### setUserMeta

**Description:**

Set user meta.

This method will overwrite any preexisting meta value with the same key.

**Parameters:**

- `$user_id` (string)
- `$meta` (array): Key/value pair of user meta to set

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidUserException`

<hr />

### getUserMeta

**Description:**

Get user meta.

**Parameters:**

- `$user_id` (string)
- `$meta_key = NULL` (string|null): Optionally return the value of a single meta key

**Returns:**

- (mixed)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidMetaException`

<hr />

### deleteUserMeta

**Description:**

Delete user meta.

**Parameters:**

- `$user_id` (string)
- `$meta_key = NULL` (string|null): Array of meta keys to delete. If `NULL`, all meta will be deleted for this user.

**Returns:**

- (bool): If meta key existed

**Throws:**

- `Exception`

<hr />

### grantGroupUsers

**Description:**

Grant group to users.

**Parameters:**

- `$group_id` (string)
- `$users` (string|array): User ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokeGroupUsers

**Description:**

Revoke users from group.

**Parameters:**

- `$group_id` (string)
- `$users` (string|array): User ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`

<hr />

### grantUserGroups

**Description:**

Grant groups to user.

**Parameters:**

- `$user_id` (string)
- `$groups` (string|array): Group ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokeUserGroups

**Description:**

Revoke groups from user.

**Parameters:**

- `$user_id` (string)
- `$groups` (string|array): Group ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`

<hr />

### grantRolePermissions

**Description:**

Grant permissions to role.

**Parameters:**

- `$role_id` (string)
- `$permissions` (string|array): Permission ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokeRolePermissions

**Description:**

Revoke permissions from role.

**Parameters:**

- `$role_id` (string)
- `$permissions` (string|array): Permission ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`

<hr />

### grantPermissionRoles

**Description:**

Grant permission to roles.

**Parameters:**

- `$permission_id` (string)
- `$roles` (string|array): Role ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokePermissionRoles

**Description:**

Revoke permission from roles.

**Parameters:**

- `$permission_id` (string)
- `$roles` (string|array): Role ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`

<hr />

### grantRoleUsers

**Description:**

Grant users to role.

**Parameters:**

- `$role_id` (string)
- `$users` (string|array): User ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokeRoleUsers

**Description:**

Revoke users from role.

**Parameters:**

- `$role_id` (string)
- `$users` (string|array): User ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`

<hr />

### grantUserRoles

**Description:**

Grant roles to user.

**Parameters:**

- `$user_id` (string)
- `$roles` (string|array): Role ID(s)

**Returns:**

- (void)

**Throws:**

- `Bayfront\RBAC\Exceptions\InvalidGrantException`

<hr />

### revokeUserRoles

**Description:**

Revoke roles from user.

**Parameters:**

- `$user_id` (string)
- `$roles` (string|array): Role ID(s)

**Returns:**

- (void)

**Throws:**

- `Exception`