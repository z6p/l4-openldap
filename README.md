# laravel4-openldap

An OpenLDAP authentication driver for Laravel 4.

## Installation

Add the following to your `composer.json` file.

```
require {
	"z6p/laravel4-openldap": "dev-master"
}


"repositories": [
	{
    		"type": "vcs",
   		 "url": "https://github.com/z6p/laravel4-openldap.git"
	}
]
```

Run `composer update`.

Open `app/config/app.php` and add:

`Z6p\OpenLdap\OpenLdapServiceProvider`

Open `app/config/auth.php` and change the authentication driver to `ldap`.

## Configuration

Add this to `app/config/auth.php`.

```php
/**
 * LDAP Configuration for z6p/laravel4-openldap
 */
'ldap' => array(
	'host' => 'ldap.example.com',
	'rdn' => 'ou=System,dc=example,dc=com', // rdn used by the user configured below, optional
	'username' => 'username', // optional
	'password' => 'thisisasecret', // optional
	'version'  => '3',	// LDAP protocol version (2 or 3)
	'use_tls' => true,

	'filter' => '(&(objectclass=posixAccount)(|(status=member)))', // optional

	'login_attribute' => 'uid', // login attributes for users
	'basedn' => 'ou=people,dc=example,dc=com', // basedn for users
	'user_id_attribute' => 'uidNumber', // the attribute name containg the uid number
	'user_attributes' => array( // the ldap attributes you want to store in session (ldap_attr => array_field_name)
		'uid' => 'username', // example: this stores the ldap uid attribute as username in GenericUser
	)
),
```
