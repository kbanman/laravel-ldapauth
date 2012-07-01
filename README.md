LDAP-Auth
================

This bundle allows you to authenticate users against an LDAP server. Only tested against Windows Directory, but I'm happy to include support for others if there is a need.

*Note: This bundle requires the PHP LDAP extension to be installed.*

## Installation
### Get the bundle

Install using Laravel's Artisan CLI tool:

	php artisan bundle:install ldapauth

Or clone into the bundles directory with git:

	git clone https://github.com/kbanman/laravel-ldapauth


### Autoload it

Register the bundle and set it to autoload by adding this line to `application/bundles.php`:

	'ldapauth' => array('auto' => true),


### Set the Auth Driver and Server

Change the `driver` parameter in `application/config/auth.php` to `ldapauth`.

And add the following to the end of that file:

	'ldap' => array(
		// Hostname of the domain controller
		'host' => 'dc',

		// The domain name
		'domain' => 'example.com',

		// Optionally require users to be in this group
		//'group' => 'AppUsers',

		// Domain credentials the app should use to validate users
		// This user doesn't need any privileges; it's just used to connect to the DC
		'control_user' => 'LaravelApp',
		'control_password' => 'thepassword',
	),


And you're all set!