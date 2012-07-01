<?php
/**
 * LDAP Auth bundle starter
 *
 * @package    LDAPauth
 * @version    1.0
 * @author     Cartalyst LLC
 * @license    MIT License
 * @copyright  (c) 2011 - 2012, Cartalyst LLC
 * @link       http://cartalyst.com
 */

Autoloader::map(array(
	'LDAPauth\\LDAPauth' => __DIR__.DS.'ldap.php',
));

// Set the global alias for Sentry
//Autoloader::alias('Sentry\\Sentry', 'Sentry');

// Add Sentry as an auth driver
Auth::extend('ldapauth', function()
{
	return new LDAPauth\LDAPauth;
});
