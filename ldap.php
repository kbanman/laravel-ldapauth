<?php namespace LDAPauth;
/**
 * LDAP Auth Driver for Laravel
 *
 * @author Kelly Banman (kelly.banman@gmail.com)
 *			Credit to idbobby at rambler dot ru for the search code
 *			(post on http://www.php.net/manual/en/ref.ldap.php)
 */
class LDAPauth extends \Laravel\Auth\Drivers\Driver {

	public function __construct()
	{
		// Check if the ldap extension is installed
		if ( ! function_exists('ldap_connect'))
		{
			throw new Exception('LDAPauth requires the php-ldap extension to be installed.');
		}

		parent::__construct();
	}

	/**
	 * Get the current user of the application.
	 *
	 * @param  int         $id
	 * @return mixed|null
	 */
	public function retrieve($id)
	{
		return $id;
	}

	/**
	 * Attempt to log a user into the application.
	 *
	 * @param  array  $arguments
	 * @return void
	 */
	public function attempt($arguments = array())
	{
		$user = $this->get_user($arguments['username']);

		// This driver uses a basic username and password authentication scheme
		// so if the credentials match what is in the database we will just
		// log the user into the application and remember them if asked.
		$password = $arguments['password'];

		$group = Config::get('auth.ldap.group', 'Users');

		try
		{
			$userdn = $this->ldap_login($user, $password, $group);
			return ! empty($userdn);
		}
		catch (\Exception $e)
		{
			throw $e;
		}

		return false;
	}

	/**
	 * Get the user from the database table by username.
	 *
	 * @param  mixed  $value
	 * @return mixed
	 */
	protected function get_user($value)
	{
		$table = Config::get('auth.table');

		$username = Config::get('auth.username');

		return DB::table($table)->where($username, '=', $value)->first();
	}

	protected function ldap_login($user, $password, $group)
	{
		$config = Config::get('auth.ldap');

		// Guess Base DN from domain
		if ( ! isset($config['basedn']))
		{
			$i = strrpos($config['domain'], '.');
			$config['basedn'] = sprintf('dc=%s,dc=%s',
				substr($config['domain'], 0, $i),
				substr($config['domain'], $i+1));
		}

		// Connect to the controller
		if ( ! $ad = ldap_connect("ldap://{$config['host']}.{$config['domain']}"))
		{
			throw new \Exception("Could not connect to LDAP host {$config['host']}.{$config['domain']}: ".ldap_error($ad));
		}

		// No idea what this does
		ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);

		// Try to authenticate
		if ( ! @ldap_bind($ad, "{$user}@{$config['domain']}", $password))
		{
			throw new \Exception('Could not bind to AD: '.ldap_error($ad));
		}

		$groupdn = $this->get_dn($ad, $group, $basedn);
		$userdn = $this->get_dn($ad, $user, $basedn);

		if ($this->check_group_recursive($ad, $userdn, $groupdn))
		{
			echo "You're authorized as ".$this->get_cn($userdn);
		}
		else
		{
			echo 'Authorization failed';
		}

		ldap_unbind($ad);

		return $userdn;
	}

	/**
	 * Searches the LDAP tree for the specified account
	 */
	protected function get_dn($ad, $account, $basedn)
	{
		$result = ldap_search($ad, $basedn, "(samaccountname={$account})", array('dn'));
		if ($result === false)
		{
			return null;
		}

		$entries = ldap_get_entries($ad, $result);
		if ($entries['count'] > 0)
		{
			return $entries[0]['dn'];
		}
	}

	/**
	 * This function retrieves and returns CN from given DN
	 */
	public function get_cn($dn)
	{
		if (preg_match('/[^,]*/', $dn, $matchse, PREG_OFFSET_CAPTURE, 3))
		{
			return $matches[0][0];
		}

		throw new \Exception('Could not parse DN');
	}

	/**
	 * Checks group membership of the user, searching only
	 * in specified group (not recursively).
	 */
	public function check_group($ad, $userdn, $groupdn)
	{
		$result = ldap_read($ad, $userdn, "(memberof={$groupdn})", array('members'));
		
		if ($result === false)
		{
			return false;
		};
		
		$entries = ldap_get_entries($ad, $result);

		return ($entries['count'] > 0);
	}

	/**
	 * Checks group membership of the user, searching
	 * in the specified group and its children (recursively)
	 */
	function check_group_recursive($ad, $userdn, $groupdn)
	{
		$result = ldap_read($ad, $userdn, '(objectclass=*)', array('memberof'));
		if ($result === false)
		{
			return false;
		}

		$entries = ldap_get_entries($ad, $result);
		if ($entries['count'] <= 0 || empty($entries[0]['memberof']))
		{
			return false;
		}

		$entries = $entries[0]['memberof'];

		for ($i = 0; $i < $entries['count']; $i++)
		{
			if ($entries[$i] == $groupdn || $this->check_group_recursive($ad, $entries[$i], $groupdn))
			{
				return true;
			}
		}

		return false;
	}
}


