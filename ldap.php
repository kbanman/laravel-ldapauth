<?php namespace LDAPauth; use \Config, \Exception, \DB;
/**
 * LDAP Auth Driver for Laravel
 *
 * @author Kelly Banman (kelly.banman@gmail.com)
 *			Credit to idbobby at rambler dot ru for the search code
 *			(post on http://www.php.net/manual/en/ref.ldap.php)
 */
class LDAPauth extends \Laravel\Auth\Drivers\Driver {

	protected $conn;

	protected $ldap_type;

	public function __construct()
	{
		// Check if the ldap extension is installed
		if ( ! function_exists('ldap_connect'))
		{
			throw new \Exception('LDAPauth requires the php-ldap extension to be installed.');
		}

		// load ldap_type at start
		$this->ldap_type = Config::get('auth.ldap.ldap_type');

		parent::__construct();
	}

	public function __destruct()
	{
		if ( ! is_null($this->conn))
		{
			ldap_unbind($this->conn);
		}
	}

	/**
	 * Get the current user of the application.
	 *
	 * @param  int         $id
	 * @return mixed|null
	 */
	public function retrieve($token)
	{
		if (empty($token))
		{
			return;
		}
		
		if (is_null($this->conn))
		{
			// Create a connection using a control account
			try
			{
				$this->ldap_connect(Config::get('auth.ldap.control_user'), Config::get('auth.ldap.control_password'));
			}
			catch (Exception $e)
			{
				throw new Exception('LDAP Control account error: '.ldap_error($this->conn));
				return;
			}
		}

		try
		{
			if ($user = $this->get_user_by_dn($token))
			{
				return $user;
			}
			echo 'No user found for '.$token;
		}
		catch (Exception $e)
		{
			die($e->getMessage());
		}
	}

	/**
	 * Attempt to log a user into the application.
	 *
	 * @param  array  $arguments
	 * @return void
	 */
	public function attempt($arguments = array())
	{
		// This driver uses a basic username and password authentication scheme
		// so if the credentials match what is in the database we will just
		// log the user into the application and remember them if asked.
		$username = $arguments['username'];
		$password = $arguments['password'];

		$group = Config::get('auth.ldap.group');

		try
		{
			$user = $this->ldap_login($username, $password, $group);
			return $this->login($user->dn, array_get($arguments, 'remember'));
		}
		catch (Exception $e)
		{
			throw $e;
			return false;
		}

		return false;
	}

	protected function ldap_connect($user, $password)
	{
		$config = Config::get('auth.ldap');

		// Guess Base DN from domain
		if ( ! isset($config['base_dn']))
		{
			$i = strrpos($config['domain'], '.');
			$config['base_dn'] = sprintf('dc=%s,dc=%s',
				substr($config['domain'], 0, $i),
				substr($config['domain'], $i+1));
			Config::set('auth.ldap.base_dn', $config['base_dn']);
		}

		// Connect to the controller
		if ( ! $this->conn = ldap_connect("ldap://{$config['host']}.{$config['domain']}"))
		{
			throw new Exception("Could not connect to LDAP host {$config['host']}.{$config['domain']}: ".ldap_error($this->conn));
		}

		// No idea what this does, but they're required for Windows AD
		ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);

		if ( $this->ldap_type == 'openldap' ) {

			$user_dn = '';

			if ( ! isset($config['user_dn']))
			{
				$user_dn = $config['base_dn'];
			} else {
				$user_dn = $config['user_dn'];
			}
			
			$user_search = $config['user_search'];

			$rdn = "{$user_search}={$user},{$user_dn}";
			// Try to authenticate
			if ( ! @ldap_bind($this->conn, $rdn, $password))
			{
				throw new Exception('Could not bind to '."{$this->ldap_type}: {$rdn}: {$config['host']}.{$config['domain']}".ldap_error($this->conn));
			}
		} 

		if ( $this->ldap_type == 'ad' ) {
			// Try to authenticate
			if ( ! @ldap_bind($this->conn, "{$user}@{$config['domain']}", $password))
			{
				throw new Exception('Could not bind to AD: '."{$user}@{$config['domain']}: ".ldap_error($this->conn));
			}
		}

		return true;
	}

	protected function ldap_login($user, $password, $group = null)
	{
		if ( ! $this->ldap_connect($user, $password))
		{
			throw new Exception('Could not connect to LDAP: '.ldap_error($this->conn));
		}

		$group_obj = $this->get_account($group, Config::get('auth.ldap.base_dn'));
		$user_obj = $this->get_account($user, Config::get('auth.ldap.base_dn'));

		if ($group && ! $this->check_group($user_obj['dn'], $group_obj['dn']))
		{
			throw new Exception('User is not part of the '.$group.' group.');
		}

		return $this->clean_user($user_obj);		
	}

	protected function clean_user($user)
	{
		if ( ! isset($user['cn'][0]))
		{
			throw new Exception('Not a valid user object');
		}

		if ( $this->ldap_type == "openldap" )
		{
			return (object) array(
				'dn' => $user['dn'],
				'name' => $user['cn'][0],
				// 'username' => strtolower($user),
				'firstname' => $user['givenname'][0],
				'lastname' => $user['sn'][0],
				'uid' => $user['uid'][0],
				'member' => isset($user['member']) ? $user['member'] : array('count' => 0),
			);
		}

		if ( $this->ldap_type == "ad" )
		{
			return (object) array(
				'dn' => $user['dn'],
				'name' => $user['cn'][0],
				// 'username' => strtolower($user),
				'firstname' => $user['givenname'][0],
				'lastname' => $user['sn'][0],
				'objectguid' => $user['objectguid'][0],
				'memberof' => isset($user['memberof']) ? $user['memberof'] : array('count' => 0),
			);
		}
	}

	/**
	 * Searches the LDAP tree for the specified account or group
	 */
	protected function get_account($account, $basedn)
	{
		if (is_null($this->conn))
		{
			throw new Exception('No LDAP connection bound');
		}

		$attr = array();

		if ( $this->ldap_type == "openldap" )
		{
			$attr = array('dn', 'givenname', 'sn', 'cn', 'member', 'uid');
		}

		if ( $this->ldap_type == "ad" )
		{
			$attr = array('dn', 'givenname', 'sn', 'cn', 'memberof', 'objectguid');
		}

		$user_search = Config::get('auth.ldap.user_search');
		$result = ldap_search($this->conn, $basedn, "({$user_search}={$account})", $attr);
		if ($result === false)
		{
			return null;
		}

		$entries = ldap_get_entries($this->conn, $result);
		if ($entries['count'] > 0)
		{
			return $entries[0];
		}
	}

	/**
	 * Checks group membership of the user, searching
	 * in the specified group and its children (recursively)
	 */
	public function check_group($userdn, $groupdn)
	{
		if ( ! $user = $this->get_user_by_dn($userdn))
		{
			throw new Exception('Invalid userDN');
		}

		for ($i = 0; $i < $user->memberof['count']; $i++)
		{
			if ($groupdn == $user->memberof[$i])
			{
				return true;
			}
		}

		die('group validation');

		return false;
	}

	public function get_user_by_dn($userdn)
	{
		if (is_null($this->conn))
		{
			throw new Exception('No LDAP connection bound');
		}

		$result = ldap_read($this->conn, $userdn, '(objectclass=*)');

		if ($result === false)
		{
			return null;
		}

		$entries = ldap_get_entries($this->conn, $result);
		if ( ! $entries['count'])
		{
			return null;
		}

		return $this->clean_user($entries[0]);
	}

	public function search($basedn, $filter, $attributes = array()) {
		
		if (is_null($this->conn))
		{
			throw new Exception('No LDAP connection bound');
		}

		if (is_null($basedn) or $basedn = '') {
			$basedn = Config::get('auth.ldap.user_dn');
		}

		$result = ldap_search($this->conn, $basedn, $filter, $attributes);

		if ($result === false)
		{
			return null;
		}

		$entries = ldap_get_entries($this->conn, $result);
		if ($entries['count'] > 0)
		{
			return $entries[0];
		}
	}
}


