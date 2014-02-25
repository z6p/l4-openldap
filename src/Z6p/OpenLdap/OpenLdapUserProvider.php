<?php

namespace Z6p\OpenLdap;

use Illuminate\Auth\UserProviderInterface;
use Illuminate\Auth\UserInterface;
use Illuminate\Auth\GenericUser;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Sébastien Boucontet
 *         Original code from Yuri Moens (yuri.moens@gmail.com)
 *        
 */
class OpenLdapUserProvider implements UserProviderInterface {
	
	/**
	 * The user model
	 */
	protected $model;

	public function __construct($config) {
		$this->config = $config;
		
		if(!extension_loaded( 'ldap' )) throw new \Exception( "PHP LDAP extension not loaded." );
		
		if(!$this->conn = ldap_connect( "ldap://{$this->config['host']}" )) {
			throw new \Exception( "Could not connect to LDAP host {$this->config['host']}: " . ldap_error( $this->conn ) );
		}
		
		ldap_set_option( $this->conn, LDAP_OPT_PROTOCOL_VERSION, $this->config['version'] );
		ldap_set_option( $this->conn, LDAP_OPT_REFERRALS, 0 );
		
		if($this->config['use_tls']) {
			if(!@ldap_start_tls( $this->conn )) {
				throw new \Exception( 'Could not use TLS: ' . ldap_error( $this->conn ) );
			}
		}
		
		if($this->config['username'] && $this->config['password'] && $this->config['rdn']) {
			if(!@ldap_bind( $this->conn, 'cn=' . $this->config['username'] . ',' . $this->config['rdn'], 
					$this->config['password'] )) {
				throw new \Exception( 'Could not bind to LDAP: ' . ldap_error( $this->conn ) );
			}
		} else {
			if(!@ldap_bind( $this->conn )) {
				throw new \Exception( 'Could not bind to LDAP: ' . ldap_error( $this->conn ) );
			}
		}
	}

	public function __destruct() {
		if(!is_null( $this->conn )) {
			ldap_unbind( $this->conn );
		}
	}

	public function retrieveByID($identifier) {
		
		file_put_contents( '/tmp/debug.txt', 'Identifier '.json_encode( $identifier ) . PHP_EOL );
		
		$filter = $this->config['filter'];
		if(strpos( $filter, '&' ))
			$filter = substr_replace( $filter, '(' . $this->config['user_id_attribute'] . '=' . $identifier . ')', 
					strpos( $filter, '&' ) + 1, 0 );
		else
			$filter = '(&(' . $this->config['user_id_attribute'] . '=' . $identifier . ')' . $filter . ')';
		
		$result = @ldap_search( $this->conn, $this->config['basedn'], $filter );
		
		if($result == false) return null;
		
		$entries = ldap_get_entries( $this->conn, $result );
		if($entries['count'] == 0 || $entries['count'] > 1) return null;
		
		if($this->config['use_db']) {
			$ldap_value = $entries[0][$this->config['ldap_field']][0];
			$user = $this->db_conn->table( $this->config['db_table'] )->where( $this->config['db_field'], '=', $ldap_value )->first();
			
			if($this->config['eloquent'])
				$this->model = $this->createModel()->newQuery()->find( $user->id );
			else
				$this->model = new GenericUser( get_object_vars( $user ) );
		} else {
			$this->model = $this->createGenericUserFromLdap( $entries[0] );
		}
		
		return $this->model;
	}

	public function retrieveByCredentials(array $credentials) {
		file_put_contents( '/tmp/debug.txt', 'Credentials: '.json_encode( $credentials ) . PHP_EOL );
		
		$result = @ldap_search( $this->conn, 
				$this->config['login_attribute'] . '=' . $credentials['username'] . ',' . $this->config['basedn'], 
				$this->config['filter'] );
		if($result == false) return null;
		
		$entries = ldap_get_entries( $this->conn, $result );
		if($entries['count'] == 0 || $entries['count'] > 1) return null;
		
		$this->model = $this->createGenericUserFromLdap( $entries[0] );
		return $this->model;
	}

	public function validateCredentials(UserInterface $user, array $credentials) {
		if($user == null) return false;
		if(isset( $credentials['password'] ) == '') return false;
		
		$dn = '';
		
		if(!$result = @ldap_bind( $this->conn, $dn, $credentials['password'] )) return false;
		
		return true;
	}

	public function createGenericUserFromLdap($entry) {
		$parameters = array(
				'id' => $entry[$this->config['user_id_attribute']][0]
		);
		
		foreach( $this->config['user_attributes'] as $key => $value ) {
			$parameters[$value] = $entry[$key][0];
		}
		
		return new GenericUser( $parameters );
	}
}
