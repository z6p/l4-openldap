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
		
		$this->justthese = array();
		
		foreach( $this->config['user_attributes'] as $key => $value ) {
			$this->justthese[] = $key;
		}
		
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
		$filter = $this->config['filter'];
		if(strpos( $filter, '&' ))
			$filter = substr_replace( $filter, '(' . $this->config['user_id_attribute'] . '=' . $identifier . ')', 
					strpos( $filter, '&' ) + 1, 0 );
		else
			$filter = '(&(' . $this->config['user_id_attribute'] . '=' . $identifier . ')' . $filter . ')';
		
		$result = @ldap_search( $this->conn, $this->config['basedn'], $filter, $this->justthese );
		
		if($result == false) return null;
		
		$entries = ldap_get_entries( $this->conn, $result );
		if($entries['count'] == 0 || $entries['count'] > 1) return null;
		
		$this->model = $this->createGenericUserFromLdap( $entries[0] );
		
		return $this->model;
	}

	public function retrieveByCredentials(array $credentials) {
		foreach( $credentials as $key => $value ) {
			if($key !== 'password') {
				$filter[] = '(' . $key . '=' . $value . ')';
			}
		}
		if(count( $filter ) > 1) {
			$filter = '(&' . implode( '', $filter ) . ')';
		} else {
			$filter = implode( '', $filter );
		}
		
		$filterConf = (isset( $this->config['filter'] )) ? '(&(' . $this->config['filter'] . ')' . $filter . ')' : $filter;
		
		$result = @ldap_search( $this->conn, $this->config['basedn'], $filter, $this->justthese );
		
		if($result == false) return null;
		
		$entries = ldap_get_entries( $this->conn, $result );
		if($entries['count'] == 0 || $entries['count'] > 1) return null;
		
		$this->model = $this->createGenericUserFromLdap( $entries[0] );
		
		return $this->model;
	}

	public function validateCredentials(UserInterface $user, array $credentials) {
		if($user == null) return false;
		if(isset( $credentials['password'] ) == '') return false;
		
		$dn = $user->dn;
		
		if(!$result = @ldap_bind( $this->conn, $dn, $credentials['password'] )) return false;
		
		return true;
	}

	protected function createGenericUserFromLdap($entry) {
		if(is_array( $entry[$this->config['user_id_attribute']] ))
			$parameters = array(
					'id' => $entry[$this->config['user_id_attribute']][0]
			);
		else
			$parameters = array(
					'id' => $entry[$this->config['user_id_attribute']]
			);
		
		foreach( $this->config['user_attributes'] as $key => $value ) {
			if(is_array( $entry[$key] )) {
				if($entry[$key]['count'] <= 1) {
					$parameters[$value] = $entry[$key][0];
				} else {
					$parameters[$value] = array();
					for($i = 0; $i < $entry[$key]['count']; $i++) {
						$parameters[$value][] = $entry[$key][$i];
					}
				}
			} else
				$parameters[$value] = $entry[$key];
		}
		
		$parameters['dn'] = $entry['dn'];
		
		return new GenericUser( $parameters );
	}
}
