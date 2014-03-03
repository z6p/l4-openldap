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
		$filter = OpenLdapFilter::parse( $this->config['filter'] );
		if(count( $filter ) > 0) {
			$firstFilter = array_keys( $filter );
			$filter = array(
					'&' => array(
							$firstFilter[0] => $filter[$firstFilter[0]],
							$this->config['user_id_attribute'] => $identifier
					)
			);
		} else {
			$filter = array(
					$this->config['user_id_attribute'] => $identifier
			);
		}
		$filter = OpenLdapFilter::toString( $filter );
		
		$result = @ldap_search( $this->conn, $this->config['basedn'], $filter, $this->justthese );
		
		if($result == false) return null;
		
		$entries = ldap_get_entries( $this->conn, $result );
		if($entries['count'] == 0 || $entries['count'] > 1) return null;
		
		$this->model = $this->createGenericUserFromLdap( $entries[0] );
		
		return $this->model;
	}

	public function retrieveByCredentials(array $credentials) {
		$filter = OpenLdapFilter::parse( $this->config['filter'] );
		$firstFilter = array_keys( $filter );
		foreach( $credentials as $key => $value ) {
			if($key !== 'password') {
				if(count( $filter ) > 0) {
					$firstFilter = array_keys( $filter );
					$filter = array(
							'&' => array(
									$firstFilter[0] => $filter[$firstFilter[0]],
									$this->config['user_id_attribute'] => $identifier
							)
					);
				} else {
					$filter = array(
							$this->config['user_id_attribute'] => $identifier
					);
				}
			}
		}
		$filter = OpenLdapFilter::toString( $filter );
		
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
		
		return new OpenLdapUser( $parameters );
	}
}
