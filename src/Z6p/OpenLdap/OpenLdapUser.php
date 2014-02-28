<?php

namespace Z6p\OpenLdap;

use Illuminate\Auth\GenericUser;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Sébastien Boucontet
 *         Original code from Yuri Moens (yuri.moens@gmail.com)
 *        
 */
class OpenLdapUser extends GenericUser {

	public function getAuthRoles() {
		$roles = array();
		
		if(isset( $this->attributes['roles'] )) {
			
			$ldapRoles = $this->attributes['roles'];
			
			foreach( $ldapRoles as $value ) {
				$output_array = array();
				if(preg_match( "/cn=([^,=]+),?ou=Groups/", $value, $output_array )) {
					$roles[] = $output_array[1];
				}
			}
		}
		
		return $roles;
	}
}
