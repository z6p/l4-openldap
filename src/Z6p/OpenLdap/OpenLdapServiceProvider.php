<?php

namespace Z6p\OpenLdap;

use Illuminate\Support\ServiceProvider;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Sébastien Boucontet
 *         Original code from Yuri Moens (yuri.moens@gmail.com)
 *        
 */
class OpenLdapServiceProvider extends ServiceProvider {

	public function boot() {
		$this->package( 'z6p/laravel4-openldap' );
		
		$this->app['auth']->extend( 'ldap', 
				function ($app) {
					return new OpenLdapGuard( 
							new OpenLdapUserProvider( $app['config']->get( 'auth.ldap' ) ), $app->make( 'session.store' ) );
				} );
	}

	public function register() {
	}

	public function provides() {
		return array(
				'ldap'
		);
	}
}