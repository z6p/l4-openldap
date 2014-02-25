<?php

namespace Z6p\OpenLdap;

use Illuminate\Auth\Guard;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 * 
 * @author Sébastien Boucontet
 * Original code from Yuri Moens (yuri.moens@gmail.com)
 *
 */

 class OpenLdapGuard extends Guard
 {
 	public function admin()
 	{
 		if ($this->check() && $this->user())
 			return $this->user()->type == 0;

 		return false;
 	}
 }