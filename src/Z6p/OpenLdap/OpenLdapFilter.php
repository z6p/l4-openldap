<?php
namespace Z6p\OpenLdap;

class OpenLdapFilter {

	public static function parse($filterPart) {
		$matches = array();
		if(preg_match( '/\(([!&|]{1})(.*\))\)/', $filterPart, $matches )) {
			// Operators
			$ret = array(
					$matches[1][0] => OpenLdapFilter::parse( $matches[2] )
			);
			if(($more = substr( $filterPart, strlen( $matches[2] ) + 3 ))) {
				$moreParsed = OpenLdapFilter::parse( $more );
				foreach( $moreParsed as $key => $value )
					$ret[$key] = $value;
			}
			return $ret;
		} else {
			// Values
			$ret = array();
			$values = explode( ')(', trim( $filterPart, '()' ) );
			foreach( $values as $value ) {
				$valuesParts = explode( '=', $value );
				$ret[$valuesParts[0]] = $valuesParts[1];
			}
			return $ret;
		}
	}

	public static function toString($filterArray) {
		$filterString = '';
		foreach( $filterArray as $key => $value ) {
			if(is_array( $value ))
				$filterString .= "($key" . OpenLdapFilter::toString( $value ) . ")";
			else
				$filterString .= "($key=$value)";
		}
		return $filterString;
	}
}
?>