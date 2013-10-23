<?php

class Security_Sniffs_Drupal8_Utils extends Security_Sniffs_Symfony2_Utils {

	// TODO: arg() is a user input?! (we will need to refactorise many other parts for that)
	public static function is_direct_user_input($var) {
		if (parent::is_direct_user_input($var)) {
			return TRUE;
		} else {

		}
		return FALSE;
	}
}

?>
