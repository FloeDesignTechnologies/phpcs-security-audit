<?php

class Security_Sniffs_Symfony2_Utils extends Security_Sniffs_Utils {

	public static function is_direct_user_input($var) {
		if (parent::is_direct_user_input($var)) {
			return TRUE;
		} else {
			if ($var == '$request') {
				return TRUE;
			}
		}
		return FALSE;
	}
}

?>
