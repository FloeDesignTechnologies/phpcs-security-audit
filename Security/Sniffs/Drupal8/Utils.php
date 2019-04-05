<?php

class Utils extends Security_Sniffs_Symfony2_Utils {

	/**
	* Heavy used function to verify if a token contains user input
	*
    * @param String $t	The token to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_token_user_input($t) {
		if ($t['code'] == T_VARIABLE || $t['code'] == T_STRING) {
			if (parent::is_token_user_input($t)) {
				return true;
			} else {
				if ($t['content'] == '$form') {
					return true;
				} elseif ($t['content'] == 'arg') {
					return true;
				}
			}
			return false;
		}
	}

}

?>
