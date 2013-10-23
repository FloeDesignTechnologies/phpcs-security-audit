<?php

class Security_Sniffs_Symfony2_Utils extends Security_Sniffs_Utils {

	/**
	* Heavy used function to verify if a token contains user input
	*
    * @param String $t	The token to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_token_user_input($t) {
		if (parent::is_token_user_input($t)) {
			return TRUE;
		}
		if ($t['code'] == T_VARIABLE) {
			if ($t['content'] == '$request') {
				return TRUE;
			}
		} elseif ($t['code'] == T_STRING) {
			if ($t['content'] == 'get') {
				return TRUE;
			}
		}
		return FALSE;
	}

}

?>
