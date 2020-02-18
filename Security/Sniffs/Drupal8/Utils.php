<?php
namespace PHPCS_SecurityAudit\Security\Sniffs\Drupal8;

class Utils extends PHPCS_SecurityAudit\Security\Sniffs\Symfony2\Utils {

	/**
	* Heavy used function to verify if a token contains user input
	*
    * @param String $t	The token to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_token_user_input($t) {
		if ($t['code'] == T_VARIABLE || $t['code'] == T_STRING) {
			if (parent::is_token_user_input($t)) {
				return TRUE;
			} else {
				if ($t['content'] == '$form') {
					return TRUE;
				} elseif ($t['content'] == 'arg') {
					return TRUE;
				}
			}
			return FALSE;
		}
	}

}

?>
