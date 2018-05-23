<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class ErrorHandlingSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_STRING);
	}

	/**
	* Processes the tokens that this sniff is interested in.
	*
	* @param File $phpcsFile The file where the token was found.
	* @param int                  $stackPtr  The position in the stack where
	*                                        the token was found.
	*
	* @return void
	*/
	public function process(File $phpcsFile, $stackPtr) {
		$tokens = $phpcsFile->getTokens();
		$utils = new \PHPCS_SecurityAudit\Sniffs\Utils();

		if ($tokens[$stackPtr]['content'] == 'error_reporting') {
			$p = $utils::get_param_tokens($phpcsFile, $stackPtr, 1);
			if (is_array($p) && count($p) == 1 && $p[0]['content'] === '0') {
				$error = 'Please do not disable error_reporting, it could be useful';
				$phpcsFile->addWarning($error, $stackPtr, 'ErrorReporting0');
			}
		}
	}

}

?>
