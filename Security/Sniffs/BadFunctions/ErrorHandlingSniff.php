<?php


class Security_Sniffs_BadFunctions_ErrorHandlingSniff implements PHP_CodeSniffer_Sniff {

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
	* @param PHP_CodeSniffer_File $phpcsFile The file where the token was found.
	* @param int                  $stackPtr  The position in the stack where
	*                                        the token was found.
	*
	* @return void
	*/
	public function process(PHP_CodeSniffer_File $phpcsFile, $stackPtr) {
		$tokens = $phpcsFile->getTokens();
		$utils = new Security_Sniffs_Utils();

		if ($tokens[$stackPtr]['content'] == 'error_reporting') {
			$p = $utils::get_param_tokens($phpcsFile, $stackPtr, 1);
			if (count($p) == 1 && $p[0]['content'] === '0') {
				$error = 'Please do not disable error_reporting, it could be useful';
				$phpcsFile->addWarning($error, $stackPtr, 'ErrorReporting0');
			}
		}
	}

}

?>
