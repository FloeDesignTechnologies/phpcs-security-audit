<?php


class Security_Sniffs_BadFunctions_PhpinfosSniff implements PHP_CodeSniffer_Sniff {

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
		$utils = Security_Sniffs_UtilsFactory::getInstance();

		if ($tokens[$stackPtr]['content'] == 'phpinfo') {
			$phpcsFile->addWarning('phpinfo() function detected', $stackPtr, 'WarnPhpinfo');
		}

	}

}

?>
