<?php


class Security_Sniffs_BadFunctions_FringeFunctionsSniff implements PHP_CodeSniffer_Sniff {

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

		if (preg_match("/^ftp_/", $tokens[$stackPtr]['content'])) {
            $opener = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
			$closer = $tokens[$opener]['parenthesis_closer'];
            $s = $stackPtr + 1;
			$s = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$emptyTokens, PHP_CodeSniffer_Tokens::$bracketTokens, Security_Sniffs_Utils::$staticTokens, array(T_STRING_CONCAT)), $s, $closer, true);
			$msg = 'Unusual function ' . $tokens[$stackPtr]['content'] . '() detected';
             if ($s) {
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError($msg . ' with parameter directly from user input', $stackPtr, 'ErrFringestuff');
				} else {
					$phpcsFile->addWarning($msg, $stackPtr, 'WarnFringestuff');
				}
			} else {
					$phpcsFile->addWarning($msg, $stackPtr, 'WarnFringestuff');
			}
		}

	}

}

?>
