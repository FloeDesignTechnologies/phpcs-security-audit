<?php


class Security_Sniffs_BadFunctions_EasyXSSSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_ECHO, T_EXIT, T_PRINT, T_OPEN_TAG_WITH_ECHO);
	}

	/**
	* Force the paranoia on or off for this particular rule ignoring global setting ParanoiaMode.
	*
	* @var bool
	*/
	public $forceParanoia = -1;

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
		$utils = Security_Sniffs_UtilsFactory::getInstance();
		if ($this->forceParanoia >= 0) {
			$parano =  $this->forceParanoia ? 1 : 0;
		} else {
			$parano = PHP_CodeSniffer::getConfigData('ParanoiaMode') ? 1 : 0;
		}
		$tokens = $phpcsFile->getTokens();
		$s = $phpcsFile->findNext(PHP_CodeSniffer_Tokens::$emptyTokens, $stackPtr, null, true, null, true);

		if ($tokens[$stackPtr]['code'] == T_OPEN_TAG_WITH_ECHO) {
			$closer = $phpcsFile->findNext(T_CLOSE_TAG, $stackPtr);
		} elseif ($tokens[$s]['code'] == T_OPEN_PARENTHESIS) {
			$closer = $tokens[$s]['parenthesis_closer'];
		} else {
			$closer = $phpcsFile->findNext(array(T_SEMICOLON, T_CLOSE_TAG), $stackPtr);
			$s = $stackPtr;
		}

		$warn = false;
		while ($s) {
			$s = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$emptyTokens, PHP_CodeSniffer_Tokens::$bracketTokens, Security_Sniffs_Utils::$staticTokens), $s + 1, $closer, true);
			if ($s && $utils::is_token_user_input($tokens[$s])) {
				$phpcsFile->addError('Easy XSS detected because of direct user input with ' . $tokens[$s]['content'] . ' on ' . $tokens[$stackPtr]['content'], $s, 'EasyXSSerr');
			} elseif ($s && $utils::is_XSS_mitigation($tokens[$s]['content'])) {
				$s = $tokens[$s+1]['parenthesis_closer'];
			} elseif ($s && $parano && !$warn) {
				$warn = $s;
			}
		}
		if ($warn)
			$phpcsFile->addWarning('Possible XSS detected with ' . $tokens[$warn]['content'] . ' on ' . $tokens[$stackPtr]['content'], $warn, 'EasyXSSwarn');
	}

}

?>
