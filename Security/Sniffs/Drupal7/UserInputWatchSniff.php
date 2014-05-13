<?php


class Security_Sniffs_Drupal7_UserInputWatchSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_STRING, T_VARIABLE);
	}

	/**
	* Paranoya mode. Will generate more alerts but will miss less vulnerabilites.
	*
	* @var bool
	*/
	public $ParanoiaMode = 1;

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
		if (!$this->ParanoiaMode) return;

		$utils = new Security_Sniffs_Drupal7_Utils();
		$tokens = $phpcsFile->getTokens();

		if ($utils::is_token_user_input($tokens[$stackPtr])) {
					$phpcsFile->addWarning('User input detetected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaWarn');
		}
	}

}


?>
