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
	* This sniff depends on it to be set, otherwise it won't be excuted.
	*
	* @var bool
	*/
	public $ParanoiaMode = 1;

	/**
	* Threshold for $form and $form_state possible user input.
	* Will generate one alert per file when this threshold is reached.
	*
	* @var int
	* @var int
	*/
	public $FormThreshold =  10;
	public $FormStateThreshold =  10;

	/**
	* Privates variables used for the above threshold
	* @var int
	* @var int
	*/
	private static $form_count = 0;
	private static $form_state_count = 0;

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
			if ($tokens[$stackPtr]['content'] == '$form') {
				// $form and $form_state are generating too much noise, let's do a count and make a generic warning for the file instead for each line
				if (++self::$form_count == $this->FormThreshold) {
					$phpcsFile->addWarning('At least '.$this->FormThreshold.' possible user input detetected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaFormWarn');
				}
			} elseif ($tokens[$stackPtr]['content'] == '$form_state') {
				// $form and $form_state are generating too much noise, let's do a count and make a generic warning for the file instead for each line
				if (++self::$form_state_count == $this->FormStateThreshold) {
					$phpcsFile->addWarning('At least '.$this->FormStateThreshold.' possible user input detetected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaFormStateWarn');
				}
			} else {
				$phpcsFile->addWarning('User input detetected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaWarn');
			}
		}
	}

}


?>
