<?php


class Security_Sniffs_Drupal7_XSSFormValueSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING,T_DOUBLE_QUOTED_STRING);
	}

	/**
	* Paranoya mode. Will generate more alerts in order to direct manual code review.
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

		$utils = Security_Sniffs_UtilsFactory::getInstance($this->CmsFramework);
		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == "'#value'" || $tokens[$stackPtr]['content'] == '"#value"') {
			$next = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$bracketTokens, PHP_CodeSniffer_Tokens::$emptyTokens, PHP_CodeSniffer_Tokens::$assignmentTokens),
								$stackPtr + 1, null, true);
			if ($utils::is_token_user_input($tokens[$next])) {
				$phpcsFile->addError('XSS found with #value on ' . $tokens[$next]['content'], $next, 'D7XSSErrFormValue');
			}
			if ($this->ParanoiaMode || !in_array($tokens[$next]['content'], $utils::getXSSMitigationFunctions())) {
				// Case of $label = $element['#value'];
				if ($tokens[$next]['code'] == T_SEMICOLON) {
					$next = $phpcsFile->findPrevious(PHP_CodeSniffer_Tokens::$assignmentTokens, $next);
					$next = $phpcsFile->findPrevious(T_VARIABLE, $next);
				}
				$phpcsFile->addWarning('Potential XSS found with #value on ' . $tokens[$next]['content'], $next, 'D7XSSWarFormValue');
			}
		}
	}

}

?>
