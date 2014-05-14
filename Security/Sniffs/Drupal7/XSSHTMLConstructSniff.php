<?php


class Security_Sniffs_Drupal7_XSSHTMLConstructSniff implements PHP_CodeSniffer_Sniff {
	// TODO maybe this should be a generic sniff?

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
		if (preg_match('/<|>/', $tokens[$stackPtr]['content'])) {
			$end = $phpcsFile->findNext(T_SEMICOLON, $stackPtr + 1);
			$next = $stackPtr;
			while($next && $next = $phpcsFile->findNext(array_merge(array(T_STRING_CONCAT), PHP_CodeSniffer_Tokens::$emptyTokens), $next + 1, $end, true)) {
				// Next token will be checked with this sniff, no need to go further
				if (in_array($tokens[$next]['code'], $this->register())) {
					return;
				}
				if ($next && !in_array($tokens[$next]['content'], $utils::getXSSMitigationFunctions())) {
					if ($utils::is_direct_user_input($tokens[$next]['content'])) {
						$phpcsFile->addError('HTML construction with direct user input '.$tokens[$next]['content'].' detected.', $stackPtr, 'D7XSSHTMLConstructErr');
					} elseif ($this->ParanoiaMode && !in_array($tokens[$next]['code'], array_merge(array(T_INLINE_ELSE, T_COMMA), PHP_CodeSniffer_Tokens::$booleanOperators))) {
						$phpcsFile->addWarning('HTML construction with '.$tokens[$next]['content'].' detected.', $stackPtr, 'D7XSSHTMLConstructWarn');
					}
				}
				$next = $phpcsFile->findNext(T_STRING_CONCAT, $next + 1, $end);
			}
		}
	}

}

?>
