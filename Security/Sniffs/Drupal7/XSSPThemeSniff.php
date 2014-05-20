<?php


class Security_Sniffs_Drupal7_XSSPThemeSniff implements PHP_CodeSniffer_Sniff {

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

		if ($tokens[$stackPtr]['content'] == "'#theme'" || $tokens[$stackPtr]['content'] == '"#theme"') {
			$next = $phpcsFile->findNext(PHP_CodeSniffer_Tokens::$stringTokens, $stackPtr + 1);
			if($this->ParanoiaMode && $tokens[$next]['content'] == "'html_tag'") {
				$phpcsFile->addWarning('Potential XSS found with #theme and html_tag', $stackPtr, 'D7XSSWarhtmltag');
			} else {
				$next = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$bracketTokens, PHP_CodeSniffer_Tokens::$emptyTokens, PHP_CodeSniffer_Tokens::$assignmentTokens),
								$stackPtr + 1, null, true);
				if ($next && $this->ParanoiaMode && $tokens[$next]['code'] != T_CONSTANT_ENCAPSED_STRING) {
					$phpcsFile->addWarning('Potential XSS found with #theme on ' . $tokens[$next]['content'], $stackPtr, 'D7XSSWarTheme');
				}
			}
		}
	}

}

?>
