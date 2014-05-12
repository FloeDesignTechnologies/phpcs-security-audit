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

		if (!$this->ParanoiaMode) {
			return;
		}

		if ($tokens[$stackPtr]['content'] == "'#theme'" || $tokens[$stackPtr]['content'] == '"#theme"') {
			$next = $phpcsFile->findNext(PHP_CodeSniffer_Tokens::$stringTokens, $stackPtr + 1);
			if($tokens[$next]['content'] == "'html_tag'") {
				$phpcsFile->addWarning('Potential XSS found with #theme and html_tag', $stackPtr, 'D7XSSWarhtmltag');
			} else {
				$phpcsFile->addWarning('Potential XSS found with #theme', $stackPtr, 'D7XSSWarTheme');
			}
		}
	}

}

?>
