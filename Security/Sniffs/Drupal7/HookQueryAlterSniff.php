<?php


class Security_Sniffs_Drupal7_HookQueryAlterSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_STRING);
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
		$utils = new Security_Sniffs_Drupal7_Utils();

		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == 'db_query') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $phpcsFile->findNext(PHP_CodeSniffer_Tokens::$stringTokens, $stackPtr + 1, $closer);
			if (preg_match('/{/', $tokens[$s]['content'])) {
				$n = $phpcsFile->findPrevious(T_STRING, $s);				
				if ($tokens[$n]['content'] != 'hook_query_alter') {
					$phpcsFile->addError('You must use hook_query_alter with {} in db_query', $s, 'D7DbQueryHookQAlter');
				}
			}
		}
	}

}


?>
