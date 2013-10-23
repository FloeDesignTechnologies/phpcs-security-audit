<?php


class Security_Sniffs_CVE_20132110Sniff implements PHP_CodeSniffer_Sniff {

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
		if ($tokens[$stackPtr]['content'] == 'quoted_printable_encode') {
			$closer = $tokens[$stackPtr + 1]['parenthesis_closer'];
			$s = $stackPtr + 1; // to skip the parenthesis opener '('
			$s = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$emptyTokens, Security_Sniffs_Utils::$staticTokens), $s + 1, $closer, true);
			if ($s) {
				$phpcsFile->addWarning('CVE-2013-2110 Heap-based buffer overflow in the php_quot_print_encode function in ext/standard/quot_print.c in PHP before 5.3.26 and 5.4.x before 5.4.16 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted argument to the quoted_printable_encode function.', $stackPtr, 'CVE-2013-2110');
			}
		}
	}

}


?>
