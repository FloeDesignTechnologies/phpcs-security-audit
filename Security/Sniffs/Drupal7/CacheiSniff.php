<?php


class Security_Sniffs_Drupal7_CacheiSniff implements PHP_CodeSniffer_Sniff {

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
		$utils = new Security_Sniffs_Drupal7_Utils();

		$tokens = $phpcsFile->getTokens();
		$content = $tokens[$stackPtr]['content'];

		if ($content == 'cache_get' || $content == 'cache_set') {
			//$closer = $tokens[$stackPtr + 1]['parenthesis_closer'];

			// The first parameter is the one sensible
			$p1tokens = $utils::get_param_tokens($phpcsFile, $stackPtr, 1);

			if (!$p1tokens) {
				echo "empty $content?\n";
				return;
			}

			$closer = end($p1tokens)['stackPtr']+1;
			$s = $stackPtr + 1;

			while ($s < $closer) {
				$s = $phpcsFile->findNext(PHP_CodeSniffer_Tokens::$emptyTokens, $s + 1, $closer, true);
				if (!$s) {
					break;
				}
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError("Potential cache injection found in $content()", $s, 'D7Cachei');
				} elseif (PHP_CodeSniffer::getConfigData('ParanoiaMode') && in_array($tokens[$s]['code'], $utils::getVariableTokens())) {
					$phpcsFile->addWarning("Direct variable usage in $content()", $s, 'D7CacheDirectVar');
				}
			}
		}
	}

}


?>
