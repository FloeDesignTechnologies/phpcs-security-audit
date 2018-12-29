<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class CallbackFunctionsSniff implements Sniff {

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
	* @param File $phpcsFile The file where the token was found.
	* @param int                  $stackPtr  The position in the stack where
	*                                        the token was found.
	*
	* @return void
	*/
	public function process(File $phpcsFile, $stackPtr) {
		$tokens = $phpcsFile->getTokens();
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance();

		if (in_array($tokens[$stackPtr]['content'], $utils::getCallbackFunctions())) {
	        $opener = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
			$closer = $tokens[$opener]['parenthesis_closer'];
            $s = $stackPtr + 1;
			if ($tokens[$stackPtr]['content'] == 'array_filter') {
				// Case of array_filter() with only one argument
				$s = $phpcsFile->findNext(T_COMMA, $s, $closer);
				if (!$s) {
					return;
				}
			}
			$s = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHP_CodeSniffer\Util\Tokens::$bracketTokens,
										\PHPCS_SecurityAudit\Sniffs\Utils::$staticTokens, array(T_STRING_CONCAT)), $s, $closer, true);
			$msg = 'Function ' . $tokens[$stackPtr]['content'] . '() that supports callback detected';
             if ($s) {
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError($msg . ' with parameter directly from user input', $stackPtr, 'ErrCallbackFunctions');
				} else {
					$phpcsFile->addWarning($msg, $stackPtr, 'WarnCallbackFunctions');
				}
			}
		}
	}

}

?>
