<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class AssertsSniff implements Sniff {

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

		if ($tokens[$stackPtr]['content'] == 'assert') {
            $opener = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
			$closer = $tokens[$opener]['parenthesis_closer'];
            $s = $stackPtr + 1;
			$s = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHP_CodeSniffer\Util\Tokens::$bracketTokens, \PHPCS_SecurityAudit\Sniffs\Utils::$staticTokens, array(T_STRING_CONCAT)), $s, $closer, true);
             if ($s) {
				$msg = 'Assert eval function ' . $tokens[$stackPtr]['content'] . '() detected with dynamic parameter';
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError($msg . ' directly from user input', $stackPtr, 'ErrFunctionHandling');
				} else {
					$phpcsFile->addWarning($msg, $stackPtr, 'WarnFunctionHandling');
				}
			}
		}

	}

}

?>
