<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class EasyRFISniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE);
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
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance();
		$tokens = $phpcsFile->getTokens();
		$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, $stackPtr, null, true, null, true);

		if ($tokens[$s]['code'] == T_OPEN_PARENTHESIS) {
			$closer = $tokens[$s]['parenthesis_closer'];
		} else {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $stackPtr;
		}
		while ($s) {
			$s = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHP_CodeSniffer\Util\Tokens::$bracketTokens, \PHPCS_SecurityAudit\Sniffs\Utils::$staticTokens), $s + 1, $closer, true);
			if ($s && $utils::is_token_user_input($tokens[$s])) {
				if (\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') || !$utils::is_token_false_positive($tokens[$s], $tokens[$s+2])) {
					$phpcsFile->addError('Easy RFI detected because of direct user input with ' . $tokens[$s]['content'] . ' on ' . $tokens[$stackPtr]['content'], $s, 'ErrEasyRFI');
				}
			} elseif ($s && \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') && $tokens[$s]['content'] != '.') {
				$phpcsFile->addWarning('Possible RFI detected with ' . $tokens[$s]['content'] . ' on ' . $tokens[$stackPtr]['content'], $s, 'WarnEasyRFI');
			}
		}
	}

}

?>
