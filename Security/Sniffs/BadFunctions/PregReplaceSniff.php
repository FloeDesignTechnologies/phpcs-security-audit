<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class PregReplaceSniff implements Sniff  {

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
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance();

		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == 'preg_replace') {
			$s = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
			$closer = $tokens[$s]['parenthesis_closer'];
			$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, $s + 1, $closer, true);
			if ($tokens[$s]['code'] == T_CONSTANT_ENCAPSED_STRING) {
				$pattern = $tokens[$s]['content'];
				if (substr($pattern, 1, 1) === '/') {
					// $pattern is a regex
					if (preg_match('/(\/|\))\w*e\w*"$/', $pattern)) {
						$phpcsFile->addWarning("Usage of preg_replace with /e modifier is not recommended.", $stackPtr, 'PregReplaceE');

						$s = $phpcsFile->findNext(array(T_COMMA, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT), $s + 1, $closer, true);
						if ($utils::is_token_user_input($tokens[$s]))
							$phpcsFile->addError("User input and /e modifier found in preg_replace, remote code execution possible.", $stackPtr, 'PregReplaceUserInputE');
					}

				} else {
					$phpcsFile->addWarning("Weird usage of preg_replace, please check manually for /e modifier.", $stackPtr, 'PregReplaceWeird');
				}
			} elseif ($tokens[$s]['code'] == T_VARIABLE && $utils::is_token_user_input($tokens[$s])) {
				$phpcsFile->addError("User input found in preg_replace, /e modifier could be used for malicious intent.", $stackPtr, 'PregReplaceUserInput');
			} else {
				$phpcsFile->addWarning("Dynamic usage of preg_replace, please check manually for /e modifier or user input.", $stackPtr, 'PregReplaceDyn');
			}
		}

	}

}

?>
