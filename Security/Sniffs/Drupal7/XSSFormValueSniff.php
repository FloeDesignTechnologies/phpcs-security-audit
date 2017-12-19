<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class XSSFormValueSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING,T_DOUBLE_QUOTED_STRING);
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
		if ($tokens[$stackPtr]['content'] == "'#value'" || $tokens[$stackPtr]['content'] == '"#value"') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$next = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$bracketTokens, \PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHP_CodeSniffer\Util\Tokens::$assignmentTokens),
								$stackPtr + 1, $closer + 1, true);
			if ($next == $closer && $tokens[$next]['code'] == T_SEMICOLON)  {
				// Case of $label = $element['#value'];
				$next = $phpcsFile->findPrevious(\PHP_CodeSniffer\Util\Tokens::$assignmentTokens, $next);
				$next = $phpcsFile->findPrevious(T_VARIABLE, $next);
				$phpcsFile->addWarning('Potential XSS found with #value on ' . $tokens[$next]['content'], $next, 'D7XSSWarFormValue');
			} elseif ($next && $utils::is_token_user_input($tokens[$next])) {
				$phpcsFile->addError('XSS found with #value on ' . $tokens[$next]['content'], $next, 'D7XSSErrFormValue');
			} elseif ($next && \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
				if (in_array($tokens[$next]['content'], $utils::getXSSMitigationFunctions())) {
					$n = $phpcsFile->findNext($utils::getVariableTokens(), $next + 1, $closer);
					if ($n) {
						$phpcsFile->addWarning('Potential XSS found with #value on ' . $tokens[$n]['content'], $n, 'D7XSSWarFormValue');
					}
				} else {
					$phpcsFile->addWarning('Potential XSS found with #value on ' . $tokens[$next]['content'], $next, 'D7XSSWarFormValue');
				}
			}
		}
	}

}

?>
