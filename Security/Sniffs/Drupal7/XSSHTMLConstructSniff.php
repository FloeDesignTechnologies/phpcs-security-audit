<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class XSSHTMLConstructSniff implements Sniff {
	// TODO maybe this should be a generic sniff?

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
		if (preg_match('/<|>/', $tokens[$stackPtr]['content'])) {
			$end = $phpcsFile->findNext(T_SEMICOLON, $stackPtr + 1);
			$next = $stackPtr;
			while($next && $next = $phpcsFile->findNext(array_merge(array(T_STRING_CONCAT), \PHP_CodeSniffer\Util\Tokens::$emptyTokens), $next + 1, $end, true)) {
				// Next token will be checked with this sniff, no need to go further
				if (in_array($tokens[$next]['code'], $this->register())) {
					return;
				}
				if ($next && !in_array($tokens[$next]['content'], $utils::getXSSMitigationFunctions())) {
					if ($utils::is_direct_user_input($tokens[$next]['content'])) {
						$phpcsFile->addError('HTML construction with direct user input '.$tokens[$next]['content'].' detected.', $stackPtr, 'D7XSSHTMLConstructErr');
					} elseif (\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') && !in_array($tokens[$next]['code'], array_merge(array(T_INLINE_ELSE, T_COMMA), \PHP_CodeSniffer\Util\Tokens::$booleanOperators))) {
						if ($tokens[$next]['code'] == T_CLOSE_PARENTHESIS) {
							$f = $phpcsFile->findPrevious(T_STRING, $next);
							if ($f) {
								$phpcsFile->addWarning('HTML construction with '.$tokens[$f]['content'].'() detected.', $stackPtr, 'D7XSSHTMLConstructWarnF');
							}
						} else {
							$phpcsFile->addWarning('HTML construction with '.$tokens[$next]['content'].' detected.', $stackPtr, 'D7XSSHTMLConstructWarn');
						}
					}
				}
				$next = $phpcsFile->findNext(T_STRING_CONCAT, $next + 1, $end);
			}
		}
	}

}

?>
