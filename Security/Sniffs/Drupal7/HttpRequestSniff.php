<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class HttpRequestSniff implements Sniff {

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
		$utils = new Utils();

		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == 'drupal_http_request') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $closer;
			$warn = 1;
			while ($s) {
				$s = $phpcsFile->findPrevious(array(T_CONSTANT_ENCAPSED_STRING,T_DOUBLE_QUOTED_STRING), $s - 1);
				if($tokens[$s]['content'] == "'verify_peer'" || $tokens[$s]['content'] == '"verify_peer"') {
					$warn = 0;
				}
			}
			if ($warn) {
				$phpcsFile->addWarning('Verify that drupal_http_request uses HTTPS and is called with verify_peer in order to validate the certificate', $stackPtr, 'D7HttpRequestSSL');
			}

			$d = $utils::findDirtyParam($phpcsFile, $stackPtr);
			if ($d && $utils::is_token_user_input($tokens[$d])) {
				$phpcsFile->addError('drupal_http_request called with direct user input ' . $tokens[$d]['content'], $stackPtr, 'D7HttpRequestUserInputErr');
			} elseif ($d && \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
				$phpcsFile->addWarning('drupal_http_request called with variable ' . $tokens[$d]['content'], $stackPtr, 'D7HttpRequestUserInputErr');
			}

		}
	}

}


?>
