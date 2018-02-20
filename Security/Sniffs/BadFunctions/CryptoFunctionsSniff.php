<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class CryptoFunctionsSniff implements Sniff  {
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
		// Run this sniff only in paranoia mode
		if (!\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
			return;
		}
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance();
		$tokens = $phpcsFile->getTokens();
		if (preg_match("/^mcrypt_/", $tokens[$stackPtr]['content']) || in_array($tokens[$stackPtr]['content'], $utils::getCryptoFunctions())) {
			$phpcsFile->addWarning('Crypto function ' . $tokens[$stackPtr]['content'] . ' used.', $stackPtr, 'WarnCryptoFunc');
		}
	}

}

?>
