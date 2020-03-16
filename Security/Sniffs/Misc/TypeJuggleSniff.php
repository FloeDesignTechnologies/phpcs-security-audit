<?php
namespace PHPCS_SecurityAudit\Security\Sniffs\Misc;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class TypeJuggleSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_IS_EQUAL, T_IS_NOT_EQUAL);
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
		if (\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
			$tokens  = $phpcsFile->getTokens();
			$warning = 'You are using the comparison operator "%s" that converts type and may cause unintended results.';
			$phpcsFile->addWarning($warning, $stackPtr, 'TypeJuggle', array($tokens[$stackPtr]['content']));
		}
	}

}

?>
