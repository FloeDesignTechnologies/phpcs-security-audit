<?php
namespace PHPCS_SecurityAudit\Sniffs\Misc;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;

class IncludeMismatchSniff implements Sniff {

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
		$tokens = $phpcsFile->getTokens();
		$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr + 1);
		if (preg_match('/\.(\w+)(?:\'|\")$/', $tokens[$s]['content'], $matches)) {
			$ext = $matches[1];
			if (!array_key_exists($ext, $phpcsFile->config->extensions)) {
				$phpcsFile->addError("The file extension '.$ext' that is not specified by --extensions has been used in a include/require function. Please add it to the scan process.", $stackPtr, 'ErrMiscIncludeMismatch');
			}
		} else {
			$phpcsFile->addError("No file extension has been found in a include/require function. This implies that some PHP code is not scanned by PHPCS.", $stackPtr, 'ErrMiscIncludeMismatchNoExt');
		}
	}

}

?>
