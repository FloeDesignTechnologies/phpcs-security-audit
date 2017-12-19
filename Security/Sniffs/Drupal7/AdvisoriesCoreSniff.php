<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class AdvisoriesCoreSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING);
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
		if ($stackPtr > 0)
			return;
		$fileName  = $phpcsFile->getFileName();
		if (!preg_match('/includes\/bootstrap\.inc$/', $fileName))
			return;
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance('Drupal7');
		$tokens = $phpcsFile->getTokens();

		if ($tokens[$stackPtr]['content'] == "'VERSION'") {

			$s = $phpcsFile->findNext(T_CONSTANT_ENCAPSED_STRING, $stackPtr + 1);

			if (preg_match('/(\d+)\.(\d+)/', $tokens[$s]['content'], $m)) {
				// Check if it's the right Drupal version
				if ($m[1] != 7)
					return;
				$minorversion = $m[2];
			} else {
				// This is not the right Drupal file?
				return;
			}

			foreach ($utils::$CoreAdvisories as $key => $value) {
				if ($minorversion < $key) {
					// TODO clean the error and maybe the variable in Utils.. make a loop for fetch all bugs and addErrors?
					$phpcsFile->addError("FOUND core out of date $minorversion $key, ".$value[0][0]." cves: ".$value[0][1], $stackPtr, 'D7AdvCore');
				}
			}

		}

	}

}


?>
