<?php


class Security_Sniffs_Drupal7_AdvisoriesCoreSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING);
	}

	/**
	* Framework or CMS used. Must be a class under Security_Sniffs.
	*
	* @var String
	*/
	public $CmsFramework = NULL;

	/**
	* Processes the tokens that this sniff is interested in.
	*
	* @param PHP_CodeSniffer_File $phpcsFile The file where the token was found.
	* @param int                  $stackPtr  The position in the stack where
	*                                        the token was found.
	*
	* @return void
	*/
	public function process(PHP_CodeSniffer_File $phpcsFile, $stackPtr) {
		$fileName  = $phpcsFile->getFileName();
		if (!preg_match('/includes\/bootstrap\.inc$/', $fileName))
			return;
		$utils = Security_Sniffs_UtilsFactory::getInstance('Drupal7');
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
