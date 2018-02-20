<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class BackticksSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_BACKTICK);
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
        $closer = $phpcsFile->findNext(T_BACKTICK, $stackPtr + 1, null, false, null, true);
		if (!$closer) {
			return;
		}
        $s = $stackPtr + 1;
		$s = $phpcsFile->findNext(T_VARIABLE, $s, $closer);
        if ($s) {
			$msg = 'System execution with backticks detected with dynamic parameter';
			if ($utils::is_token_user_input($tokens[$s])) {
				$phpcsFile->addError($msg . ' directly from user input', $stackPtr, 'ErrSystemExec');
			} else {
				$phpcsFile->addWarning($msg, $stackPtr, 'WarnSystemExec');
			}
		}

	}

}


?>
