<?php
namespace PHPCS_SecurityAudit\Security\Sniffs\BadFunctions;

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
		$closer = $phpcsFile->findNext(T_BACKTICK, $stackPtr + 1, null, false, null, true);
		if (!$closer) {
			return;
		}

		$utils  = \PHPCS_SecurityAudit\Security\Sniffs\UtilsFactory::getInstance();
		$tokens = $phpcsFile->getTokens();
		$s      = $stackPtr;
		while (($s = $phpcsFile->findNext(T_VARIABLE, ($s + 1), $closer)) !== false) {
			$msg = 'System execution with backticks detected with dynamic parameter';
			if ($utils::is_token_user_input($tokens[$s])) {
				$phpcsFile->addError($msg . ' directly from user input', $s, 'ErrSystemExec');
			} else {
				$phpcsFile->addWarning($msg, $s, 'WarnSystemExec');
			}
		}

	}

}


?>
