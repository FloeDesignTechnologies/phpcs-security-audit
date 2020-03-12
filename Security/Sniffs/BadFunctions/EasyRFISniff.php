<?php
namespace PHPCS_SecurityAudit\Security\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class EasyRFISniff implements Sniff {

	/**
	 * Tokens to search for within an include/require statement.
	 *
	 * @var array
	 */
	private $search = [];

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		// Set the $search property.
		$this->search  = \PHP_CodeSniffer\Util\Tokens::$emptyTokens;
		$this->search += \PHP_CodeSniffer\Util\Tokens::$bracketTokens;
		$this->search += \PHPCS_SecurityAudit\Security\Sniffs\Utils::$staticTokens;

		return \PHP_CodeSniffer\Util\Tokens::$includeTokens;
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
		$closer = $phpcsFile->findNext(T_SEMICOLON, ($stackPtr + 1));
		if ($closer === false) {
			// Live coding or parse error.
			return;
		}

		$utils  = \PHPCS_SecurityAudit\Security\Sniffs\UtilsFactory::getInstance();
		$tokens = $phpcsFile->getTokens();
		$s      = $stackPtr;

		while ($s) {
			$s = $phpcsFile->findNext($this->search, $s + 1, $closer, true);

			$data = array(
				$tokens[$s]['content'],
				$tokens[$stackPtr]['content'],
			);

			if ($s && $utils::is_token_user_input($tokens[$s])) {
				if (\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') || !$utils::is_token_false_positive($tokens[$s], $tokens[$s+2])) {
					$phpcsFile->addError('Easy RFI detected because of direct user input with %s on %s', $s, 'ErrEasyRFI', $data);
				}
			} elseif ($s && \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') && $tokens[$s]['content'] != '.') {
				$phpcsFile->addWarning('Possible RFI detected with %s on %s', $s, 'WarnEasyRFI', $data);
			}
		}
	}

}

?>
