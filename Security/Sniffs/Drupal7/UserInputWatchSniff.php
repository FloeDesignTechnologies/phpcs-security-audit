<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class UserInputWatchSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_STRING, T_VARIABLE);
	}

	/**
	* Threshold for $form and $form_state possible user input.
	* Will generate one alert per file when this threshold is reached.
	*
	* @var int
	* @var int
	*/
	public $FormThreshold =  10;
	public $FormStateThreshold =  10;

	/**
	* Privates variables used for the above threshold
	* @var int
	* @var int
	*/
	private static $form_count = 0;
	private static $form_state_count = 0;

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
		if (!\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) return;

		$utils = new Utils();
		$tokens = $phpcsFile->getTokens();
		if ($utils::is_token_user_input($tokens[$stackPtr])) {
			if ($tokens[$stackPtr]['content'] == '$form') {
				// $form and $form_state are generating too much noise, let's do a count and make a generic warning for the file instead for each line
				if (++self::$form_count == $this->FormThreshold) {
					$phpcsFile->addWarning('At least '.$this->FormThreshold.' possible user input detected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaFormWarn');
				}
			} elseif ($tokens[$stackPtr]['content'] == '$form_state') {
				// $form and $form_state are generating too much noise, let's do a count and make a generic warning for the file instead for each line
				if (++self::$form_state_count == $this->FormStateThreshold) {
					$phpcsFile->addWarning('At least '.$this->FormStateThreshold.' possible user input detected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaFormStateWarn');
				}
			} else {
				$phpcsFile->addWarning('User input detetected with '.$tokens[$stackPtr]['content'].'.', $stackPtr, 'D7UserInWaWarn');
			}
		}
	}

}


?>
