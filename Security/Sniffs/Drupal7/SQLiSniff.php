<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class SQLiSniff implements Sniff {

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
		if ($tokens[$stackPtr]['content'] == 'db_query') {
			//$closer = $tokens[$stackPtr + 1]['parenthesis_closer'];

			// The first parameter is the one sensible
			$p1tokens = $utils::get_param_tokens($phpcsFile, $stackPtr, 1);

			if (!$p1tokens) {
				echo "empty db_query?\n";
				return;
			}

			$closer = end($p1tokens)['stackPtr']+1;
			$s = $stackPtr + 1;
			$warn = FALSE;

			while ($s < $closer) {
				$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, $s + 1, $closer, true);
				if (!$s) {
					break;
				}
				if ($tokens[$s]['code'] != T_CONSTANT_ENCAPSED_STRING) {
					$warn = TRUE;
				}
				if ($tokens[$s]['code'] == T_DOUBLE_QUOTED_STRING) {
					$phpcsFile->addError('Direct variable usage in db_query()', $s, 'D7DbQueryDirectVar');
				} elseif ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError('Potential SQL injection found in db_query()', $s, 'D7DbQuerySQLi');
				}
			}

			if ($warn) {
				$phpcsFile->addWarning('db_query() is deprecated except when doing a static query', $stackPtr, 'D7NoDbQuery');
			}
		}
	}

}


?>
