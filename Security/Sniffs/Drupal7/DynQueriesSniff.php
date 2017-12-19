<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class DynQueriesSniff implements Sniff {

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

		// Array of dynamic queries methods	and vulnerable params
		// TODO https://drupal.org/node/310085 db_merge()
		$dynq = array(
			'condition' => 3,
			'where' => 1,
			'having' => 1,
			'havingCondition' => 3,
			'orderBy' => array(1,2),
			'groupBy' => 1,
			'addExpression' => 1,
			'join' => 3,
			'innerJoin' => 3,
			'leftJoin' => 3,
			'rightJoin' => 3,
			'expression' => array(1,2),
			'fields' => 1, //special case with sub array() in param #1
		);

		if (!array_key_exists($tokens[$stackPtr]['content'], $dynq)) {
			return;
		}
		$paramnumlist = $dynq[$tokens[$stackPtr]['content']];

		if (!is_array($paramnumlist)) {
			$paramnumlist = array($paramnumlist);
		}

		foreach ($paramnumlist as $paramnum) {
			$t = $utils::get_param_tokens($phpcsFile, $stackPtr, $paramnum);
			if (!$t) {
				// Param not found or empty
				return;
			}

			$closer = end($t)['stackPtr']+1;
			$s = $t[0]['stackPtr'] - 1;
			$warn = FALSE;
			$already = FALSE;
			$next = false;
			while ($s < $closer) {
				$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, $s + 1, $closer, true);
				if (!$s) {
					break;
				}
				if ($tokens[$stackPtr]['content'] == 'fields' && ($tokens[$s]['content'] == 'array' || $next)) {
					$next = $phpcsFile->findNext(T_DOUBLE_ARROW, $s + 1, $closer);
					if ($next) {
						$s = $phpcsFile->findPrevious(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, $next - 1, null, true);
						if (is_numeric($paramnum)) {
							$paramnum .= ' with array key value';
						}
					} else {
						// End of Array or empty Array
						break;
					}
				}
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError('SQL injection found in ' . $tokens[$stackPtr]['content'] . " with param #$paramnum", $s, 'D7DynQueriesSQLi');
				} elseif ($tokens[$s]['code'] == T_DOUBLE_QUOTED_STRING || $tokens[$s]['code'] == T_VARIABLE) {
					$phpcsFile->addWarning('Potential SQL injection with direct variable usage in ' . $tokens[$stackPtr]['content'] . " with param #$paramnum", $s, 'D7DynQueriesDirectVar');
				} elseif ($tokens[$s]['code'] != T_CONSTANT_ENCAPSED_STRING && $tokens[$s]['code'] != T_LNUMBER) {
					$warn = TRUE;
				}
			}

			if ($warn && \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
				$phpcsFile->addWarning('Potential SQL injection in ' . $tokens[$stackPtr]['content'] . " with param #$paramnum", $stackPtr, 'D7DynQueriesWarn');
			}
		}
	}

}


?>
