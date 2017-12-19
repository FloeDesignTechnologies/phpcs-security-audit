<?php
namespace PHPCS_SecurityAudit\Sniffs\BadFunctions;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class MysqliSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_NEW, T_OBJECT_OPERATOR, T_STRING);
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

		// http://www.php.net/manual/en/book.mysqli.php
		$mysqlifunctions = array('query', 'prepare', 'multi_query', 'real_query');

		if ($tokens[$stackPtr]['code'] == T_NEW) {
			$s = $phpcsFile->findNext(T_STRING, $stackPtr);
			if ($tokens[$s]['content'] == 'mysqli') {
				$s = $phpcsFile->findPrevious(T_VARIABLE, $stackPtr);
				if ($s)
					$utils::addSQLObjects($tokens[$s]['content']);
			}
		} elseif ($tokens[$stackPtr]['code'] == T_OBJECT_OPERATOR) {
			$prev = $phpcsFile->findPrevious(T_VARIABLE, $stackPtr);
			if ($prev && in_array($tokens[$prev]['content'], $utils::getSQLObjects())) {
				$next = $phpcsFile->findNext(T_STRING, $stackPtr);
				if ($next && in_array($tokens[$next]['content'], $mysqlifunctions)) {
					$s = $utils::findDirtyParam($phpcsFile, $next);
					if ($s) {
						$msg = 'MYSQLi function ' . $tokens[$next]['content'] . '() detected with dynamic parameter ';
						if ($utils::is_token_user_input($tokens[$s])) {
							$phpcsFile->addError($msg . ' directly from user input', $stackPtr, 'ErrMysqli');
						} else {
							$phpcsFile->addWarning($msg, $stackPtr, 'WarnMysqli');
						}
					}
				}
			}
		} elseif ($tokens[$stackPtr]['code'] == T_STRING && $tokens[$stackPtr]['content'] == 'mysqli_connect') {
			$prev = $phpcsFile->findPrevious(T_VARIABLE, $stackPtr);
			if ($prev)
				$utils::addSQLObjects($tokens[$prev]['content']);
			$s = $utils::findDirtyParam($phpcsFile, $stackPtr);
			if ($utils::is_token_user_input($tokens[$s])) {
				$phpcsFile->addError('mysqli_connect() param directly from user input', $stackPtr, 'ErrMysqliconnect');
			}
		} elseif ($tokens[$stackPtr]['code'] == T_STRING && in_array($tokens[$stackPtr]['content'],array_map(function($v) { return 'mysqli_' . $v; }, $mysqlifunctions))) {
			// The first parameter is always the link
			$p2 = $utils::get_param_tokens($phpcsFile, $stackPtr, 2);
			$s = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHP_CodeSniffer\Util\Tokens::$bracketTokens, \PHPCS_SecurityAudit\Sniffs\Utils::$staticTokens, array(T_STRING_CONCAT)), $p2[0]['stackPtr'], end($p2)['stackPtr']+1, true);
			if ($s) {
				$msg = 'MYSQLi function ' . $tokens[$stackPtr]['content'] . '() detected with dynamic parameter ';
				if ($utils::is_token_user_input($tokens[$s])) {
					$phpcsFile->addError($msg . ' directly from user input', $stackPtr, 'ErrMysqli' . $tokens[$stackPtr]['content']);
				} else {
					$phpcsFile->addWarning($msg, $stackPtr, 'WarnMysqli' . $tokens[$stackPtr]['content']);
				}
			}
		}

	}

}


?>
