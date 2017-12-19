<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class DbQueryACSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING, T_STRING);
	}

	/**
	* Force the paranoia on or off for this particular rule ignoring global setting ParanoiaMode.
	*
	* @var bool
	*/
	public $forceParanoia = -1;

	// This function can be used as an example of dealing with local defines
	private static $defines = array();

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
		if ($this->forceParanoia >= 0) {
			$parano =  $this->forceParanoia ? 1 : 0;
		} else {
			$parano = \PHP_CodeSniffer\Config::getConfigData('ParanoiaMode') ? 1 : 0;
		}

		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == 'db_query' || $tokens[$stackPtr]['content'] == 'db_query_range') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr + 1, $closer);
			if (preg_match('/{\s*(field_data|node|taxonony_term_data)\w*}/', $tokens[$s]['content'], $matches)) {
				$phpcsFile->addWarning($tokens[$stackPtr]['content'] . ' should not be used with ' . $matches[0] . ' because access control modules won\'t be able to modify or extend your SQL query.', $s, 'D7DbQueryACWar');
			}
		}

		if (in_array(str_replace("'", "", $tokens[$stackPtr]['content']), $utils::getACEntityTypes())) {
			$s = $phpcsFile->findPrevious(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr - 1);
			if ($tokens[$s]['content'] == "'entity_type'") {
				// TODO refactor to not have to backtrace for defines, use $utils::addACEntityType
			} elseif ($parano) {
				$isdef = $phpcsFile->findPrevious(T_STRING, $s - 1);
				if ($tokens[$isdef]['content'] == 'define') {
					array_push(self::$defines, str_replace("'", "", $tokens[$s]['content']));
				}
			}
		}

		// TODO the folling two ifs needs refactoring (putting the while in $utils might be a good idea)

		if ($tokens[$stackPtr]['content'] == 'entityCondition') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr + 1, $closer);
			if ($tokens[$s]['content'] == "'entity_type'") {
				$closer = $phpcsFile->findNext(T_CLOSE_PARENTHESIS, $s);
				$s = $phpcsFile->findNext(array_merge(array(T_STRING), \PHP_CodeSniffer\Util\Tokens::$stringTokens), $s + 1, $closer);
				if ($s) {
					$found = str_replace("'", "", $tokens[$s]['content']);
					if (in_array($found, array_merge(self::$defines, $utils::getACEntityTypes()))) {
						$closer = $phpcsFile->findNext(T_SEMICOLON, $s);
						$warn = true;
						while ($s = $phpcsFile->findNext(T_STRING, $s + 1, $closer)) {
							if ($tokens[$s]['content'] == 'addTag') {
								$c = $phpcsFile->findNext(T_CLOSE_PARENTHESIS, $s);
								$n = $phpcsFile->findNext(array_merge(array(T_STRING), \PHP_CodeSniffer\Util\Tokens::$stringTokens), $s + 1, $c);
								$tag = str_replace("'", "", $tokens[$n]['content']);
								if ($n && in_array($tag, array('node_access','entity_field_access','term_access'))) {
									// This will not warn if wrong _access is used. Please warn anyways when paranoia is enforced.
									$warn = false;
								}
							}
						}
						if ($warn) {
							$phpcsFile->addWarning("EntityFieldQuery with entity type $found should be tagged for access restrictions", $stackPtr, 'D7DbQueryACErr');
						} elseif ($parano) {
							$phpcsFile->addWarning("Please validate that EntityFieldQuery with entity type $found is tagged with adequate access restrictions", $stackPtr, 'D7DbQueryACErr');
						}
					}
				}
			}
		}

		if ($tokens[$stackPtr]['content'] == 'db_select') {
			$closer = $phpcsFile->findNext(T_SEMICOLON, $stackPtr);
			$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr + 1, $closer);
			if (preg_match('/(field_data|node|taxonony_term_data)\w*/', $tokens[$s]['content'], $matches)) {
				$closer = $phpcsFile->findNext(T_SEMICOLON, $s);
				$warn = true;
				while ($s = $phpcsFile->findNext(T_STRING, $s + 1, $closer)) {
					if ($tokens[$s]['content'] == 'addTag') {
						$c = $phpcsFile->findNext(T_CLOSE_PARENTHESIS, $s);
						$n = $phpcsFile->findNext(array_merge(array(T_STRING), \PHP_CodeSniffer\Util\Tokens::$stringTokens), $s + 1, $c);
						$tag = str_replace("'", "", $tokens[$n]['content']);
						if ($n && in_array($tag, array('node_access','entity_field_access','term_access'))) {
							// This will not warn if wrong _access is used. Please warn anyways when paranoia is enforced.
							$warn = false;
						}
					}
				}
				if ($warn) {
					$phpcsFile->addWarning("Dynamic query with db_select on table $matches[0] should be tagged for access restrictions", $stackPtr, 'D7DbQueryACErr');
				} elseif ($parano) {
					$phpcsFile->addWarning("Please validate that dynamic query with db_select on table $matches[0] is tagged with adequate access restrictions", $stackPtr, 'D7DbQueryACErr');
				}
			}
		}

	}

}


?>
