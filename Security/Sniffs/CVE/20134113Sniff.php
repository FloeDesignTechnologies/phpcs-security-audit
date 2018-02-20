<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal8;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class CVE20134113Sniff implements Sniff {

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
		$tokens = $phpcsFile->getTokens();
		if ($tokens[$stackPtr]['content'] == 'xml_parse_into_struct') {
			$closer = $tokens[$stackPtr + 1]['parenthesis_closer'];
			$s = $stackPtr + 1; // to skip the parenthesis opener '('
						$s = $phpcsFile->findNext(array_merge(\PHP_CodeSniffer\Util\Tokens::$emptyTokens, \PHPCS_SecurityAudit\Sniffs\Utils::$staticTokens), $s + 1, $closer, true);
			if ($s) {
				$phpcsFile->addWarning('CVE-2013-4113 ext/xml/xml.c in PHP before 5.3.27 does not properly consider parsing depth, which allows remote attackers to cause a denial of service (heap memory corruption) or possibly have unspecified other impact via a crafted document that is processed by the xml_parse_into_struct function.', $stackPtr, 'CVE-2013-4113');
				if ($tokens[$s]['code'] == T_DOUBLE_QUOTED_STRING) {
					echo $tokens[$s]['content'];
				}
			}
		}
	}

}


?>
