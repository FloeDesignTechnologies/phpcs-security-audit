<?php
namespace PHPCS_SecurityAudit\Sniffs\Misc;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class BadCorsHeaderSniff implements Sniff  {
	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_CONSTANT_ENCAPSED_STRING, T_DOUBLE_QUOTED_STRING);
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
		if (stristr($tokens[$stackPtr]['content'], 'Access-Control-Allow-Origin')) {
			$closer = $phpcsFile->findNext(T_CLOSE_PARENTHESIS, $stackPtr);
			$s = $phpcsFile->findNext(\PHP_CodeSniffer\Util\Tokens::$stringTokens, $stackPtr + 1, $closer);
			if ($s && stristr($tokens[$s]['content'], '*')) {
				$phpcsFile->addWarning('Bad CORS header detected.', $stackPtr, 'WarnPCKS1Crypto');
			}
			
		}
		/*
		if (preg_match("/^mcrypt_/", ) || in_array($tokens[$stackPtr]['content'], $utils::getCryptoFunctions())) {
			$tokstr = $tokens[$stackPtr]['content'];
			if ( $tokstr == "openssl_public_encrypt" || $tokstr == "openssl_private_decrypt") {
				$p4 = $utils::get_param_tokens($phpcsFile, $stackPtr, 4);
				$p4 == null ? $s = false : $s = $phpcsFile->findNext(T_STRING, $p4[0]['stackPtr'], end($p4)['stackPtr']+1);
				if ($s) {
					if ($tokens[$s]['content'] != "OPENSSL_PKCS1_OAEP_PADDING") {
						$phpcsFile->addError('Bad use of ' . $tokstr . ' without OPENSSL_PKCS1_OAEP_PADDING', $s, 'ErrPCKS1Crypto');
					}
				} else {
					// there's no 4th parameter, according to the doc the default is OPENSSL_PKCS1_PADDING
					$phpcsFile->addWarning($tokstr . ' is using insecure OPENSSL_PKCS1_PADDING by default.', $stackPtr, 'WarnPCKS1Crypto');
				}
			} else {
				// Only warn on crypto functions in paranoia mode
				if (\PHP_CodeSniffer\Config::getConfigData('ParanoiaMode')) {
					$phpcsFile->addWarning('Crypto function ' . $tokens[$stackPtr]['content'] . ' used.', $stackPtr, 'WarnCryptoFunc');
				}
			}
		}
		
		*/
	}

}

?>
