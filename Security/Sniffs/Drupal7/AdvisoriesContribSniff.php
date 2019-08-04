<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;


class AdvisoriesContribSniff implements Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_INLINE_HTML);
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
		if ($stackPtr > 0)
			return;
		$dversion = '7';
        $fileName  = $phpcsFile->getFileName();
		if (!preg_match('/\.info$/', $fileName))
			return;
		$utils = \PHPCS_SecurityAudit\Sniffs\UtilsFactory::getInstance('Drupal7');
		$tokens = $phpcsFile->getTokens();

		$info = $utils->drupal_parse_info_format(file_get_contents($fileName));
		if (isset($info) && count($info) && array_key_exists('project', $info) && array_key_exists($info['project'], $utils::$ContribAdvisories)) {
			if ($utils::$ContribAdvisories[$info['project']][0][0] == 'abandoned') {
				$phpcsFile->addError("Module " . $info['project'] . " is abandoned due to a security issue the maintainer never fixed. Details: " . $utils::$ContribAdvisories[$info['project']][0][1], $stackPtr, 'D7ErrAdvisoriesContribAbandonned');
				return;
			}
			if ($utils::$ContribAdvisories[$info['project']][0][0] == 'unsupported') {
				$phpcsFile->addError("Module " . $info['project'] . " is unsupported due to unfixed security issue. The Drupal Security Team recommends that this module be uninstalled immediately Details: " . $utils::$ContribAdvisories[$info['project']][0][1], $stackPtr, 'D7ErrAdvisoriesContribUnsupported');
				return;
			}
			if (array_key_exists('core', $info) && array_key_exists('version', $info)) {
				if (strpos($info['core'], $dversion) === 0) {
						foreach ($utils::$ContribAdvisories[$info['project']] as $vcve) {
							list($a, $CVEversion) = explode('-', $vcve[0]);
							if ($a != $info['core'])
								echo "WARNING Drupal core version inconsistence!!";
							list ($a, $mversion) = explode('-', $info['version']);
							$CVEversion = preg_replace('/^(\d+)\.(\d)$/','${1}.0${2}', $CVEversion);
							$CVEversion = (float) $CVEversion;
							if (preg_match('/dev/', $vcve[0]))
								$phpcsFile->addWarning("WARNING module " . $info['project'] . " does not have any release for the security fix, manual checking required. Details: " . $vcve[1], $stackPtr, 'D7WarnAdvisoriesContribDev');
							if (preg_match('/rc|alpha|beta/', $vcve[0]))
								$phpcsFile->addWarning("WARNING module " . $info['project'] . " is using special version tagging around the security fix, manual checking recommanded. Details: " . $vcve[1], $stackPtr, 'D7WarnAdvisoriesContribrc');
							$mversion = preg_replace('/^(\d+)\.(\d)$/','${1}.0${2}', $mversion);
							$mversion = (float) $mversion;
							$diff = $CVEversion - $mversion;
							if ($diff > 0 && $diff < 1)
								$phpcsFile->addError("Module " . $info['project'] ." ". $info['version'] . " contains security issue and must be updated to at least $vcve[0]. Details: " . $vcve[1], $stackPtr, 'D7ErrAdvisoriesContribFoundMinor');
							elseif ($diff >= 1)
								$phpcsFile->addWarning("Module " . $info['project'] ." ". $info['version'] . " is out of date a major version and might contains security issue. " . $vcve[1], $stackPtr, 'D7WarnAdvisoriesContribFoundMajor');
							elseif ($diff <= 0) {
								if (preg_match('/x$/', $vcve[0])) {
									$phpcsFile->addError("Module " . $info['project'] ." ". $info['version'] . " contains security issue to all $vcve[0] versions. " . $vcve[1], $stackPtr, 'D7ErrAdvisoriesContribFoundMajor');
								} else {
									//echo "$fileName: SAFE! " . $info['version'] . "\n";
								}
							} else {
								echo "MAJOR ERROR IN LOGIC!!!!!\n";
							}
						}
				}
			} else {
				$phpcsFile->addWarning("Module " . $info['project'] . " is listed in advisories but file doesn't provide version information. Please use packages from drupal.org", $stackPtr, 'D7WarnAdvisoriesContribNoInfo');
			}
		}

	}

}


?>
