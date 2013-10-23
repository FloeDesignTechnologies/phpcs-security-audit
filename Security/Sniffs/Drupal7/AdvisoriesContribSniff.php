<?php


class Security_Sniffs_Drupal7_AdvisoriesContribSniff implements PHP_CodeSniffer_Sniff {

	/**
	* Returns the token types that this sniff is interested in.
	*
	* @return array(int)
	*/
	public function register() {
		return array(T_INLINE_HTML);
	}

	/**
	* Framework or CMS used. Must be a class under Security_Sniffs.
	*
	* @var String
	*/
	public $CmsFramework = NULL;

	/**
	* Processes the tokens that this sniff is interested in.
	*
	* @param PHP_CodeSniffer_File $phpcsFile The file where the token was found.
	* @param int                  $stackPtr  The position in the stack where
	*                                        the token was found.
	*
	* @return void
	*/
	public function process(PHP_CodeSniffer_File $phpcsFile, $stackPtr) {
		if ($stackPtr > 0)
			return;
		$dversion = '7';
		$utils = Security_Sniffs_UtilsFactory::getInstance('Drupal7');
		$tokens = $phpcsFile->getTokens();
        $fileName  = $phpcsFile->getFileName();

		if (preg_match('/\.info$/', $fileName)) {
			$info = $utils->drupal_parse_info_format(file_get_contents($fileName));
			if (isset($info) && count($info) && strpos($info['core'], $dversion) === 0) {
				if (array_key_exists('project', $info) && array_key_exists($info['project'], $utils::$CVEModule)) {
					foreach ($utils::$CVEModule[$info['project']] as $vcve) {
						list($a, $CVEversion) = explode('-', $vcve[0]);
						if ($a != $info['core'])
							echo "WARNING Drupal core version inconsistence!!";
						list ($a, $mversion) = explode('-', $info['version']);
						$CVEversion = (float) $CVEversion;
						$mversion = (float) $mversion;
	print "$CVEversion - $mversion\n";
						$diff = $CVEversion - $mversion;
						if ($diff > 0 && $diff < 1)
							echo "FOUND minor " . $info['version'] . "CVE: " .$vcve[1]. "\n";
						elseif ($diff > 1)
							echo "FOUND major " . $info['version'] . "\n";
						elseif ($diff < 0)
							echo "SAFE! " . $info['version'] . "\n";
					}
				}
			}
		}
	}

}


?>
