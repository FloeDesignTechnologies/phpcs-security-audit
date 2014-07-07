<?php

class Security_Sniffs_UtilsFactory {

	public static function getInstance() {
		$cmsframework = PHP_CodeSniffer::getConfigData('CmsFramework');
		if (isset($cmsframework)) {
			$utilsclass = 'Security_Sniffs_'.$cmsframework.'_Utils';
			if (class_exists($utilsclass)) {
				return new $utilsclass();
			} else {
				exit("ERROR - Invalid CmsFramework value \"$cmsframework\" in config. Must be a class under Security_Sniffs.\n");
			}
		}
		return new Security_Sniffs_Utils();
	}

}

?>
