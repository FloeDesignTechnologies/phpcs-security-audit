<?php
namespace PHPCS_SecurityAudit\Sniffs;
class UtilsFactory {

	public static function getInstance() {
		$cmsframework = \PHP_CodeSniffer\Config::getConfigData('CmsFramework');
		if (isset($cmsframework)) {
			$utilsclass = '\\PHPCS_SecurityAudit\\Sniffs\\'.$cmsframework.'\\Utils';
			if (class_exists($utilsclass)) {
				return new $utilsclass();
			} else {
				exit("ERROR - Invalid CmsFramework value \"$cmsframework\" in config. Must be a class under Security_Sniffs.\n");
			}
		}
		return new \PHPCS_SecurityAudit\Sniffs\Utils();
	}

}

?>
