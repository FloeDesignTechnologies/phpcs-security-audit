<?php

class Security_Sniffs_UtilsFactory {

	public static function getInstance($cmsframework) {
		if (isset($cmsframework)) {
			$utilsclass = 'Security_Sniffs_'.$cmsframework.'_Utils';
			if (class_exists($utilsclass)) {
				return new $utilsclass();
			}
		}
		return new Security_Sniffs_Utils();
	}

}

?>
