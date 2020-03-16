<?php
/**
 * An abstract class that all Security sniff unit tests must extend.
 *
 * A sniff unit test checks a .inc file for expected violations of a single
 * coding standard. Expected errors and warnings that are not found, as well as
 * unexpected warnings and errors, are considered test failures.
 *
 * This class will take care of setting the configuration variables in PHP_CodeSniffer
 * needed to test all relevant configuration combinations for each sniff in
 * the Security standard.
 *
 * The configuration variables set are based on the file name of a test case file.
 *
 * Naming conventions for the test case files:
 * SniffNameUnitTest[.CmsFramework][.ParanoiaMode].inc
 *
 * Both `[.CmsFramework]` as well as `[.ParanoiaMode]` are optional.
 * If neither is set, the defaults of no CmsFramework and Paranoia level 0 will be used.
 *
 * Separate test case files for different paranoia levels and different frameworks are
 * only needed if the sniff behaves differently based on these settings.
 *
 * - If the sniff behaviour is the same all round, just having one plain `SniffNameUnitTest.inc`
 *   test case file will be sufficient.
 * - If the sniff behaviour is only dependent on one of the two configuration settings,
 *   the other can be left out.
 *   Examples:
 *   - Sniff behaviour only depends on `ParanoiaMode`: `SniffNameUnitTest.[01].inc`.
 *   - Sniff behaviour only depends on `CmsFramework`: `SniffNameUnitTest.[CmsFramework].inc`.
 */

namespace PHPCS_SecurityAudit\Security\Tests;

use PHP_CodeSniffer\Tests\Standards\AbstractSniffUnitTest;

abstract class AbstractSecurityTestCase extends AbstractSniffUnitTest
{

	/**
	 * Get a list of CLI values to set before the file is tested.
	 *
	 * @param string                  $filename The name of the file being tested.
	 * @param \PHP_CodeSniffer\Config $config   The config data for the run.
	 *
	 * @return void
	 */
	public function setCliValues($filename, $config)
	{
		// Set paranoia level.
		$paranoia = substr($filename, (strlen($filename) - 5), 1);
		if ($paranoia === '1') {
			$config->setConfigData('ParanoiaMode', 1, true);
		} else {
			$config->setConfigData('ParanoiaMode', 0, true);
		}

		// Set the CMS Framework if necessary.
		$firstDot    = strpos($filename, '.');
		$firstOffset = ($firstDot + 1);
		$secondDot   = strpos($filename, '.', $firstOffset);

		$extendedExtension = '';
		if ($secondDot !== false) {
			$extendedExtension = substr($filename, $firstOffset, ($secondDot - $firstOffset));
		}

		switch ($extendedExtension) {
			case 'Drupal7':
				$config->setConfigData('CmsFramework', 'Drupal7', true);
				break;

			default:
				$config->setConfigData('CmsFramework', null, true);
				break;
		}
	}
}
