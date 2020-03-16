<?php
/**
 * Unit test class for the Backticks sniff.
 */

namespace PHPCS_SecurityAudit\Security\Tests\BadFunctions;

use PHPCS_SecurityAudit\Security\Tests\AbstractSecurityTestCase;

class BackticksUnitTest extends AbstractSecurityTestCase
{

	/**
	 * Returns the lines where errors should occur.
	 *
	 * The key of the array should represent the line number and the value
	 * should represent the number of errors that should occur on that line.
	 *
	 * @param string $testFile The name of the file being tested.
	 *
	 * @return array<int, int>
	 */
	public function getErrorList($testFile = '')
	{
		switch ($testFile) {
			case 'BackticksUnitTest.inc':
				return [
					9  => 1,
					13 => 1,
					16 => 1,
				];

			case 'BackticksUnitTest.Drupal7.inc':
				return [
					3 => 1,
					5 => 1,
				];

			default:
				return [];
		}
	}

	/**
	 * Returns the lines where warnings should occur.
	 *
	 * The key of the array should represent the line number and the value
	 * should represent the number of warnings that should occur on that line.
	 *
	 * @param string $testFile The name of the file being tested.
	 *
	 * @return array<int, int>
	 */
	public function getWarningList($testFile = '')
	{
		switch ($testFile) {
			case 'BackticksUnitTest.inc':
				return [
					7  => 1,
					8  => 1,
					11 => 1,
					13 => 1,
					17 => 1,
				];

			case 'BackticksUnitTest.Drupal7.inc':
				return [
					4 => 1,
				];

			default:
				return [];
		}
	}
}
