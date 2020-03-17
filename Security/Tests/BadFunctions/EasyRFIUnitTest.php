<?php

namespace PHPCS_SecurityAudit\Security\Tests\BadFunctions;

use PHPCS_SecurityAudit\Security\Tests\AbstractSecurityTestCase;

/**
 * Unit test class for the EasyRFI sniff.
 *
 * @covers \PHPCS_SecurityAudit\Security\Sniffs\BadFunctions\EasyRFISniff
 */
class EasyRFIUnitTest extends AbstractSecurityTestCase
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
			case 'EasyRFIUnitTest.0.inc':
				return [
					8  => 1,
					10 => 1,
					20 => 1,
				];

			case 'EasyRFIUnitTest.1.inc':
				return [
					8  => 1,
					10 => 1,
					17 => 1,
					20 => 1,
				];

			case 'EasyRFIUnitTest.Drupal7.1.inc':
				return [
					8  => 1,
					10 => 1,
					13 => 1,
					14 => 2,
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
			case 'EasyRFIUnitTest.1.inc':
				return [
					9  => 2,
					13 => 1,
					14 => 2,
				];

			case 'EasyRFIUnitTest.Drupal7.1.inc':
				return [
					9  => 2,
				];

			default:
				return [];
		}
	}
}
