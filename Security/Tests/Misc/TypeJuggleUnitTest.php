<?php

namespace PHPCS_SecurityAudit\Security\Tests\Misc;

use PHPCS_SecurityAudit\Security\Tests\AbstractSecurityTestCase;

/**
 * Unit test class for the TypeJuggle sniff.
 *
 * @covers \PHPCS_SecurityAudit\Security\Sniffs\Misc\TypeJuggleSniff
 */
class TypeJuggleUnitTest extends AbstractSecurityTestCase
{

	/**
	 * Returns the lines where errors should occur.
	 *
	 * The key of the array should represent the line number and the value
	 * should represent the number of errors that should occur on that line.
	 *
	 * @return array<int, int>
	 */
	public function getErrorList()
	{
		return [];
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
			case 'TypeJuggleUnitTest.1.inc':
				return [
					8  => 1,
					15 => 1,
					17 => 1,
				];

			default:
				return [];
		}
	}
}
