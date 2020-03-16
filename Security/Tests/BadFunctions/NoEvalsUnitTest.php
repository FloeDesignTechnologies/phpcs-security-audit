<?php

namespace PHPCS_SecurityAudit\Security\Tests\BadFunctions;

use PHPCS_SecurityAudit\Security\Tests\AbstractSecurityTestCase;

/**
 * Unit test class for the NoEvals sniff.
 *
 * @covers \PHPCS_SecurityAudit\Security\Sniffs\BadFunctions\NoEvalsSniff
 */
class NoEvalsUnitTest extends AbstractSecurityTestCase
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
		return [
			3 => 1,
			4 => 1,
			5 => 1,
		];
	}

	/**
	 * Returns the lines where warnings should occur.
	 *
	 * The key of the array should represent the line number and the value
	 * should represent the number of warnings that should occur on that line.
	 *
	 * @return array<int, int>
	 */
	public function getWarningList()
	{
		return [];
	}
}
