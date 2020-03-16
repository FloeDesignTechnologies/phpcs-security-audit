<?php

/*
 * Paranoia mode = 1
 */

// Test for 'equals' conditionals.
if ( true == $true ) { // Warning.
	echo 'True';
} elseif ( false === $true ) {
	echo 'False';
}

// Test for 'not equals' conditionals.
if ( true != $true ) { // Warning.
	echo 'True';
} elseif ( true <> $true ) { // Warning.
	echo 'False';
} elseif ( false !== $true ) { // Ok.
	echo 'False';
}
