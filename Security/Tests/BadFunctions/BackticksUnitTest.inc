<?php

// Not using variable input.
$output = `ls -al`;

// These should all give an error/warning.
$output = `$form['field']`; // Warning.
$output = `$request['field']`; // Warning.
`$_GET`; // Error (user input).

$output = `git blame --date=short "$filename"`; // Warning.

$output = `git blame --date=$_POST['key'] "$filename"`; // Warning + error.

$output = `git blame
	--date=$_POST['key'] // Error.
	"$filename"`; // Warning.

// Incomplete command. Ignore.
// Intentional parse error. This should be the last test in the file.
$output = `ls
