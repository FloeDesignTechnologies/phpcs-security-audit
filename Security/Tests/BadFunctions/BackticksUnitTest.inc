<?php

// Not using variable input.
$output = `ls -al`;

// These should all give an error/warning.
$output = `$form['field']`; // Warning.
$output = `$request['field']`; // Warning.
`$_GET`; // Error (user input).

$output = `git blame --date=short "$filename"`; // Warning.

// Incomplete command. Ignore.
// Intentional parse error. This should be the last test in the file.
$output = `ls
