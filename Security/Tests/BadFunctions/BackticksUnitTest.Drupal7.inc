<?php

$output = `$form['field']`; // Error (user input).
$output = `$request['field']`; // Warning.
`$_GET`; // Error (user input).
