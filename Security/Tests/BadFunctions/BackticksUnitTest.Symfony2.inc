<?php

$output = `$form['field']`; // Warning.
$output = `$request['field']`; // Error (user input).
`$_GET`; // Error (user input).
