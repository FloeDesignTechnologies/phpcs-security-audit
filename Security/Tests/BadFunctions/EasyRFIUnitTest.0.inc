<?php

/*
 * Paranoia mode = 0.
 */

// Base.
include ( 'path/to/' . $_GET['filename'] ); // Error.
include_once ('path/to/' . "$filename") . '.' . $extension;
require getenv('PATHTOFILE'); // Error.

// Drupal 7.
require_once ( 'path/to/' . $form['filename'] );
include arg(2) . drupal_get_query_parameters()['param'];

// Prevent false positives on safe $_SERVER variables.
include $_SERVER['DOCUMENT_ROOT'] . '/filename.php';

?>
<?php include $_POST['path'] ?><!-- Error. -->
<?php
echo function_call($param);

// Intentional parse error. This should be the last test in the file.
require_once
