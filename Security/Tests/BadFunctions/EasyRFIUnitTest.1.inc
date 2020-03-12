<?php

/*
 * Paranoia mode = 1.
 */
 
// Base.
include ( 'path/to/' . $_GET['filename'] ); // Error.
include ('path/to/' . "$filename") . '.' . $extension; // Warning x 2.
include getenv('PATHTOFILE'); // Error.

// Drupal 7.
include ( 'path/to/' . $form['filename'] ); // Warning.
include arg(2) . drupal_get_query_parameters()['param']; // Warning x 2.

// Prevent false positives on safe $_SERVER variables.
include $_SERVER['DOCUMENT_ROOT'] . '/filename.php'; // Error.
