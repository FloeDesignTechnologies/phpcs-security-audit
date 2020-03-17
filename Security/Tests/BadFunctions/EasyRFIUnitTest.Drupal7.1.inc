<?php

/*
 * Paranoia mode = 1, CmsFramework = Drupal7.
 */
 
// Base.
include ( 'path/to/' . $_GET['filename'] ); // Error.
include ('path/to/' . "$filename") . '.' . $extension; // Warning x 2.
include getenv('PATHTOFILE'); // Error.

// Drupal 7.
include ( 'path/to/' . $form['filename'] ); // Error.
include arg(2) . drupal_get_query_parameters()['param']; // Error x 2.

// Intentional parse error. This should be the last test in the file.
include_once ( $_GET['path']
