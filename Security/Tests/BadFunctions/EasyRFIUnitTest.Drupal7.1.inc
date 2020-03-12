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
