<?php

class Security_Sniffs_Drupal7_Utils extends Security_Sniffs_Utils {

	public static function getFilesystemFunctions() {
		return array_merge(parent::getFilesystemFunctions(), array(
			'drupal_basename', 'drupal_chmod', 'drupal_dirname', 'drupal_mkdir', 'drupal_move_uploaded_file', 'drupal_realpath', 'drupal_rmdir',
			'drupal_tempnam', 'drupal_unlink', 'file_build_uri', 'file_copy', 'file_create_filename', 'file_create_htaccess', 'file_create_url',
			'file_default_scheme', 'file_delete', 'file_destination', 'file_directory_temp', 'file_download', 'file_ensure_htaccess',
			'file_get_content_headers', 'file_get_mimetype', 'file_get_stream_wrappers', 'file_load', 'file_load_multiple', 'file_move',
			'file_munge_filename', 'file_prepare_directory', 'file_save', 'file_save_data', 'file_save_upload', 'file_scan_directory',
			'file_space_used', 'file_stream_wrapper_get_class', 'file_stream_wrapper_get_instance_by_scheme', 'file_stream_wrapper_get_instance_by_uri', 				'file_stream_wrapper_uri_normalize', 'file_stream_wrapper_valid_scheme', 'file_transfer', 'file_unmanaged_copy', 'file_unmanaged_delete',
			'file_unmanaged_delete_recursive', 'file_unmanaged_move', 'file_unmanaged_save_data', 'file_unmunge_filename', 'file_upload_max_size',
			'file_uri_scheme', 'file_uri_target', 'file_usage_add', 'file_usage_delete', 'file_usage_list', 'file_validate', 'file_validate_extensions',
			'file_validate_image_resolution', 'file_validate_is_image', 'file_validate_name_length', 'file_validate_size', 'file_valid_uri'
		));
	}


	/**
	* Heavy used function to verify if a string from a token contains user input
	* @deprecated	We should use is_token_user_input() instead to allow functions in CMS/frameworks as user input.
	*
    * @param String $var	The string contening the token content to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_direct_user_input($var) {
		if (parent::is_direct_user_input($var)) {
			return TRUE;
		} else {
			if ($var == '$form') {
				return TRUE;
			} elseif ($var == 'arg') {
				return TRUE;
			}
		}
		return FALSE;
	}


	/**
	* Heavy used function to verify if a token contains user input
	*
    * @param String $t	The token to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_token_user_input($t) {
		if ($t['code'] == T_VARIABLE || $t['code'] == T_STRING) {
			if (parent::is_token_user_input($t)) {
				return TRUE;
			} else {
				if ($t['content'] == '$form') {
					return TRUE;
				} elseif ($t['content'] == 'arg') {
					return TRUE;
				}
			}
			return FALSE;
		}
	}


	// List of modules with fixed version and CVE-ID
	public static $CVEModule = array(
		'nodeblock' => array(array('7.x-1.3', 'CVE-2013-0325'), array('7.x-2.4', 'CVE-2013-0325'), array('7.x-1.1', 'CVE-2013-0325')),
	);


	// List of core advisories keyed by fixed minor version, with Advisory ID and CVE (optional)
	public static $CoreAdvisories = array(
		5 => array(
			array('DRUPAL-SA-CORE-2011-003', 'CVE-2011-2726'),
		),
		16 => array(
			array('DRUPAL-SA-CORE-2012-003', 'CVE-2012-4553 CVE-2012-4554'),
		),
		99 => array(
			array('DRUPAL-SA-CORE-FAKE-000', 'NO CVE'),
		),
	);


	/**
	* Parses data in Drupal's .info format. Directly copied from Drupal source code 
	* https://api.drupal.org/api/drupal/includes%21common.inc/function/drupal_parse_info_format/7
	*
	* Data should be in an .ini-like format to specify values. White-space
	* generally doesn't matter, except inside values:
	* @code
	*   key = value
	*   key = "value"
	*   key = 'value'
	*   key = "multi-line
	*   value"
	*   key = 'multi-line
	*   value'
	*   key
	*   =
	*   'value'
	* @endcode
	*
	* Arrays are created using a HTTP GET alike syntax:
	* @code
	*   key[] = "numeric array"
	*   key[index] = "associative array"
	*   key[index][] = "nested numeric array"
	*   key[index][index] = "nested associative array"
	* @endcode
	*
	* PHP constants are substituted in, but only when used as the entire value.
	* Comments should start with a semi-colon at the beginning of a line.
	*
	* @param $data
	*   A string to parse.
	*
	* @return
	*   The info array.
	*
	* @see drupal_parse_info_file()
	*/
	function drupal_parse_info_format($data) {
	  $info = array();
	  $constants = get_defined_constants();

	  if (preg_match_all('
		@^\s*                           # Start at the beginning of a line, ignoring leading whitespace
		((?:
		  [^=;\[\]]|                    # Key names cannot contain equal signs, semi-colons or square brackets,
		  \[[^\[\]]*\]                  # unless they are balanced and not nested
		)+?)
		\s*=\s*                         # Key/value pairs are separated by equal signs (ignoring white-space)
		(?:
		  ("(?:[^"]|(?<=\\\\)")*")|     # Double-quoted string, which may contain slash-escaped quotes/slashes
		  (\'(?:[^\']|(?<=\\\\)\')*\')| # Single-quoted string, which may contain slash-escaped quotes/slashes
		  ([^\r\n]*?)                   # Non-quoted string
		)\s*$                           # Stop at the next end of a line, ignoring trailing whitespace
		@msx', $data, $matches, PREG_SET_ORDER)) {
		foreach ($matches as $match) {
		  // Fetch the key and value string.
		  $i = 0;
		  foreach (array('key', 'value1', 'value2', 'value3') as $var) {
		    $$var = isset($match[++$i]) ? $match[$i] : '';
		  }
		  $value = stripslashes(substr($value1, 1, -1)) . stripslashes(substr($value2, 1, -1)) . $value3;

		  // Parse array syntax.
		  $keys = preg_split('/\]?\[/', rtrim($key, ']'));
		  $last = array_pop($keys);
		  $parent = &$info;

		  // Create nested arrays.
		  foreach ($keys as $key) {
		    if ($key == '') {
		      $key = count($parent);
		    }
		    if (!isset($parent[$key]) || !is_array($parent[$key])) {
		      $parent[$key] = array();
		    }
		    $parent = &$parent[$key];
		  }

		  // Handle PHP constants.
		  if (isset($constants[$value])) {
		    $value = $constants[$value];
		  }

		  // Insert actual value.
		  if ($last == '') {
		    $last = count($parent);
		  }
		  $parent[$last] = $value;
		}
	  }

	  return $info;
	}

}

?>
