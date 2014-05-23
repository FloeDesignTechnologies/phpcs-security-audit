<?php

class Security_Sniffs_Utils {

	// Tokens that can't containts or use any variables (so no user input)
	public static $staticTokens = array(T_CONSTANT_ENCAPSED_STRING, T_COMMA, T_LNUMBER, T_DNUMBER);

	/**
	* Heavy used function to verify if a string from a token contains user input
	* @deprecated	We should use is_token_user_input() instead to allow functions in CMS/frameworks as user input.
	*
    * @param String $var	The string contening the token content to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_direct_user_input($var) {
		if (preg_match('/\$\{?_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)/', $var) || preg_match('/^(getenv|apache_getenv)$/', $var))
			return TRUE;
		else
			return FALSE;
	}

	/**
	* Heavy used function to verify if a token contains user input
	*
    * @param String $t	The token to match
	* @return Boolean	Returns TRUE if found, FALSE if not found
	*/
	public static function is_token_user_input($t) {
		if ($t['code'] == T_VARIABLE) {
			if (preg_match('/\$\{?_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)/', $t['content'])) {
				return TRUE;
			}
		} elseif ($t['code'] == T_STRING) {
			if (preg_match('/^(getenv|apache_getenv)$/', $t['content'])) {
				return TRUE;
			}
		}
		return FALSE;
	}


	public static function getFilesystemFunctions() {
		return array(
			// From http://www.php.net/manual/en/book.filesystem.php
			'basename', 'chgrp', 'chmod', 'chown', 'clearstatcache', 'copy', 'delete', 'dirname', 'disk_free_space', 'disk_total_space',
			'diskfreespace', 'fclose', 'feof', 'fflush', 'fgetc', 'fgetcsv', 'fgets', 'fgetss', 'file_exists', 'file_get_contents', 'file_put_contents',
			'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype', 'flock', 'fnmatch',
			'fopen', 'fpassthru', 'fputcsv', 'fputs', 'fread', 'fscanf', 'fseek', 'fstat', 'ftell', 'ftruncate', 'fwrite', 'glob', 'is_dir', 'is_executable',
			'is_file', 'is_link', 'is_readable', 'is_uploaded_file', 'is_writable', 'is_writeable', 'lchgrp', 'lchown', 'link', 'linkinfo', 'lstat', 'mkdir',
			'move_uploaded_file', 'parse_ini_file', 'parse_ini_string', 'pathinfo', 'readfile', 'readlink', 'realpath_cache_get',
			'realpath_cache_size', 'realpath', 'rename', 'rewind', 'rmdir', 'set_file_buffer', 'stat', 'symlink', 'tempnam', 'tmpfile', 'touch', 'umask', 'unlink',

			// From http://www.php.net/manual/en/ref.dir.php except function that use directory handle as parameter
			'chdir', 'chroot', 'dir', 'opendir', 'scandir',

			// From http://ca2.php.net/manual/en/function.mime-content-type.php
			'finfo_open', 

			// From http://ca2.php.net/manual/en/book.xattr.php
			'xattr_get', 'xattr_list', 'xattr_remove', 'xattr_set', 'xattr_supported',

			// From http://www.php.net/manual/en/function.readgzfile.php
			'readgzfile', 'gzopen', 'gzfile',

			// From http://www.php.net/manual/en/ref.image.php
			'getimagesize', 'imagecreatefromgd2', 'imagecreatefromgd2part', 'imagecreatefromgd', 'imagecreatefromgif', 'imagecreatefromjpeg', 'imagecreatefrompng',
			'imagecreatefromwbmp', 'imagecreatefromwebp', 'imagecreatefromxbm', 'imagecreatefromxpm',
			'imagepsloadfont', 'jpeg2wbmp', 'png2wbmp',
			// 2nd params only, maybe make it standalone and check just the second param?
			'image2wbmp', 'imagegd2', 'imagegd', 'imagegif', 'imagejpeg', 'imagepng', 'imagewbmp', 'imagewebp', 'imagexbm',

			// From http://www.php.net/manual/en/ref.exif.php
			'exif_imagetype', 'exif_read_data', 'exif_thumbnail', 'read_exif_data',

			// From http://www.php.net/manual/en/ref.hash.php
			'hash_file', 'hash_hmac_file', 'hash_update_file',

			// From http://www.php.net/manual/en/ref.misc.php
			'highlight_file', 'php_check_syntax', 'php_strip_whitespace', 'show_source',

			// Various functions that open/read files
			'get_meta_tags', 'hash_file', 'hash_hmac_file', 'hash_update_file', 'md5_file', 'sha1_file',
			'bzopen',
		);
	}

	// From http://www.php.net/manual/en/book.exec.php
	public static function getSystemexecFunctions() {
		return array(
			'exec', 'passthru', 'proc_open', 'popen', 'shell_exec', 'system', 'pcntl_exec'
		);
	}

	// From http://www.php.net/manual/en/ref.funchand.php
	public static function getFunctionhandlingFunctions() {
		return array(
			'create_function', 'call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array',
			'function_exists', 'register_shutdown_function', 'register_tick_function'
		);
	}

	// From RIPS and http://stackoverflow.com/questions/3115559/exploitable-php-functions
	public static function getCallbackFunctions() {
		return array(
			'ob_start', 'array_diff_uassoc', 'array_diff_ukey', 'array_filter', 'array_intersect_uassoc', 'array_intersect_ukey', 'array_map', 'array_reduce',
			'array_udiff_assoc', 'array_udiff_uassoc', 'array_udiff', 'array_uintersect_assoc', 'array_uintersect_uassoc', 'array_uintersect', 'array_walk_recursive',
			'array_walk', 'assert_options', 'uasort', 'uksort', 'usort', 'preg_replace_callback', 'spl_autoload_register', 'iterator_apply', 'call_user_func',
			'call_user_func_array', 'register_shutdown_function', 'register_tick_function', 'set_error_handler', 'set_exception_handler', 'session_set_save_handler',
			'sqlite_create_aggregate', 'sqlite_create_function'
		);
	}


	/**
	* Set of variables and helpers to collect SQL functions depending of the driver selected
	*/
	public static $sqlFunctions = array();

	public static function getSQLFunctions() {
		return Security_Sniffs_Utils::$sqlFunctions;
	}

	public static function addSQLFunction($f) {
		array_push(Security_Sniffs_Utils::$sqlFunctions, $f);
	}


	/**
	* Set of variables and helpers to collect SQL objects created by new()
	*/
	public static $sqlObjects = array();

	public static function getSQLObjects() {
		return Security_Sniffs_Utils::$sqlObjects;
	}

	public static function addSQLObjects($o) {
		array_push(Security_Sniffs_Utils::$sqlObjects, $o);
	}


	// Returns the token constants that are considerated as variables
	public static function getVariableTokens() {
		return array(
			T_DOUBLE_QUOTED_STRING, T_VARIABLE
		);
	}

	/**
	* Array of XSS mitigation function
	*
	* @return array(String)	returns the array of functions
	*/
	public static function getXSSMitigationFunctions() {
		return array(
			'htmlspecialchars', 'htmlentities'
		);
	}

	/**
	* Verify that a function is a XSS mitigation
	*
	* @param $var	The variable containing the function string
	* @return Boolean	returns TRUE if it's a XSS mitigation function, FALSE otherwise
	*/
	public static function is_XSS_mitigation($var) {
		if (in_array($var,  Security_Sniffs_Utils::getXSSMitigationFunctions())) {
			return TRUE;
		}
		return FALSE;
	}


	/**
	* Helper function for get_param_tokens() that recursivly go inside parenthesis
	*
    * @param Array $tokens	The array of tokens from $phpcsFile->getTokens()
	* @param int $s	The $stackPtr from PHP_CodeSniffer where the opening parenthesis is
	* @param Array $t	The array of tokens where to crawl
	* @return Array()	An array containing tokens from the requested param
	* @return Array(int, Array())	Returns the stack pointer and the tokens that has been crawled into
	*/
	private static function crawl_open_parenthesis($tokens, $s, $t) {
		$subcloser = $tokens[$s]['parenthesis_closer'];
		while ($s < $subcloser) {
			$tokens[$s]['stackPtr'] = $s;
			$t[] = $tokens[$s];
			$s++;
			if ($tokens[$s]['code'] == T_OPEN_PARENTHESIS)
				list($s, $t) = Security_Sniffs_Utils::crawl_open_parenthesis($tokens, $s, $t);
		}
		return array($s, $t);
	}


	/**
	* Returns the tokens contained in the function paramters such as f(param1token1 . param1token3, param2token1)
	*
    * @param PHP_CodeSniffer_File $phpcsFile	The working instance of PHP_CodeSniffer
	* @param int $stackPtr	The $stackPtr from PHP_CodeSniffer where the function is
	* @param int $num	The parameter number desired (starts with 1)
	* @return Array()	An array containing tokens from the requested param
	* @return NULL	If no tokens is found or parameter doesn't exists
	*/
	public static function get_param_tokens($phpcsFile, $stackPtr, $num) {
		$tokens = $phpcsFile->getTokens();
		$opener = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
		$closer = $tokens[$opener]['parenthesis_closer'];
		$s = $opener + 1;
		$i = 1;
		$olds = $s;
		$t = array();
		$pcloser = $s;
		while ($s < $closer) {
			$pcloser = $phpcsFile->findNext(T_COMMA, $s, $closer);
			if (!$pcloser) {
				if ($num > $i) {
					// param num doesnt exists
					return NULL;
				}
				while ($s < $closer) {
					$tokens[$s]['stackPtr'] = $s;
					$t[] = $tokens[$s];
					$s++;
				}
				break;
			}
			while ($s < $pcloser) {
				if ($tokens[$s]['code'] == T_OPEN_PARENTHESIS) {
					list($s, $t) = Security_Sniffs_Utils::crawl_open_parenthesis($tokens, $s, $t);
				}
				$tokens[$s]['stackPtr'] = $s;
				$t[] = $tokens[$s];
				$s++;
			}
			if ($num == $i)
				break;
			else
				$t = array();

			// Edge case of func()[0], skip.
			if ($tokens[$s]['code'] == T_OPEN_SQUARE_BRACKET) {
				$s = $tokens[$s]['bracket_closer'];
			} else {
				$i++;
				$s++;
			}
		}
		return empty($t) ? NULL : $t;
	}


	/**
	* Returns a dirty param found in the parameter of a function call
	*
    * @param PHP_CodeSniffer_File $phpcsFile	The working instance of PHP_CodeSniffer
	* @param int $stackPtr	The $stackPtr from PHP_CodeSniffer where the function is.
	*
	* @return int The stackPtr of the param found, false if nothing is found
	*/
	public static function findDirtyParam($phpcsFile, $stackPtr) {
		$tokens = $phpcsFile->getTokens();
		$opener = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
		$closer = $tokens[$opener]['parenthesis_closer'];
		$s = $opener + 1;
		$s = $phpcsFile->findNext(array_merge(PHP_CodeSniffer_Tokens::$emptyTokens, PHP_CodeSniffer_Tokens::$bracketTokens, Security_Sniffs_Utils::$staticTokens, array(T_STRING_CONCAT)), $s, $closer, true);
		return $s;
	}

}

?>
