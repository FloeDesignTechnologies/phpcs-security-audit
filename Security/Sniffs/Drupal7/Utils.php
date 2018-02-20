<?php
namespace PHPCS_SecurityAudit\Sniffs\Drupal7;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;
use PHPCS_SecurityAudit\Sniffs\Utils as BaseUtils;
class Utils extends BaseUtils {

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
	* Array of XSS mitigation function
	* Note: does not inherit from parent, see is_XSS_mitigation()
	*
	* @return array(String)	returns the array of functions
	*/
	public static function getXSSMitigationFunctions() {
		return array(
			'check_plain', 't', 'l', 'url', 'drupal_attributes', 'drupal_render_children', 'drupal_render'
		);
	}

	/**
	* Verify that a function is a XSS mitigation
	* By default this function will return TRUE even if a normal PHP mitigation function is used,
	* because it's considered a bad practice to do otherwise; see second param $isparent
	*
	* @param $var	The variable containing the function string
	* @param Boolean	bool set to TRUE if we check for the parent's functions, default FALSE
	* @return Boolean	returns TRUE if it's a XSS mitigation function, FALSE otherwise
	*/
	public static function is_XSS_mitigation($var, $isparent=FALSE) {
		if ($isparent && parent::is_XSS_mitigation($var)) {
			return TRUE;
		} else {
			if (in_array($var,  Utils::getXSSMitigationFunctions())) {
				return TRUE;
			}
		}
		return FALSE;
	}

	// Entity types that will need _access addTag
	// https://drupal.org/node/93737 https://drupal.org/node/310077
	private static $ACEntityTypes = array('node', 'taxonomy_term', 'term', 'entity_field');

	public static function getACEntityTypes() {
		return Utils::$ACEntityTypes;
	}

	public static function addACEntityType($e) {
		array_push(Utils::$ACEntityTypes, $e);
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
		if (parent::is_token_user_input($t))
			return TRUE;

		if ($t['code'] == T_VARIABLE) {
			if (in_array($t['content'], array(
					'$form', '$form_state'
				)))	return TRUE;
		} elseif ($t['code'] == T_STRING) {
			if (in_array($t['content'], array(
					'arg', 'drupal_get_query_parameters', 'field_view_value'
				))) return TRUE;
		}

		return FALSE;
	}


	// List of modules with fixed (prior to / upgrade to) version  and CVE-ID (or DRUPAL-SA-CONTRIB-ID if not available)
	public static $ContribAdvisories = array(
		'domain' => array(array('7.x-2.4', 'DRUPAL-SA-CONTRIB-2010-096')),
		'aes' => array(array('7.x-1.5', 'DRUPAL-SA-CONTRIB-2011-005')),
		'webform' => array(array('7.x-3.10', 'DRUPAL-SA-CONTRIB-2011-021'), array('7.x-3.17', 'SA-CONTRIB-2012-035 CVE-2012-1660'), array('7.x-3.20', 'SA-CONTRIB-2014-018'), array('7.x-4.1', 'SA-CONTRIB-2014-018')),

		'nodereference_url' => array(array('7.x-1.10', 'DRUPAL-SA-CONTRIB-2011-018')),
		'save_draft' => array(array('7.x-1.4', 'DRUPAL-SA-CONTRIB-2011-017')),
		'forward' => array(array('7.x-1.1', 'DRUPAL-SA-CONTRIB-2011-035'), array('7.x-1.3', 'DRUPAL-SA-CONTRIB-2012-016 CVE-2012-1057 CVE-2012-1056')),

		'devel' => array(array('7.x-1.1', 'SA-CONTRIB-2011-030')),
		'taxonomy_filter' => array(array('7.x-1.x-dev', 'DRUPAL-SA-CONTRIB-2011-029')),
		'simpleclean' => array(array('7.x-1.3', 'DRUPAL-SA-CONTRIB-2011-028')),
		'facebookshare' => array(array('7.x-1.3', 'DRUPAL-SA-CONTRIB-2011-027')),
		'rate' => array(array('7.x-1.2', 'DRUPAL-SA-CONTRIB-2011-045')),
		'webform_civicrm' => array(array('7.x-2.2', 'DRUPAL-SA-CONTRIB-2011-055'), array('7.x-3.4', 'SA-CONTRIB-2012-161 CVE-2012-5554')),

		'ckeditor' => array(array('7.x-1.5', 'DRUPAL-SA-CONTRIB-2011-054'), array('7.x-1.7', 'DRUPAL-SA-CONTRIB-2012-040 CVE-2012-2066 CVE-2012-2067'),
						array('7.x-1.16', 'SA-CONTRIB-2014-098')),

		'og' => array(array('7.x-1.2', 'DRUPAL-SA-CONTRIB-2011-050'), array('7.x-1.5', 'SA-CONTRIB-2012-148 CVE-2012-5539'), array('7.x-2.4', 'SA-CONTRIB-2013-095 CVE-2013-7065 CVE-2013-7068'), array('7.x-2.7', 'SA-CONTRIB-2014-049')),

		'echo' => array(array('7.x-1.7', 'DRUPAL-SA-CONTRIB-2011-046')),
		'supercron' => array(array('abandoned', 'DRUPAL-SA-CONTRIB-2012-006 CVE-2012-1628')),
		'taxotouch' => array(array('abandoned', 'DRUPAL-SA-CONTRIB-2012-006 CVE-2012-1629')),
		'taxonomy_navigator' => array(array('abandoned', 'DRUPAL-SA-CONTRIB-2012-006 CVE-2012-1630')),
		'admin_hover' => array(array('abandoned', 'DRUPAL-SA-CONTRIB-2012-006 CVE-2012-1631')),
		'fillpdf' => array(array('7.x-1.2', 'DRUPAL-SA-CONTRIB-2012-003 CVE-2012-1625')),
		'metatags_quick' => array(array('7.x-2.3', 'DRUPAL-SA-CONTRIB-2011-059')),
		'webform_validation' => array(array('7.x-1.0', 'DRUPAL-SA-CONTRIB-2011-056'), array('7.x-1.4', 'SA-CONTRIB-2014-014')),

		'commerce' => array(array('7.x-1.2', 'DRUPAL-SA-CONTRIB-2012-014 CVE-2012-1639'), array('7.x-1.10', 'SA-CONTRIB-2014-087')),

		'search_autocomplete' => array(array('7.x-2.1', 'DRUPAL-SA-CONTRIB-2012-013 CVE-2012-1638')),
		'quicktabs' => array(array('7.x-3.3', 'DRUPAL-SA-CONTRIB-2012-012 CVE-2012-1637'), array('7.x-3.6', 'SA-CONTRIB-2013-078 CVE-2013-4406')),
		'stickynote' => array(array('7.x-1.1', 'DRUPAL-SA-CONTRIB-2012-010 CVE-2012-1636')),

		'revisioning' => array(array('7.x-1.3', 'DRUPAL-SA-CONTRIB-2012-009 CVE-2012-1635'), array('7.x-1.6', 'SA-CONTRIB-2013-090 CVE-2013-4597'), array('7.x-1.8', 'SA-CONTRIB-2014-039')),

		'video_filter' => array(array('7.x-3.0', 'DRUPAL-SA-CONTRIB-2012-008 CVE-2012-1634')),
		'mediafront' => array(array('7.x-1.5', 'DRUPAL-SA-CONTRIB-2012-024 CVE-2012-1647'), array('7.x-2.1', 'SA-CONTRIB-2013-074 CVE-2013-4380')),

		'cdn' => array(array('7.x-2.3', 'DRUPAL-SA-CONTRIB-2012-022 CVE-2012-1645')),
		'fp' => array(array('7.x-1.2', 'DRUPAL-SA-CONTRIB-2012-020 CVE-2012-1643')),
		'finder' => array(array('7.x-2.0-alpha8', 'DRUPAL-SA-CONTRIB-2012-017 CVE-2012-1641')),

		'slidebox' => array(array('7.x-1.4', 'SA-CONTRIB-2012-037 CVE-2012-2063'), array('7.x-2.x-dev', 'SA-CONTRIB-2012-037 CVE-2012-2063')),

		'content_lock' => array(array('7.x-1.2', 'SA-CONTRIB-2012-036 CVE-2012-2056'), array('7.x-2.0', 'SA-CONTRIB-2014-024')),


		'uc_bulk_stock_updater' => array(array('abandoned', 'SA-CONTRIB-2012-036 CVE-2012-2057')),
		'uc_payflowlink' => array(array('abandoned', 'SA-CONTRIB-2012-036 ')),
		'ticketyboo' => array(array('abandoned', 'SA-CONTRIB-2012-036 CVE-2012-2059')),
		'admintools' => array(array('abandoned', 'SA-CONTRIB-2012-036 CVE-2012-2060 CVE-2012-2061')),
		'bouncer' => array(array('abandoned', 'SA-CONTRIB-2012-036 CVE-2012-2062')),

		'block_class' => array(array('7.x-1.1', 'SA-CONTRIB-2012-032 CVE-2012-1657')),
		'bundle_copy' => array(array('7.x-1.1', 'SA-CONTRIB-2012-046 CVE-2012-2073')),
		'multiblock' => array(array('7.x-1.1', 'SA-CONTRIB-2012-043 CVE-2012-2070')),
		'wishlist' => array(array('7.x-2.6', 'SA-CONTRIB-2012-042 CVE-2012-2069')),

		'languageicons' => array(array('7.x-1.0', 'DRUPAL-SA-CONTRIB-2012-039 CVE-2012-2065')),
		'views_lang_switch' => array(array('7.x-1.2', 'SA-CONTRIB-2012-038 CVE-2012-2064')),
		'print' => array(array('7.x-1.0', 'SA-CONTRIB-2012-057 CVE-2012-2084')),
		'rpx' => array(array('7.x-2.2', 'SA-CONTRIB-2012-056 CVE-2012-2296')),
		'ctools' => array(array('7.x-1.0', 'SA-CONTRIB-2012-054 CVE-2012-2082'), array('7.x-1.4', 'SA-CONTRIB-2014-013')),

		'sharethis' => array(array('7.x-2.2', 'SA-CONTRIB-2012-049 CVE-2012-2076 CVE-2012-2077'), array('7.x-2.5', 'SA-CONTRIB-2012-155 CVE-2012-5545')),

		'linkit' => array(array('7.x-2.3', 'SA-CONTRIB-2012-067 CVE-2012-2304')),
		'ubercart' => array(array('7.x-3.1', 'SA-CONTRIB-2012-064 CVE-2012-2299 CVE-2012-2300 CVE-2012-2301'), array('7.x-3.4', 'SA-CONTRIB-2013-020 CVE-2013-0322'), array('7.x-3.6', 'SA-CONTRIB-2013-098 CVE-2013-7302'), array('7.x-3.7', 'SA-CONTRIB-2014-085'), array('7.x-3.8', 'SA-CONTRIB-2014-101')),

		'contact_forms' => array(array('7.x-1.3', 'SA-CONTRIB-2012-074 CVE-2012-2340')),
		'cctags' => array(array('7.x-1.10', 'SA-CONTRIB-2012-072 CVE-2012-2310')),

		'browserid' => array(array('7.x-1.3', 'SA-CONTRIB-2012-085 CVE-2012-2713 CVE-2012-2714')),
		'search_api' => array(array('7.x-1.1', 'SA-CONTRIB-2012-084 CVE-2012-2712'), array('7.x-1.3', 'SA-CONTRIB-2012-156 CVE-2012-5547'), array('7.x-1.4', 'SA-CONTRIB-2013-001 CVE-2013-0181')),

		'janrain_capture' => array(array('7.x-1.1', 'SA-CONTRIB-2012-098 CVE-2012-2727')),
		'protest' => array(array('7.x-1.2', 'SA-CONTRIB-2012-097 CVE-2012-2726')),
		'simplenews' => array(array('7.x-1.0-rc1', 'SA-CONTRIB-2012-095 CVE-2012-2724'), array('7.x-1.1', 'SA-CONTRIB-2013-080 CVE-2013-4447')),

		'maestro' => array(array('7.x-1.2', 'SA-CONTRIB-2012-094 CVE-2012-2723 CVE-2012-3799'), array('7.x-1.4', 'SA-CONTRIB-2014-021')),
		'node_embed' => array(array('7.x-1.0', 'SA-CONTRIB-2012-093 CVE-2012-2722')),

		'colorbox_node' => array(array('7.x-2.2', 'SA-CONTRIB-2012-110 CVE-2012-4474')),
		'restrict_node_page_view' => array(array('7.x-1.2', 'SA-CONTRIB-2012-109 CVE-2012-4473')),

		'hashcash' => array(array('7.x-2.2', 'SA-CONTRIB-2012-105 CVE-2012-4469')),
		'privatemsg' => array(array('7.x-1.3', 'SA-CONTRIB-2012-104 CVE-2012-4468')),
		'globalredirect' => array(array('7.x-1.4', 'SA-CONTRIB-2012-103 CVE-2012-2732')),

		'securelogin' => array(array('7.x-1.3', 'SA-CONTRIB-2012-118')),
		'location' => array(array('7.x-3.0-alpha1', 'SA-CONTRIB-2012-117')),
		'galleryformatter' => array(array('7.x-1.2', 'SA-CONTRIB-2012-115')),
		'security_questions' => array(array('7.x-1.1', 'SA-CONTRIB-2012-111 CVE-2012-4475')),

		'jstool' => array(array('7.x-1.7', 'SA-CONTRIB-2012-130')),
		'elegant_theme' => array(array('7.x-1.1', 'SA-CONTRIB-2012-128')),
		'ctools' => array(array('7.x-1.1', 'SA-CONTRIB-2012-125'), array('7.x-1.3', 'SA-CONTRIB-2013-041 CVE-2013-1925')),
		'better_revisions' => array(array('7.x-1.1', 'SA-CONTRIB-2012-122')),
		'shorten' => array(array('7.x-1.2', 'SA-CONTRIB-2012-121')),

		'pdfthumb' => array(array('7.x-1.1', 'SA-CONTRIB-2012-139 ')),
		'heartbeat' => array(array('7.x-1.1', 'SA-CONTRIB-2012-137 ')),
		'apachesolr_autocomplete' => array(array('7.x-1.3', 'SA-CONTRIB-2012-136 CVE-2012-6573')),
		'email' => array(array('7.x-1.2', 'SA-CONTRIB-2012-131 ')),


		'twitter_pull' => array(array('7.x-1.0-rc3', 'SA-CONTRIB-2012-150 CVE-2012-5541')),
		'hostip' => array(array('7.x-1.2', 'SA-CONTRIB-2012-149 CVE-2012-5540')),

		'filefield_sources' => array(array('7.x-1.6', 'SA-CONTRIB-2012-147 CVE-2012-5538'), array('7.x-1.9', 'SA-CONTRIB-2013-084 SA-CONTRIB-2013-084 CVE-2013-4502')),

		'fonecta_verify' => array(array('7.x-1.6', 'SA-CONTRIB-2012-144')),
		'spambot' => array(array('7.x-1.1', 'SA-CONTRIB-2012-142 CVE-2012-6582')),

		'om_maximenu' => array(array('7.x-1.44', 'SA-CONTRIB-2012-160 CVE-2012-5553')),
		'password_policy' => array(array('7.x-1.3', 'SA-CONTRIB-2012-159 CVE-2012-5552'), array('7.x-1.5', 'SA-CONTRIB-2013-069 CVE-2013-4274'), array('7.x-1.9', 'SA-CONTRIB-2014-070')),

		'mailchimp' => array(array('7.x-2.7', 'SA-CONTRIB-2012-158 CVE-2012-5551')),
		'time_spent' => array(array('unsupported', 'SA-CONTRIB-2012-157')),

		'mandrill' => array(array('7.x-1.2', 'SA-CONTRIB-2012-153 CVE-2012-5544')),
		'feeds' => array(array('7.x-2.0-alpha6', 'SA-CONTRIB-2012-152 CVE-2012-5543')),
		'multilink' => array(array('7.x-2.7', 'SA-CONTRIB-2012-170 CVE-2012-5589')),
		'services' => array(array('7.x-3.3', 'SA-CONTRIB-2012-168 CVE-2012-5586'), array('7.x-3.4', 'SA-CONTRIB-2013-051 CVE-2013-2158'), array('7.x-3.10', 'SA-CONTRIB-2014-092')),

		'user_readonly' => array(array('7.x-1.4', 'SA-CONTRIB-2012-163 CVE-2012-5557')),
		'restws' => array(array('7.x-1.1', 'SA-CONTRIB-2012-162 CVE-2012-5556'), array('7.x-1.2', 'SA-CONTRIB-2013-003 CVE-2013-0205'), array('7.x-1.3', 'SA-CONTRIB-2013-042 CVE-2013-1946'), array('7.x-2.1', 'SA-CONTRIB-2013-062 CVE-2013-4225')),

		'video' => array(array('7.x-2.9', 'SA-CONTRIB-2013-006 CVE-2013-0224')),
		'mark_complete' => array(array('7.x-1.1', 'SA-CONTRIB-2013-005 CVE-2013-0207')),
		'live_css' => array(array('7.x-2.7', 'SA-CONTRIB-2013-004 CVE-2013-0206')),

		'payment' => array(array('7.x-1.3', 'SA-CONTRIB-2013-002 CVE-2013-0182')),
		'context' => array(array('7.x-3.0-beta6', 'SA-CONTRIB-2012-174 CVE-2012-5655'), array('7.x-3.0', 'SA-CONTRIB-2013-079 CVE-2013-4445 CVE-2013-4446')),
		'zeropoint' => array(array('7.x-1.4', 'SA-CONTRIB-2012-172 CVE-2012-5591'), array('7.x-1.9', 'SA-CONTRIB-2013-036 CVE-2013-1905')),

		'banckle_live_chat' => array(array('unsupported', 'SA-CONTRIB-2013-016 CVE-2013-0318')),
		'og_manager_change' => array(array('7.x-2.1', 'SA-CONTRIB-2013-015 CVE-2013-0317')),
		'debuild' => array(array('unsupported', 'SA-CONTRIB-2013-014 CVE-2013-0260')),
		'boxes' => array(array('7.x-1.1', 'SA-CONTRIB-2013-013 CVE-2013-0259')),
		'ga_login' => array(array('7.x-1.3', 'SA-CONTRIB-2013-012 CVE-2013-0258'), array('7.x-1.4', 'SA-CONTRIB-2013-047 CVE-2013-4177 CVE-2013-4178')),

		'1097626' => array(array('7.x-1.4', 'SA-CONTRIB-2013-010 CVE-2013-0227')),
		'keyboard_shortcut' => array(array('7.x-1.1', 'SA-CONTRIB-2013-009 CVE-2013-0226')),
		'curvycorners' => array(array('unsupported', 'SA-CONTRIB-2013-008 CVE-2013-1393')),
		'user_relationships' => array(array('7.x-1.0-alpha5', 'SA-CONTRIB-2013-007 CVE-2013-0225')),

		'best_responsive' => array(array('7.x-1.1', 'SA-CONTRIB-2013-026 CVE-2013-1780')),
		'fresh' => array(array('7.x-1.4', 'SA-CONTRIB-2013-025 CVE-2013-1779')),
		'creative' => array(array('7.x-1.2', 'SA-CONTRIB-2013-024 CVE-2013-1778')),
		'menu_reference' => array(array('7.x-1.1', 'SA-CONTRIB-2013-022 CVE-2013-0324')),
		'ds' => array(array('7.x-1.7', 'SA-CONTRIB-2013-021 CVE-2013-0323'), array('7.x-2.3', 'SA-CONTRIB-2013-052 CVE-2013-2177')),

		'taxonomy_manager' => array(array('7.x-1.0-rc1', 'SA-CONTRIB-2013-018 CVE-2013-0320')),
		'yandex_metrics' => array(array('7.x-1.5', 'SA-CONTRIB-2013-017 CVE-2013-0319')),

		'views' => array(array('7.x-3.6', 'SA-CONTRIB-2013-035 CVE-2013-1887'), array('7.x-3.8', 'SA-CONTRIB-2014-054')),

		'corporate' => array(array('7.x-1.4', 'SA-CONTRIB-2013-033 CVE-2013-1787')),
		'company' => array(array('7.x-1.4', 'SA-CONTRIB-2013-032 CVE-2013-1786')),
		'responsive' => array(array('7.x-1.6', 'SA-CONTRIB-2013-031 CVE-2013-1785')),
		'clean_theme' => array(array('7.x-1.3', 'SA-CONTRIB-2013-030 CVE-2013-1784')),
		'business' => array(array('7.x-1.8', 'SA-CONTRIB-2013-029 CVE-2013-1783')),
		'responsive_blog' => array(array('7.x-1.6', 'SA-CONTRIB-2013-028 CVE-2013-1782')),

		'autocomplete_widgets' => array(array('7.x-1.0-rc1', 'SA-CONTRIB-2013-045 CVE-2013-1973')),
		'elfinder' => array(array('7.x-0.8', 'SA-CONTRIB-2013-044 CVE-2013-1972')),

		'commerce_moneybookers' => array(array('7.x-1.2', 'SA-CONTRIB-2013-040 CVE-2013-1924')),
		'commons_wikis' => array(array('7.x-3.1', 'SA-CONTRIB-2013-039 CVE-2013-1908')),
		'commons_groups' => array(array('7.x-3.1', 'SA-CONTRIB-2013-038 CVE-2013-1907')),
		'rules' => array(array('7.x-2.3', 'SA-CONTRIB-2013-037 CVE-2013-1906')),

		'stage_file_proxy' => array(array('7.x-1.4', 'SA-CONTRIB-2013-056 CVE-2013-4139')),
		'hatch' => array(array('7.x-1.4', 'SA-CONTRIB-2013-055 CVE-2013-4138')),
		'fpa' => array(array('7.x-2.3', 'SA-CONTRIB-2013-054 CVE-2013-2247')),
		'login_security' => array(array('7.x-1.3', 'SA-CONTRIB-2013-053 CVE-2013-2197 CVE-2013-2198')),

		'nodeaccess_userreference' => array(array('7.x-3.10', 'SA-CONTRIB-2013-049 CVE-2013-2123')),
		'edit_limit' => array(array('7.x-1.3', 'SA-CONTRIB-2013-048 CVE-2013-2122')),

		'monster_menus' => array(array('7.x-1.13', 'SA-CONTRIB-2013-066 CVE-2013-4229 CVE-2013-4230'), array('7.x-1.15', 'SA-CONTRIB-2013-086 CVE-2013-4504')),
		'persona' => array(array('7.x-1.11', 'SA-CONTRIB-2013-064 CVE-2013-4227')),
		'authcache' => array(array('7.x-1.5', 'SA-CONTRIB-2013-063 CVE-2013-4226')),

		'flippy' => array(array('7.x-1.2', 'SA-CONTRIB-2013-061 CVE-2013-4187')),
		'scald' => array(array('7.x-1.1', 'SA-CONTRIB-2013-060 CVE-2013-4174')),
		'mrbs' => array(array('abandoned', 'SA-CONTRIB-2013-058')),
		'tinybox' => array(array('7.x-2.2', 'SA-CONTRIB-2013-057 CVE-2013-4140')),

		'jquery_countdown' => array(array('7.x-1.1', 'SA-CONTRIB-2013-076 CVE-2013-4383')),

		'node_view_permissions' => array(array('7.x-1.2', 'SA-CONTRIB-2013-072 CVE-2013-4337')),
		'flag' => array(array('7.x-3.1', 'SA-CONTRIB-2013-071 CVE-2013-4336')),

		'entity' => array(array('7.x-1.2', 'SA-CONTRIB-2013-068 CVE-2013-4273')),
		'botcha' => array(array('7.x-3.3', 'SA-CONTRIB-2013-067 CVE-2013-4272')),

		'bean' => array(array('7.x-1.5', 'SA-CONTRIB-2013-082 CVE-2013-4499')),

		'gss' => array(array('7.x-1.10', 'SA-CONTRIB-2013-077 CVE-2013-4384')),

		'nodeaccesskeys' => array(array('7.x-1.1', 'SA-CONTRIB-2013-089 CVE-2013-4596'), array('7.x-1.2', 'SA-CONTRIB-2014-066')),
		'payment_webform' => array(array('7.x-1.5', 'SA-CONTRIB-2013-087 CVE-2013-4594')),

		'invitation' => array(array('7.x-2.2', 'SA-CONTRIB-2013-093 CVE-2013-7063')),
		'misery' => array(array('7.x-2.2', 'SA-CONTRIB-2013-092 CVE-2013-4599')),

		'gcc' => array(array('7.x-1.1', 'SA-CONTRIB-2013-091 CVE-2013-4598')),

		'leaflet' => array(array('7.x-1.1', 'SA-CONTRIB-2014-005')),
		'secure_cookie_data' => array(array('7.x-2.1', 'SA-CONTRIB-2014-004')),
		'dfp' => array(array('7.x-1.2', 'SA-CONTRIB-2014-003')),
		'anonymous_posting' => array(array('7.x-1.4', 'SA-CONTRIB-2014-002 CVE-2014-1611')),
		'entityreference' => array(array('7.x-1.1', 'SA-CONTRIB-2013-096 CVE-2013-7066')),

		'push_notifications' => array(array('7.x-1.1', 'SA-CONTRIB-2014-011')),
		'tribune' => array(array('unsupported', 'SA-CONTRIB-2014-008')),
		'lang_dropdown' => array(array('7.x-1.4', 'SA-CONTRIB-2014-006')),

		'openomega' => array(array('7.x-1.1', 'SA-CONTRIB-2014-025')),
		'content_lock' => array(),
		'slickgrid' => array(array('7.x-2.0', 'SA-CONTRIB-2014-022')),
		'commons' => array(array('7.x-3.9', 'SA-CONTRIB-2014-020'), array('7.x-3.10', 'SA-CONTRIB-2014-045')),
		'easy_social' => array(array('7.x-2.11', 'SA-CONTRIB-2014-019')),
		'image_resize_filter' => array(array('7.x-1.14', 'SA-CONTRIB-2014-017')),

		'cas' => array(array('7.x-1.3', 'SA-CONTRIB-2014-035')),
		'custom_search' => array(array('7.x-1.14', 'SA-CONTRIB-2014-034'), array('7.x-1.16', 'SA-CONTRIB-2014-043')),
		'nivo_slider' => array(array('7.x-1.11', 'SA-CONTRIB-2014-033')),
		'mimemail' => array(array('7.x-1.0-beta3', 'SA-CONTRIB-2014-029'), array('7.x-1.0-beta2', 'SA-CONTRIB-2014-026')),
		'masquerade' => array(array('7.x-1.0-rc6', 'SA-CONTRIB-2014-028')),
		'newsflash' => array(array('7.x-2.5', 'SA-CONTRIB-2014-027')),

		'professional_theme' => array(array('7.x-2.04', 'SA-CONTRIB-2014-044')),
		'i18n' => array(array('7.x-1.11', 'SA-CONTRIB-2014-042')),
		'skeletontheme' => array(array('7.x-1.4', 'SA-CONTRIB-2014-040')),
		'simplecorp' => array(array('7.x-1.1', 'SA-CONTRIB-2014-038')),
		'bluemasters' => array(array('7.x-2.1', 'SA-CONTRIB-2014-037')),

		'require_login' => array(array('7.x-1.1', 'SA-CONTRIB-2014-055')),
		'fate' => array(array('7.x-1.1', 'SA-CONTRIB-2014-053')),
		'addressfield_tokens' => array(array('7.x-1.4', 'SA-CONTRIB-2014-052'), array('7.x-1.5', 'SA-CONTRIB-2014-104')),
		'realname_registration' => array(array('7.x-2.0', 'SA-CONTRIB-2014-051')),
		'commerce_postfinance' => array(array('7.x-1.5', 'SA-CONTRIB-2014-050')),
		'fape' => array(array('7.x-1.2', 'SA-CONTRIB-2014-048')),
		'zen' => array(array('7.x-3.3', 'SA-CONTRIB-2014-047'), array('7.x-5.5', 'SA-CONTRIB-2014-047')),
		'context_form_alteration' => array(array('7.x-1.2', 'SA-CONTRIB-2014-046')),

		'custom_meta' => array(array('7.x-1.3', 'SA-CONTRIB-2014-065')),
		'course' => array(array('7.x-1.2', 'SA-CONTRIB-2014-064')),
		'videowhisper' => array(array('unsupported', 'SA-CONTRIB-2014-061 CVE-2014-2715')),
		'petitions' => array(array('7.x-1.2', 'SA-CONTRIB-2014-060')),
		'touch' => array(array('7.x-1.9', 'SA-CONTRIB-2014-059 CVE-2014-4303')),
		'webserver_auth' => array(array('7.x-1.4', 'SA-CONTRIB-2014-058 ')),

		'biblio_autocomplete' => array(array('7.x-1.5', 'SA-CONTRIB-2014-075 CVE-2014-5249 CVE-2014-5249 CVE-2014-5250 CVE-2014-5250')),
		'logintoboggan' => array(array('7.x-1.4', 'SA-CONTRIB-2014-069')),
		'pane' => array(array('7.x-2.5', 'SA-CONTRIB-2014-068')),

		'rules_link' => array(array('7.x-1.0-beta5', 'SA-CONTRIB-2014-084')),
		'marketo_ma' => array(array('7.x-1.5', 'SA-CONTRIB-2014-082')),
		'social_stats' => array(array('7.x-1.5', 'SA-CONTRIB-2014-080')),
		'notify' => array(array('7.x-1.1', 'SA-CONTRIB-2014-078')),
		'tablefield' => array(array('7.x-2.3', 'SA-CONTRIB-2014-077 ')),

		'safeword' => array(array('7.x-1.10', 'SA-CONTRIB-2014-095 ')),
		'twilio' => array(array('7.x-1.9', 'SA-CONTRIB-2014-093')),
		'survey_builder' => array(array('7.x-1.2', 'SA-CONTRIB-2014-091')),
		'speech' => array(array('unsupported', 'SA-CONTRIB-2014-090 ')),
		'geofield_ymap' => array(array('7.x-1.2', 'SA-CONTRIB-2014-089 ')),
		'custom_breadcrumbs' => array(array('7.x-2.0-beta1', 'SA-CONTRIB-2014-086 ')),

		'document' => array(array('7.x-1.21', 'SA-CONTRIB-2014-102 ')),
		'badbehavior' => array(array('7.x-2.2216', 'SA-CONTRIB-2014-100 ')),
		'oa_core' => array(array('7.x-2.22', 'SA-CONTRIB-2014-099 ')),
		'nodeaccess' => array(array('7.x-1.4', 'SA-CONTRIB-2014-097 ')),
		'oauth2_client' => array(array('7.x-1.2', 'SA-CONTRIB-2014-096 ')),


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
