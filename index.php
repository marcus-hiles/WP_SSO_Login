<?php
/**
 * @package WP SSO Login
 */
/*
Plugin Name: WP SSO Login
Plugin URI: https://www.marcus-hiles.com
Description: SSO for WordPress and IMIS
Version: 4.0.3
Author: Marcus Hiles
Author URI: https://www.marcus-hiles.com
License: GPLv2 or later
*/

if ( !function_exists( 'add_action' ) ) {
	exit;
}

define( 'WP_SSO_IMIS', plugin_dir_path( __FILE__ ) );

/*
require_once( WP_SSO_IMIS . 'class.user.php' );
require_once( WP_SSO_IMIS . 'class.chapter.php' );
require_once( WP_SSO_IMIS . 'class.login.php' );
require_once( WP_SSO_IMIS . 'class.wordpress.php' );
require_once( WP_SSO_IMIS . 'class.imis.php' );
*/

if ( class_exists( 'WP_IMIS_SSO' ) ) {
	$GLOBALS['wpimis'] = WP_IMIS_SSO::get_instance();
}
