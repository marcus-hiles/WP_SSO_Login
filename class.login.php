<?php

class WP_IMIS_SSO {

	private static $instance;
	public  $user;
	public  $imis;
	public  $chapter;
	public  $wordpress;

	function __construct( ) {
		 $this->user = new WP_IMIS_SSO\User;
		 $this->imis = new WP_IMIS_SSO\IMIS;
		 $this->chapter = new WP_IMIS_SSO\Chapter;
		 $this->wordpress = new WP_IMIS_SSO\WordPress;
	}


	public static function get_instance() {

		 if ( ! isset( self::$instance ) ) {
			 self::$instance = new WP_IMIS_SSO();
			 self::$instance->add_hooks();
		 }
		 
		 return self::$instance;
	}


	public function add_hooks() {

		add_action('plugins_loaded', function(){
			add_filter( 'authenticate', array( $this, 'custom_login' ), 25, 3 );
			add_filter( 'wp_logout', array( $this->imis, 'logout_imis' ) );
			add_filter( 'wp_logout', array( $this->wordpress, 'logout_redirect' ) );
			add_filter( 'login_redirect', array( $this->wordpress, 'login_redirect' ), 10, 3 );
			add_filter( 'login_form',  array( $this->wordpress,  'login_form_acc' ), 99 );
			add_action( 'login_form_lostpassword', array( $this->wordpress, 'custom_lostpassword' ) );
			add_action( 'wp_login_failed', array( $this->wordpress, 'login_fail_redirect' ) );
		});

		add_action('init', array( $this, 'check_auth_imis' ));
	}


	public function custom_login( $user, $user_login, $user_password ) {

		/*
		* Bail if username is empty
		*/
		if( empty($user_login) ){
			return $user;
		}

		/*
		* Error for empty password
		*/
		if( empty($user_password) ){
			return new WP_Error('failed', 'Enter username and password' );
		}

		/*
		* Skip the custom login if not an IMIS user. 
		* The user must be an admin
		*/
		if ( isset( $_REQUEST['not_imis_user'] ) && $_REQUEST['not_imis_user'] == 'on' ) {

			if ( is_wp_error( $user ) ){
				return $user;
			}
			
			if( $user->exists() && $user->has_cap( 'administrator' ) ) {
				return $user;
			}

			return new WP_Error( 'failed', 'Sorry, you must be a site administrator to use this feature' );
		}

		/*
		* Fetch the IMIS ID from the login credentials
		*/
		try {
			$imis_id = $this->imis->getIdFromLoginAPI($user_login, $user_password, $user);
		}
		catch( Exception $e ){
			error_log("ERROR getIdFromLoginAPI: ". $e->getMessage() );
			return new WP_Error('failed', $e->getMessage() . ' (Error 100) ' );
		}

		/*
		* Fetch the IMIS Data from the ID
		*/
		try {
			$userData = $this->imis->getUserInfoFromAPI( $imis_id );

			$this->user->setUserData( $userData );

			delete_transient( 'imis_user_' .$imis_id );
			set_transient( 'imis_user_' .$imis_id, $this->user->getUserInfo(), 1 * HOUR_IN_SECONDS );
		}
		catch( Exception $e ){
			error_log("ERROR getUserInfoFromAPI: ". $e->getMessage() );
			return new WP_Error('failed', $e->getMessage() );
		}

		$wpUser = new WP_User(  $this->wordpress->getUserID( $this->user->getUserInfo('email') ) );

		/*
		* Update user meta if last update is different
		*/
		if($this->wordpress->check_if_should_update_info( $wpUser->ID, $userData ) ){
		 	$this->wordpress->update_existing_user_data( $wpUser->ID, $this->user->getUserInfo(), $this->chapter );
		}

		/*
		* Create new user if one does not already exist
		*/
		if( ! $wpUser->exists() ) {

			try {

				$this->wordpress->create_new_wp_user( 
					$user_login, 
					wp_generate_password(), 
					$this->user->getUserInfo() 
				);

				$wpUser = new WP_User(  $this->wordpress->getUserID( $this->user->getUserInfo('email') ) );

			}catch( Exception $e ){
				error_log("ERROR create_new_wp_user: ". $e->getMessage() );
				return new WP_Error('failed', $e->getMessage() );
			}
		}

		/*
		* Logs into rise and sets IMIS cookie
		*/
		try {
			$ImisCookie = $this->imis->loginToRiseAPI( $user_login, $user_password, $wpUser );
			$this->imis->addImisCookie( $ImisCookie );
		}
		catch ( Exception $e ){
			return new WP_Error('failed', $e->getMessage() );
		}

		return $wpUser;		
	}



	public function check_auth_imis(){

		$is_logged_in = is_user_logged_in();

		/*
		* Skip this if coming from wp-login
		*/
		if( isset( $_REQUEST['wp-submit'] ) && $_REQUEST['wp-submit'] == 'Log In') {
			return;
		}

		/*
		* Skip this if coming from logging out
		*/
		if( isset( $_REQUEST['action'] ) && $_REQUEST['action'] == 'logout') {
			return;
		}
		
		/*
		* Skip this if user is logged in as administrator
		*/
		if( $is_logged_in && current_user_can( 'administrator' ) ) {
			return;
		}

		$login_cookie = isset($_COOKIE["Login"]) ? $_COOKIE["Login"] : false;

		/*
		* If there is no 'Login' cookie, and user is logged into WP, sign them out
		*/
		if( ! $login_cookie ) {

			if( $is_logged_in ){				
				$this->wordpress->logout_wp();
			}

			return;
		}

		/*
		* There is a 'Login' cookie
		*/
		if( $login_cookie ){

			/*
			* get logged in user from IMIS via cookie
			* returns the imis username
			*/
			$loggedinUser = $this->imis->getLoggedinUserRise( 
				array( new WP_Http_Cookie( array( 'name' => 'Login', 'value' => $login_cookie ) ) ) 
			);

			/*
			* Try to setup WP_User object based on imis username
			*/
			$wpUser = new WP_User( $this->wordpress->getUserID( $loggedinUser ) );

			/*
			* They are logged into IMIS, but not a WP user yet. Disregard until they try to login
			*/
			if( ! $wpUser || ! $wpUser->exists() ){
				return;
			}

			/*
			* The IMIS user does not match the logged in user.
			*/
			$logged_in_as = new WP_User ( get_current_user_id() );

			if( $wpUser->ID != $logged_in_as->ID ) {
				$this->wordpress->logout_wp();
			}

			/*
			* Setup the user info from IMIS
			* First, looks for transient from recent login
			* If no transient, fetches from IMIS API
			*/
			try{
				$from_imis = false;

				if ( false === ( $user = get_transient( 'imis_user_' .$wpUser->imis_id  ) ) ) {
					$from_imis = true;
					$user = $this->imis->getUserInfoFromAPI( $wpUser->imis_id  );
				}

				$userData = $this->user->setUserData( $user, $from_imis );
			}catch( Exception $e ){
				error_log("ERROR getUserInfoFromAPI: ". $e->getMessage() );
				return new WP_Error('failed', $e->getMessage() );
			}
	
			/*
			* Update user meta if last update is different
			*/
			if($this->wordpress->check_if_should_update_info( $wpUser->ID, $userData ) ){
				$this->wordpress->update_existing_user_data( $wpUser->ID, $userData, $this->chapter );
			}

			/*
			* If not logged-in by this time, log them in
			*/
			if( ! $is_logged_in ) {
				$this->wordpress->login_wp( $wpUser );
				wp_redirect('/?logged-in');
				exit();
			}
		}
	}

} // WP_IMIS_SSO
