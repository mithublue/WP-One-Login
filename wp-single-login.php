<?php
/*
Plugin Name: WP One Login by Cybercraft Technologies
Plugin URI: ''
Description: Prevents multiple/concurrent login in different machines
Version: 0.1
Author: Mithu A Quayium
Author URI: http://www.cybercraftit.com
License: GPLv2 or later
Text Domain: wpsl
*/

class wpsl_init {

    public function __construct() {
        add_action( 'init' , array( $this, 'make_single_login') );
    }


    public function make_single_login() {
        $this->destroy_others( wp_get_session_token() );
    }



    /**
     * Hashes a session token for storage.
     *
     * @access private
     *
     * @param string $token Session token to hash.
     * @return string A hash of the session token (a verifier).
     */
    final private function hash_token( $token ) {
        // If ext/hash is not present, use sha1() instead.
        if ( function_exists( 'hash' ) ) {
            return hash( 'sha256', $token );
        } else {
            return sha1( $token );
        }
    }


    /**
     * Converts an expiration to an array of session information.
     *
     * @param mixed $session Session or expiration.
     * @return array Session.
     */
    protected function prepare_session( $session ) {
        if ( is_int( $session ) ) {
            return array( 'expiration' => $session );
        }

        return $session;
    }


    /**
     * Determine whether a session token is still valid,
     * based on expiration.
     *
     * @since 4.0.0
     * @access protected
     *
     * @param array $session Session to check.
     * @return bool Whether session is valid.
     */
    final protected function is_still_valid( $session ) {
        return $session['expiration'] >= time();
    }


    /**
     * Get all sessions of a user.
     *
     * @access protected
     *
     * @return array Sessions of a user.
     */
    protected function get_sessions() {
        $sessions = get_user_meta( get_current_user_id(), 'session_tokens', true );

        if ( ! is_array( $sessions ) ) {
            return array();
        }

        $sessions = array_map( array( $this, 'prepare_session' ), $sessions );
        return array_filter( $sessions, array( $this, 'is_still_valid' ) );
    }


    /**
     * Retrieve a session by its verifier (token hash).
     *
     * @access protected
     *
     * @param string $verifier Verifier of the session to retrieve.
     * @return array|null The session, or null if it does not exist
     */
    protected function get_session( $verifier ) {
        $sessions = $this->get_sessions();

        if ( isset( $sessions[ $verifier ] ) ) {
            return $sessions[ $verifier ];
        }

        return null;
    }


    /**
     * Destroy all session tokens for a user.
     *
     * @access protected
     */
    protected function destroy_all_sessions() {
        $this->update_sessions( array() );
    }


    /**
     * Destroy all session tokens for this user,
     * except a single token, presumably the one in use.
     *
     * @access public
     *
     * @param string $token_to_keep Session token to keep.
     */
    final public function destroy_others( $token_to_keep ) {
        $verifier = $this->hash_token( $token_to_keep );
        $session = $this->get_session( $verifier );
        if ( $session ) {
            $this->destroy_other_sessions( $verifier );
        } else {
            $this->destroy_all_sessions();
        }
    }


    /**
     * Update a user's sessions in the usermeta table.
     *
     * @access protected
     *
     * @param array $sessions Sessions.
     */
    protected function update_sessions( $sessions ) {
        if ( $sessions ) {
            update_user_meta( get_current_user_id(), 'session_tokens', $sessions );
        } else {
            delete_user_meta( get_current_user_id(), 'session_tokens' );
        }
    }



    /**
     * Destroy all session tokens for a user, except a single session passed.
     *
     * @access protected
     *
     * @param string $verifier Verifier of the session to keep.
     */
    protected function destroy_other_sessions( $verifier ) {
        $session = $this->get_session( $verifier );
        $this->update_sessions( array( $verifier => $session ) );
    }



    public static function init() {
        new wpsl_init();
    }
}

wpsl_init::init();