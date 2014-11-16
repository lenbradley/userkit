<?php
require dirname(__FILE__) . '/userkit.class.php';
$userKit = new userKit();

if ( $userKit->editUser( 2 ) ) {
    echo 'USER IS READY FOR EDIT!';
} else {
    echo 'USER DOES NOT EXIST FOR EDIT!';
}
$userKit->debug( $userKit );
?>