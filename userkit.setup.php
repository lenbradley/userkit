<?php

require dirname(__FILE__) . DIRECTORY_SEPARATOR . 'userkit.class.php';

$error_message      = array();
$success_message    = array();

if ( $userkit = new userKit() ) {
    $settings = $userkit->getSettings();

    if ( isset( $_POST['create_database'] ) ) {

        $check_user_table_exists = $userkit->dbh->query( "SHOW TABLES LIKE '" . $settings['dbinfo']['prefix'] . $settings['dbinfo']['table_name'] . "'" );

        if ( $check_user_table_exists->rowCount() < 1 ) {

            $create_user_table_query = "
                CREATE TABLE IF NOT EXISTS `" . $settings['dbinfo']['prefix'] . $settings['dbinfo']['table_name'] . "` (
                `" . $settings['dbinfo']['colname_userid'] . "` int(10) NOT NULL AUTO_INCREMENT,
                `" . $settings['dbinfo']['colname_username'] . "` varchar(64) NOT NULL,
                `" . $settings['dbinfo']['colname_email'] . "` varchar(128) NOT NULL,
                `" . $settings['dbinfo']['colname_password'] . "` varchar(128) NOT NULL,
                `joindate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`" . $settings['dbinfo']['colname_userid'] . "`),
                UNIQUE KEY `" . $settings['dbinfo']['colname_userid'] . "` (`" . $settings['dbinfo']['colname_userid'] . "`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1";

            if ( $userkit->dbh->query( $create_user_table_query ) ) {
                $success_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['table_name'] . ' has been successfully created!';
            } else {
                $error_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['table_name'] . ' could not be created!';
            }
        } else {
            $error_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['table_name'] . ' already exists!';
        }

        $check_user_meta_table_exists = $userkit->dbh->query( "SHOW TABLES LIKE '" . $settings['dbinfo']['prefix'] . $settings['dbinfo']['meta_table_name'] . "'" );

        if ( $check_user_meta_table_exists->rowCount() < 1 ) {

            $create_user_meta_table_query = "
            CREATE TABLE IF NOT EXISTS `" . $settings['dbinfo']['prefix'] . $settings['dbinfo']['meta_table_name'] . "` (
                `" . $settings['dbinfo']['meta_colname_metaid'] . "` int(10) NOT NULL AUTO_INCREMENT,
                `" . $settings['dbinfo']['meta_colname_userid'] . "` int(10) NOT NULL,
                `" . $settings['dbinfo']['meta_colname_key'] . "` varchar(255) NOT NULL,
                `" . $settings['dbinfo']['meta_colname_val'] . "` longtext NOT NULL,
                PRIMARY KEY (`" . $settings['dbinfo']['meta_colname_metaid'] . "`),
                UNIQUE KEY `" . $settings['dbinfo']['meta_colname_metaid'] . "` (`" . $settings['dbinfo']['meta_colname_metaid'] . "`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1";

            if ( $userkit->dbh->query( $create_user_meta_table_query ) ) {
                $success_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['meta_table_name'] . ' has been successfully created!';
            } else {
                $error_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['meta_table_name'] . ' could not be created!';
            }
        } else {
            $error_message[] = $settings['dbinfo']['prefix'] . $settings['dbinfo']['meta_table_name'] . ' already exists!';
        }
    }
} else {
    $error_message[] = 'UserKit was not initiated. Check configuration and try again.';
}

if ( ! empty( $error_message ) && ! is_array( $error_message ) ) {
    $error_message[] = $error_message;
}

if ( ! empty( $success_message ) && ! is_array( $success_message ) ) {
    $success_message[] = $success_message;
}

?>
