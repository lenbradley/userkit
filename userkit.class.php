<?php

/**
* Create and manage users along with user meta
* Start by initializing: $userKit = new userKit();
*
* @package  userKit
* @author   Len Bradley <lenbradley@ninepshere.com>
* @version  2.0.0
* @link     http://www.ninesphere.com
* @license  http://www.php.net/license/3_01.txt PHP License 3.01
*
*/

class userKit {

    public $ID, $editUser, $dbh, $init;
    protected $config, $dbinfo, $phpass;

    public function __construct( $settings = array() ) {

        $settings = $this->getSettings( $settings );

        if ( $this->setupDatabaseHandler( $settings['dbh'] ) ) {

            $this->setupConfig( $settings['config'] );
            $this->setupDbInfo( $settings['dbinfo'] );
            $this->setupPHPass( $settings['phpass'] );

            $this->ID   = 0;
            $this->init = true;

            if ( isset( $_SESSION[$this->config->session_var_name] ) && $_SESSION[$this->config->session_var_name] != 0 ) {
                $this->ID = $_SESSION[$this->config->session_var_name];
                $this->setUserData( $this->ID );
            } else {
                $this->tryLoginFromCookie();
            }       
        } else {
            $this->outputErrorMessage( 'Cannot connect to database' );
            $this->init = false;
        }
    }

    public function debug( $data = null ) {
        if ( $data === null ) {
            $data = $this;
        }
        echo '<pre><code>' . print_r( $data, true ) . '</code></pre>';
    }

    public function outputErrorMessage( $message ) {
        echo '<p class="error">UserKit Error: ' . $message . '</p>';
    }

    public function editUser( $user = false ) {
        if ( $user == false ) {
            $this->editUser = $this->ID;
            return true;
        }

        $user = $this->userQuery( $user );

        if ( isset( $user['userid'] ) ) {
            $this->editUser = $user['userid'];            
            return true;
        } else {
            $this->editUser = 0;
            $this->error = 'The user specified to edit does not exist';
            return false;
        }
    }

    public function getUserToEdit() {
        if ( ! empty( $this->editUser ) ) {
            return $this->editUser;
        } else {
            return $this->ID;
        }
    }

    public function getSettings( $settings = array() ) {

        if ( empty( $settings ) ) {
            $config_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'userkit.config.php';

            if ( file_exists( $config_file ) ) {
                include $config_file;
            }
        }

        $defaults = array(
            'dbh' => array(
                'name' => '',
                'host' => '',
                'user' => '',
                'pass' => '',
            ),
            'dbinfo' => array(
                'prefix'                => '',
                'table_name'            => 'users',
                'colname_userid'        => 'userid',
                'colname_username'      => 'username',
                'colname_email'         => 'email',
                'colname_password'      => 'password',
                'meta_table_name'       => 'user_meta',
                'meta_colname_metaid'   => 'metaid',
                'meta_colname_userid'   => 'userid',
                'meta_colname_key'      => 'meta_key',
                'meta_colname_val'      => 'meta_value'
            ),
            'config' => array(
                'salt'                      => '3FiB|Mw`12yd=F3IB5[P`i>&Y|TFba3g2$++M5rR0Cd9}}N<}fu>?GQ2_9BM?Jb[',
                'delim'                     => 'Qo-ou3=*nr-}5\e2',
                'username_char_whitelist'   => '.-_!#^*+=|{}[]~<>?',
                'username_min_length'       => 3,
                'username_max_length'       => 16,
                'password_min_length'       => 8,
                'cookie_minutes_active'     => 129600, // 90 days
                'session_var_name'          => 'userkit_login'
            ),
            'phpass' => array(
                'itoa64'                => './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'portable_hashes'       => false,
                'iteration_count_log2'  => 8
            )
        );

        foreach ( $defaults as $key => $values ) {
            if ( is_array( $values ) ) {
                if ( isset( $settings[$key] ) ) {
                    $settings[$key] = array_merge( $values, $settings[$key] );
                } else {
                    $settings[$key] = $values;
                }
            } else {
                if ( isset( $settings[$key] ) ) {
                    $settings[$key] = $settings[$key];
                } else {
                    $settings[$key] = $values;
                }
            }
        }

        return $settings;
    }

    protected function setupConfig( $data = array() ) {
        $this->config = new stdClass();

        foreach ( $data as $key => $value ) {
            $this->config->{$key} = $value;
        }
    }

    protected function setupDbInfo( $data = array() ) {
        $this->dbinfo = new stdClass();

        foreach ( $data as $key => $value ) {
            $this->dbinfo->{$key} = $value;
        }
    }

    protected function setupPHPass( $data = array() ) {
        $this->phpass = new stdClass();

        foreach ( $data as $key => $value ) {
            $this->phpass->{$key} = $value;
        }
        
        $this->phpass->random_state = microtime();

        if ( function_exists( 'getmypid' ) ) {
            $this->phpass->random_state .= getmypid();
        }
    }    

    protected function setupDatabaseHandler( $dbh ) {

        if ( $dbh instanceof PDO ) {
            $this->dbh = $dbh;
        } else {

            try {                
                $this->dbh = new PDO( 'mysql:host=' . $dbh['host'] . ';dbname=' . $dbh['name'], $dbh['user'], $dbh['pass'] );
                $this->dbh->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
            } catch( PDOException $e ) {
                echo 'ERROR: ' . $e->getMessage();
            }
        }

        if ( $this->dbh ) {
            return true;
        } else {
            return false;
        }
    }

    public function login( $user, $pass, $remember = false ) {

        if ( $this->init == false ) {
            return false;
        }

        if ( empty( $user ) || empty( $pass ) ) {
            $this->error( 'Username/Password must be provided' );
            return false;
        }        
        
        if ( isset( $_SESSION[$this->config->session_var_name] ) ) {
            $this->error( 'You are already logged in!' );
            return false;
        }
        
        if ( $query = $this->userQuery( $user ) ) {
            
            if ( ( $this->checkPassword( $pass, $query['password'] ) ) ) {
                $this->setUserData( $query );

                $_SESSION[$this->config->session_var_name] = $query['userid'];
                
                if ( $remember == true ) {
                    $data = $this->secureCookieData( array( $query['userid'], $query['username'], $query['password'] ) );
                    setcookie( $this->config->session_var_name, $data, ( time() + ( 60 * $this->config->cookie_minutes_active ) ) );
                }
                return true;
            } else {
                $this->error = 'The password entered is incorrect!';
                return false;
            }
        } else {
            $this->error = 'Username and/or Email Address does not exist!';
            return false;
        }
    }

    public function tryLoginFromCookie() {
        if ( isset( $_COOKIE[$this->config->session_var_name] ) ) {
            $data   = $this->getData( $_COOKIE[$this->config->session_var_name] );
            $login  = $this->login( $data[1], $data[2], true, true );
            
            if ( ! $login ) {
                $this->error('Cookie is not valid');
                $this->logout();
            }
        }
    }

    public function logout( $redirect = '' ) {
        setcookie( $this->config->session_var_name, '', ( time() - 3600 ) );
        session_destroy();
        
        if ( $redirect != '' && ! headers_sent() ) {
            header( 'Location: ' . $redirect );
            exit();
        }

        return true;
    }

    public function isLoggedIn() {
        return ( $this->ID != 0 ) ? true : false;
    }

    public function addUser( $username, $email, $password, $meta = '' ) {

        if ( $this->init == false ) {
            return false;
        }

        if ( $this->isValidUsername( $username ) !== true ) {            
            $this->error = 'The username you entered is not valid';
            return false;
        }

        if ( !$this->isValidEmail( $email ) ) {            
            $this->error = 'The email address you entered is not valid';
            return false;
        }
        if ( !$this->isValidPassword( $password ) ) {            
            $this->error = 'Password does not meet minimum requirements';
            return false;
        }
        if ( $this->userExists( $username ) ) {            
            $this->error = 'The username already exists';
            return false;
        }
        if ( $this->userExists($email) ) {            
            $this->error = 'The email address is already taken';
            return false;
        }

        $pass = $this->hashPassword( $password );
        
        $query = $this->dbh->prepare(
            'INSERT INTO ' . $this->dbinfo->prefix . $this->dbinfo->table_name . '
            (
                ' . $this->dbinfo->colname_username . ',
                ' . $this->dbinfo->colname_email . ',
                ' . $this->dbinfo->colname_password . '
            ) VALUES (
                :username,
                :email,
                :pass
            )'
        );
        $query->bindParam( ':username', $username );
        $query->bindParam( ':email', $email );
        $query->bindParam( ':pass', $pass );

        if ( $query->execute() ) {
            $userid = $this->dbh->lastInsertId();
            
            if ( is_array( $meta ) && ! empty( $meta ) ) {
                $this->ID = $userid;
                
                foreach( $meta as $key => $value ) {
                    $this->addMeta( (string)$key, (string)$value );
                }
            }

            $this->ID = 0;
            return $userid;            
        } else {
            $this->error = 'A problem occured while creating new user';
            return false;
        }
    }

    public function updateEmail( $email = '' ) {
        $userid = $this->getUserToEdit();

        if ( $userid == 0 ) {
            $this->error = 'User to edit email address for is invalid';
            return false;
        }
    
        if ( ! $this->isValidEmail( $email ) ) {
            $this->error = 'Email address does not appear to be valid';
            return false;
        }
        
        if ( $this->userExists( $email ) ) {
            $this->error = 'The email address you entered is already in use';
            return false;
        }
        
        $update_query = '
            UPDATE ' . $this->dbinfo->prefix . $this->dbinfo->table_name . '
            SET ' . $this->dbinfo->colname_email . ' = :email
            WHERE ' . $this->dbinfo->colname_userid . ' = :userid';
            
        $query = $this->dbh->prepare( $update_query );
        $query->bindParam( ':userid', $userid );
        $query->bindParam( ':email', $email );
        
        if ( $query->execute() ) {
            $this->success('New email address has been set');
            return true;
        } else {
            $this->error('A problem occured while changing email address');
            return false;
        }
    }

    public function changePassword( $password = '', $remember = true ) {
        $userid = $this->getUserToEdit();

        if ( $userid == 0 ) {
            $this->error = 'User to edit password for is invalid';
            return false;
        }

        if ( $this->isValidPassword( $password ) ) {
            $pass       = $this->hashPassword( $password );
            $username   = $this->username;
            
            $update_query = '
                UPDATE ' . $this->dbinfo->prefix . $this->dbinfo->table_name . '
                SET ' . $this->dbinfo->colname_password . ' = :password
                WHERE ' . $this->dbinfo->colname_userid . ' = :userid';
                
            $query = $this->dbh->prepare( $update_query );
            $query->bindParam( ':userid', $userid );
            $query->bindParam( ':password', $password );
            
            if ( $query->execute() ) {
                $this->logout();
                $this->login( $username, $password, $remember );
                
                $this->success = 'New password is set';
                return true;
            } else {
                $this->error = 'Query could not be executed!';
                return false;
            }           
        } else {
            $this->error = 'New password is not valid';
            return false;
        }
    }

    public function meta( $key = '' ) {
        $userid = $this->getUserToEdit();

        if ( $userid == 0 ) {
            return '';
        }

        if ( $key == '' ) {         
            $query = $this->dbh->prepare('
                SELECT ' . $this->dbinfo->meta_colname_key . ', ' . $this->dbinfo->meta_colname_val . ' 
                FROM ' . $this->dbinfo->prefix . $this->dbinfo->meta_table_name . ' 
                WHERE   ' . $this->dbinfo->meta_colname_userid . ' = :userid');
            $query->bindParam( ':userid', $userid );
                            
            if ( $query->execute() ) {
                $return = array();
                
                while ( $row = $query->fetch( PDO::FETCH_ASSOC ) ) {
                    if ( $this->isJson( $row[$this->dbinfo->meta_colname_val] ) ) {
                        $row[$this->dbinfo->meta_colname_val] = json_decode( $row[$this->dbinfo->meta_colname_val] );
                    }
                    $return[$row[$this->dbinfo->meta_colname_key]] = $row[$this->dbinfo->meta_colname_val];
                }
                return $return;
            } else {
                return false;
            }
        } else {
            $key = strtolower( $key );
            
            $query = $this->dbh->prepare('
                SELECT ' . $this->dbinfo->meta_colname_val . ' 
                FROM ' . $this->dbinfo->prefix . $this->dbinfo->meta_table_name . ' 
                WHERE
                    ' . $this->dbinfo->meta_colname_userid . ' = :userid
                    AND LOWER(' . $this->dbinfo->meta_colname_key . ') = :key
                LIMIT 1');
            $query->bindParam( ':userid', $userid );
            $query->bindParam( ':key', $key );
            $query->execute();
            $result = $query->fetch( PDO::FETCH_ASSOC );
                
            if ( isset( $result[$this->dbinfo->meta_colname_val] ) ) {
                if ( $this->isJson( $result[$this->dbinfo->meta_colname_val] ) ) {
                    return json_decode( $result[$this->dbinfo->meta_colname_val] );
                } else {
                    return $result[$this->dbinfo->meta_colname_val];
                }
            } else {
                return false;
            }
        }
    }

    public function addMeta( $key = '', $val = '' ) {
        $userid = $this->getUserToEdit();

        if ( $userid == 0 || $key == '' || $val == '' ) {
            return false;
        }

        if ( is_array( $val ) ) {
            $val = json_encode( $val );
        }
        
        if ( $this->meta($key) ) {
            $this->error('Meta key already exists!');
            return false;
        }
        
        $insert_query = '
            INSERT INTO ' . $this->dbinfo->prefix . $this->dbinfo->meta_table_name . ' 
            (
                ' . $this->dbinfo->meta_colname_userid . ',
                ' . $this->dbinfo->meta_colname_key . ',
                ' . $this->dbinfo->meta_colname_val . '
            )
            VALUES
            (
                :userid,
                :key,
                :val
            )';
        
        $query = $this->dbh->prepare( $insert_query );
        $query->bindParam( ':userid', $userid );
        $query->bindParam( ':key', $key );
        $query->bindParam( ':val', $val );
        
        if ( $result = $query->execute() ) {
            return true;
        } else {
            $this->error('Meta query could not be executed!');
            return false;
        }
    }

    public function updateMeta( $key = '', $val = '' ) {
        $userid = $this->getUserToEdit();

        if ( $userid == 0 || $key == '' ) {
            return false;
        }

        if ( is_array( $val ) ) {
            $val = json_encode( $val );
        }
        
        $key_check = $this->meta( $key );
        
        if ( $key_check === false ) {
            return $this->addMeta( $key, $val );
        } else {
            $update_query = '
                UPDATE ' . $this->dbinfo->prefix . $this->dbinfo->meta_table_name . '
                SET ' . $this->dbinfo->meta_colname_val . ' = :value
                WHERE ' . $this->dbinfo->meta_colname_userid . ' = :userid
                AND ' . $this->dbinfo->meta_colname_key . ' = :key
            ';          
            
            $query = $this->dbh->prepare( $update_query );
            $query->bindParam( ':userid', $userid );
            $query->bindParam( ':key', $key );
            $query->bindParam( ':value', $val );            
            
            if ( $result = $query->execute() ) {            
                return true;
            } else {
                $this->error('Meta query could not be executed!');
                return false;
            }
        }
    }

    public function deleteMeta( $key = '' ) {
        $userid = $this->getUserToEdit();
    
        if ( $userid == 0 || $key == '' ) {
            return false;
        }
        
        $remove_query = '
            DELETE FROM ' . $this->dbinfo->prefix . $this->dbinfo->meta_table_name . ' 
            WHERE ' . $this->dbinfo->meta_colname_userid . ' = :userid
            AND ' . $this->dbinfo->meta_colname_key . ' = :key';
        
        $query = $this->dbh->prepare($remove_query);
        $query->bindParam( ':userid', $userid );
        $query->bindParam( ':key', $key );        
        
        if ( $result = $query->execute() ) {            
            return true;
        } else {
            $this->error('Query could not be executed!');
            return false;
        }
    }

    protected function secureCookieData( $data ) {
        if ( is_array( $data ) ) {
            $return = '';

            foreach( $data as $value ) {
                $return .= $value . $this->config->delim;
            }

            $data = preg_replace( '/' . $this->config->delim . '$/', '', $return );
        }

        return $this->encrypt( $data );
    }

    protected function getCookieData( $data ) {
        $data = explode( $this->config->delim, $this->decrypt($data) );
        return array_filter( $data );
    }

    protected function userQuery( $user = 0 ) {

        if ( $this->init == false ) {
            return false;
        }

        $user = strtolower( $user );      
        
        if ( ctype_digit( $user ) ) {
            $query = $this->dbh->prepare( 'SELECT * FROM ' . $this->dbinfo->prefix . $this->dbinfo->table_name . ' WHERE ' . $this->dbinfo->colname_userid . ' = :userid LIMIT 1' );
            $query->bindParam( ':userid', $user );
        } else {            
            $query = $this->dbh->prepare( 'SELECT * FROM ' . $this->dbinfo->prefix . $this->dbinfo->table_name . ' WHERE LOWER(' . $this->dbinfo->colname_username . ') = :username OR LOWER(' . $this->dbinfo->colname_email . ') = :email LIMIT 1' );
            $query->bindParam( ':username', $user );
            $query->bindParam( ':email', $user );
        }

        $query->execute();
        $result = $query->fetch( PDO::FETCH_ASSOC );
        
        return ( ! empty( $result ) ) ? $result : false;
    }

    protected function userExists( $user ) {

        if ( $this->init == false ) {
            return false;
        }

        $query = $this->userQuery( $user );
        return ( ! empty( $query ) ) ? true : false;
    }

    protected function setUserData( $data ) {

        if ( $this->init == false ) {
            return false;
        }
        
        if ( ! is_array( $data ) ) {
            $data = $this->userQuery( $data );
        }
        
        $this->ID           = ( ! empty( $data['userid'] ) ? $data['userid'] : 0 );
        $this->username     = ( ! empty( $data['username'] ) ? $data['username'] : '' );
        $this->email        = ( ! empty( $data['email'] ) ? $data['email'] : '' );
    }

    protected function isValidUsername( $username ) {
        $error = '';
        $allowed = str_split( $this->config->username_char_whitelist );
        
        if ( $this->isValidEmail( $username ) ) $error = 'Username cannot be an email address';
        if ( ! ctype_alnum( str_replace( $allowed, '', $username ) ) ) $error = 'Username contains illegal characters';
        if ( ctype_digit( $username ) ) $error = 'Username must not contain numbers only';
        if ( strlen( $username ) < $this->config->username_min_length ) $error = 'Username must be at least ' . $this->config->username_min_length . ' characters';
        if ( strlen( $username ) > $this->config->username_max_length ) $error = 'Username cannot exceed ' . $this->config->username_min_length . ' characters';
        
        if ( $error == '' ) {
            return true;
        } else {
            return $error;
        }
    }

    protected function isValidEmail( $email ) {
        if ( filter_var( $email, FILTER_VALIDATE_EMAIL ) && preg_match( '/@.+\./', $email ) ) {
            return true;
        } else {            
            return false;
        }
    }

    protected function isValidPassword( $password ) {
        if ( strlen( $password ) >= $this->config->password_min_length ) {
            return true;
        } else {            
            return false;
        }
    }

    protected function isJson( $data ) {
        if ( ( substr( $data, 0, 1 ) == '{' || substr( $data, 0, 1 ) == '[' ) && is_object( json_decode( $data ) ) ) {
            return true;
        } else {
            return false;
        }
    }

    protected function iv() {
        return substr( $this->config->salt, 0, mcrypt_get_iv_size( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC ) );
    }

    protected function encrypt( $data ) {
        return base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_128, substr( $this->config->salt, 0, 24 ), $data, MCRYPT_MODE_CBC, $this->iv() ) );
    }

    protected function decrypt( $data ) {
        return mcrypt_decrypt( MCRYPT_RIJNDAEL_128, substr( $this->config->salt, 0, 24 ), base64_decode( $data ), MCRYPT_MODE_CBC, $this->iv() );    
    }    

    protected function getRandomBytes( $count ) {
        $output = '';

        if ( is_readable( '/dev/urandom' ) && ( $fh = @fopen( '/dev/urandom', 'rb' ) ) ) {
            $output = fread( $fh, $count );
            fclose( $fh );
        }

        if ( strlen( $output ) < $count ) {
            $output = '';

            for ( $i = 0; $i < $count; $i += 16 ) {
                $this->phpass->random_state = md5( microtime() . $this->phpass->random_state );
                $output .= pack( 'H*', md5( $this->phpass->random_state ) );
            }
            $output = substr( $output, 0, $count );
        }

        return $output;
    }

    protected function encode64( $input, $count ) {
        $output = '';
        $i      = 0;

        do {
            $value = ord( $input[ $i++ ] );
            $output .= $this->phpass->itoa64[ $value & 0x3f ];

            if ( $i < $count ) {
                $value |= ord($input[$i]) << 8;
            }
                
            $output .= $this->phpass->itoa64[ ( $value >> 6 ) & 0x3f ];

            if ( $i++ >= $count ) {
                break;
            }
                
            if ( $i < $count ) {
                $value |= ord( $input[$i] ) << 16;
            }
                
            $output .= $this->phpass->itoa64[ ( $value >> 12 ) & 0x3f ];

            if ( $i++ >= $count ) {
                break;
            }
                
            $output .= $this->phpass->itoa64[ ( $value >> 18 ) & 0x3f ];

        } while ( $i < $count );

        return $output;
    }

    protected function generatePrivateSalt( $input ) {
        $output = '$P$';
        $output .= $this->phpass->itoa64[ min( $this->phpass->iteration_count_log2 + ( ( PHP_VERSION >= '5' ) ? 5 : 3 ), 30 ) ];
        $output .= $this->encode64( $input, 6 );

        return $output;
    }

    protected function cryptPrivate( $password, $setting ) {
        $output = '*0';

        if ( substr( $setting, 0, 2 ) == $output ) {
            $output = '*1';
        }

        $id = substr( $setting, 0, 3 );

        if ( $id != '$P$' && $id != '$H$' ) {
            return $output;
        }            

        $count_log2 = strpos( $this->phpass->itoa64, $setting[3] );

        if ( $count_log2 < 7 || $count_log2 > 30 ) {
            return $output;
        }            

        $count  = 1 << $count_log2;
        $salt   = substr( $setting, 4, 8 );

        if ( strlen( $salt ) != 8 ) {
            return $output;
        }
       
        if ( PHP_VERSION >= '5' ) {
            $hash = md5( $salt . $password, TRUE );

            do {
                $hash = md5( $hash . $password, TRUE );
            } while ( --$count );
        } else {
            $hash = pack( 'H*', md5( $salt . $password ) );

            do {
                $hash = pack( 'H*', md5( $hash . $password ) );
            } while ( --$count );
        }

        $output = substr( $setting, 0, 12 ) . $this->encode64( $hash, 16 );

        return $output;
    }

    protected function generateSaltExtended( $input ) {
        $count_log2 = min( $this->phpass->iteration_count_log2 + 8, 24 );
        $count      = ( 1 << $count_log2 ) - 1;
        $output     = '_';

        $output .= $this->phpass->itoa64[ $count & 0x3f ];
        $output .= $this->phpass->itoa64[ ( $count >> 6 ) & 0x3f ];
        $output .= $this->phpass->itoa64[ ( $count >> 12 ) & 0x3f ];
        $output .= $this->phpass->itoa64[ ( $count >> 18 ) & 0x3f ];
        $output .= $this->encode64( $input, 3 );

        return $output;
    }

    protected function generateSaltBlowfish( $input ) { 

        $output = '$2a$';
        $output .= chr( ord( '0' ) + $this->phpass->iteration_count_log2 / 10 );
        $output .= chr( ord( '0' ) + $this->phpass->iteration_count_log2 % 10 );
        $output .= '$';

        $i = 0;

        do {
            $c1 = ord( $input[$i++] );
            $output .= $this->phpass->itoa64[ $c1 >> 2 ];
            $c1 = ( $c1 & 0x03 ) << 4;

            if ( $i >= 16 ) {
                $output .= $this->phpass->itoa64[$c1];
                break;
            }

            $c2 = ord( $input[$i++] );
            $c1 |= $c2 >> 4;
            $output .= $this->phpass->itoa64[$c1];
            $c1 = ( $c2 & 0x0f ) << 2;

            $c2 = ord( $input[$i++] );
            $c1 |= $c2 >> 6;
            $output .= $this->phpass->itoa64[$c1];
            $output .= $this->phpass->itoa64[ $c2 & 0x3f ];
        } while ( 1 );

        return $output;
    }

    protected function hashPassword( $password ) {
        $random = '';

        if ( CRYPT_BLOWFISH == 1 && ! $this->phpass->portable_hashes ) {
            $random = $this->getRandomBytes(16);
            $hash   = crypt( $password, $this->generateSaltBlowfish( $random ) );

            if ( strlen( $hash ) == 60 ) {
                return $hash;
            }                
        }

        if ( CRYPT_EXT_DES == 1 && ! $this->phpass->portable_hashes ) {
            if ( strlen( $random ) < 3 ) {
                $random = $this->getRandomBytes(3);
            }
                
            $hash = crypt( $password, $this->generateSaltExtended( $random ) );

            if ( strlen( $hash ) == 20 ) {
                return $hash;
            }                
        }

        if ( strlen( $random ) < 6 ) {
            $random = $this->getRandomBytes(6);
        }
            
        $hash = $this->cryptPrivate( $password, $this->generatePrivateSalt( $random ) );

        if ( strlen( $hash ) == 34 ) {
            return $hash;
        }

        return '*';
    }

    protected function checkPassword( $password, $stored_hash ) {
        $hash = $this->cryptPrivate( $password, $stored_hash );

        if ( $hash[0] == '*' ) {
            $hash = crypt( $password, $stored_hash );
        }           

        return $hash == $stored_hash;
    }
}

?>