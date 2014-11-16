<?php require dirname( dirname(__FILE__) ) . DIRECTORY_SEPARATOR . 'userkit.setup.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>UserKit Setup</title>
    <link rel="stylesheet" href="<?php echo $path; ?>style.css">
</head>
<body>
    <h1>UserKit Database Setup</h1>

    <?php if ( ! empty( $success_message ) ) : ?>
    <ul class="message success">
        <?php foreach ( $success_message as $message ) : ?>
        <li><?php echo $message; ?></li>
        <?php endforeach; ?>
    </ul>
    <?php endif; ?>

    <?php if ( ! empty( $error_message ) ) : ?>
    <ul class="message error">
        <?php foreach ( $error_message as $message ) : ?>
        <li><?php echo $message; ?></li>
        <?php endforeach; ?>
    </ul>
    <?php endif; ?>

    <form action="" method="post">
        <input type="hidden" name="create_database">
        <input type="submit" value="Create Database">
    </form>
</body>
</html>