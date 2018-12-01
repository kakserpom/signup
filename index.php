<?php
define('R', $_SERVER['DOCUMENT_ROOT']);
define('ACCESS', TRUE);
include_once R . "/system/init.php";


switch ($act) {
    case 'ref':
        setcookie("referal", $_GET['id'], time() + 60 * 60 * 24 * 30 * 24, '/');
        header("Location: " . HOME . '/login/signup/');
        break;
    case 'exit':
        if (isset($userdata)) {
            $sql = "UPDATE users SET user_ip=0 WHERE user_id = ?s";
            $db->query($sql, $userdata['user_id']);
            setcookie("id", $userdata['user_id'], time() - 60 * 60 * 24 * 30, '/');
            setcookie("hash", $userdata['user_hash'], time() - 60 * 60 * 24 * 30, '/');
        }
        header("Location: /");
        exit();
        break;
    case 'forgot':
        if (isset($_GET['code'])) {
            if ($_GET['code'] == '0') {
                header("Location: /");
                return;
            }
            $cod = isValidMd5($_GET['code']);
            if ($cod == 1) {
                $use = $db->getRow("SELECT * FROM `users` WHERE `forgotten` = ?s LIMIT 1", $_GET['code']);
            }
            if (!isset($use['user_login'])) {
                header("Location: /");
                return;
            }
            if (isset($_POST['pass'])) {
                $sql = "UPDATE users SET user_password = ?s, forgotten=0 WHERE user_id = ?i";
                $db->query($sql, md5(md5($_POST['pass'])), $use['user_id']);
                Send_Mail($use['user_login'], 'Новый пароль ' . $_SERVER['HTTP_HOST'], $use['user_name'] . ", Вы успешно воспользовались процедурой восстановления пароля.\nВаш логин: " . $use['user_login'] . "\nВаш новый пароль: " . $_POST['pass']);
                $msg->success(__("saved_password"), "/login");
            }
            $options['title'] = __('Восстановление пароля');
            $options['h1'] = __('Восстановление пароля');
            $tpl->getHead($options);
            $tpl->getPage('forms/forgot2', $options);
            $tpl->getFoot($options);
        } else {
            if (isset($_POST['email'])) {
                if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
                    $msg->error(__("Формат email неверен"), '/login/forgot');
                }
                $use = $db->getRow("SELECT * FROM `users` WHERE `user_login` = ?s", $_POST['email']);
                if (isset($use['user_login'])) {
                    $use['forgotten'] = md5($use['user_login'] . time());
                    $code = "http://" . $_SERVER['HTTP_HOST'] . "/login/forgot/" . $use['forgotten'];


                    Send_Mail($use['user_login'], 'Восстановление пароля ' . $_SERVER['HTTP_HOST'], $use['user_name'] . ", вы забыли пароль?\nЧтобы назначить новый пароль перейдите по ссылке \n" . $code . "\nВаш логин: " . $use['user_login'] . " \n");


                    $sql = "UPDATE users SET forgotten=?s WHERE user_id = ?s";
                    $db->query($sql, $use['forgotten'], $use['user_id']);
                    $msg->success(__("success_restore_message"), "/login/forgot");
                } else {
                    $msg->error(__("Юзера с такими данными нет в системе."));
                }
            }
            $options['title'] = __('Восстановление пароля');

            $options['h1'] = __('Восстановление пароля');
            $tpl->getHead($options);
            $tpl->getPage('forms/forgot', $options);
            $tpl->getFoot($options);
        }

        break;
    case 'check':
        if (isset($_GET['code'])) {
            $use = $db->getRow("SELECT * FROM `users` WHERE `activation` = ?s and `status` = '0'", $_GET['code']);
            if ($_GET['code'] == $use['activation']) {
                $sql = "UPDATE users SET status = '1' WHERE user_id = ?i";
                $db->query($sql, $use['user_id']);
                if (!isset($userdata)) {
                    $msg->success(__('Ваш еmail адрес успешно подтвержден!'), '/login');
                } else {
                    $msg->success(__('Ваш еmail адрес успешно подтвержден!'), '/cabinet');
                }
            }
        }
        if (!isset($userdata)) {
            header('Location: /');
        } else {
            if ($userdata['status'] == '1') {
                $msg->success(__('Добро пожаловать') . ', ' . $userdata['user_name'] . '!', '/cabinet/refback');
            }
        }
        $options['title'] = __('Подтверждение аккаунта');
        $options['h1'] = __('Подтверждение аккаунта');
        $tpl->getHead($options);
        $tpl->getPage('forms/check', $options);
        $tpl->getFoot($options);
        break;
    case 'signin':
        $options['title'] = __('Авторизация');
        $options['h1'] = __('Авторизация');
        if (isset($userdata)) {
            header('Location: /cabinet/');
        }
        if (isset($_POST['submit'])) {
            if (!preg_match("/^([a-z0-9_-]+\.)*[a-z0-9_-]+@[a-z0-9_-]+(\.[a-z0-9_-]+)*\.[a-z]{2,6}$/", $_POST['login'])) {
                $msg->error(__('login_error'), '/login/');
            }
            if (!filter_var($_POST['login'], FILTER_VALIDATE_EMAIL)) {
                $msg->error(__("Формат email неверен"), '/login/');
            }
            $data = $db->getRow("SELECT * FROM users WHERE user_login = ?s", $_POST['login']);
            if ($data['user_password'] === md5(md5($_POST['password']))) {
                $user = array(
                    "user_hash" => md5(generateCode(10)),
                );
                if (!@$_POST['not_attach_ip']) {
                    $ip = $_SERVER['REMOTE_ADDR'];
                } else {
                    $ip = 0;
                }
                $allowed = array('user_hash');
                $datas = $db->filterArray($user, $allowed);
                $sql = "UPDATE users SET ?u, user_ip=inet_aton(?s) WHERE user_id = ?s";
                $db->query($sql, $datas, $ip, $data['user_id']);
                # Ставим куки
                setcookie("id", $data['user_id'], time() + 60 * 60 * 24 * 30, '/');
                setcookie("hash", $user['user_hash'], time() + 60 * 60 * 24 * 30, '/');
                # Переадресовываем браузер на страницу проверки нашего скрипта
                header("Location: /check");
                exit();
            } else {
                $msg->error(__("wrong password"));
            }
        }
        $tpl->getHead($options);
        $tpl->getPage('forms/signin', $options);
        $tpl->getFoot($options);
        break;
    case 'signup':
        $options['title'] = __('Регистрация');
        $options['h1'] = __('Регистрация');

        if (isset($userdata)) {
            header('Location: /cabinet/');
        }
        if (isset($_POST['submit'])) {
            $err = array();
            # проверям логин
            if (!preg_match("~^[a-zA-Zа-яА-Я0-9-_]+[\s]{0,1}[a-zA-Zа-яА-Я0-9-_]*$~", $_POST['name'])) {
                $msg->error(__('login_error'), '/login/signup');
            }
            if (check_black($_POST['login'])) {
                $msg->error(__('mail_error'), '/login/signup');
            }


            if (!filter_var($_POST['login'], FILTER_VALIDATE_EMAIL)) {
                $msg->error(__("Формат email неверен"), '/login/signup');
            }
            if (strlen($_POST['login']) < 5 or strlen($_POST['login']) > 250) {
                $msg->error(__('login_error'), '/login/signup');
            }
            if (strlen($_POST['name']) < 3 or strlen($_POST['name']) > 50) {
                $msg->error(__('login_error'), '/login/signup');
            }

            # проверяем, не сущестует ли пользователя с таким именем
            $ids = $db->getCol("SELECT COUNT(user_id) FROM users WHERE user_login = ?s", $_POST['login']);
            if ($ids[0] > 0) {
                $msg->error(__("user_exists"), '/login/signup');
            }
            # проверяем, не сущестует ли пользователя с таким именем
            $ids = $db->getCol("SELECT COUNT(user_id) FROM users WHERE user_name = ?s", $_POST['name']);
            if ($ids[0] > 0) {
                $msg->error(__("user_exists"), '/login/signup');
            }


            # Если нет ошибок, то добавляем в БД нового пользователя
            if (count($err) == 0) {
                $user = array(
                    "user_name" => $_POST['name'],
                    "user_login" => $_POST['login'],
                    "user_password" => md5(md5(trim($_POST['password']))),
                    "referal" => isset($_COOKIE['referal']) ? $_COOKIE['referal'] : 0,
                );
                $user['activation'] = md5($user['user_login'] . time());
                $allowed = array('user_login', 'user_name', 'user_password', 'activation', 'referal');
                $data = $db->filterArray($user, $allowed);
                $sql = "INSERT INTO users SET ?u";
                $db->query($sql, $data);
                $code = "http://" . $_SERVER['HTTP_HOST'] . "/check/" . $user['activation'];
                Send_Mail($user['user_login'], 'Регистрация на ' . $_SERVER['HTTP_HOST'], $user['user_name'] . ", cпасибо за регистрацию, Ваши данные для входа:\nЛогин: " . $user['user_login'] . "\nПароль: " . $_POST['password'] . "\nЧтобы активировать аккаунт, перейдите по ссылке:\n" . $code);
                $msg->success(__("register_message_success"), "/login");
                exit();
            }
        }
        $tpl->getHead($options);
        $tpl->getPage('forms/signup', $options);
        $tpl->getFoot($options);
        break;
    default:
        if (isset($userdata)) {
            header('Location: /cabinet/');
            return;
        }
        $options['title'] = __('Офис | GodfatherBlog');
        $tpl->getHead($options);
        $tpl->getPage('index', $options);
        $tpl->getFoot($options);
        break;
}
