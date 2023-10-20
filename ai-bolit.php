<?php

ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');

define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль

define('PASS', '????????????????');

//////////////////////////////////////////////////////////////////////////
$vars = new Variables();

if (isCli()) {
    if (strpos('--eng', $argv[$argc - 1]) !== false) {
        define('LANG', 'EN');
    }
} else {
    if (PASS == '????????????????') {
        die('Forbidden');
    }

    define('NEED_REPORT', true);
}

if (!defined('LANG')) {
    define('LANG', 'RU');
}

// put 1 for expert mode, 0 for basic check and 2 for paranoid mode
// установите 1 для режима "Обычное сканирование", 0 для быстрой проверки и 2 для параноидальной проверки (диагностика при лечении сайтов)
define('AI_EXPERT_MODE', 2);

define('AI_HOSTER', 1);

define('CLOUD_ASSIST_LIMIT', 5000);

$defaults = array(
    'path'              => dirname(__FILE__),
    'scan_all_files'    => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
    'scan_delay'        => 0, // delay in file scanning to reduce system load
    'max_size_to_scan'  => '650K',
    'max_size_to_cloudscan'  => '650K',
    'site_url'          => '', // website url
    'no_rw_dir'         => 0,
    'skip_ext'          => '',
    'skip_cache'        => false,
    'report_mask'       => JSONReport::REPORT_MASK_FULL,
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('MAX_FILE_SIZE_FOR_CHECK', 268435456); //256Mb - The maximum possible file size for the initial checking

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)) {
    define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array(
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml'
);
$g_SensitiveFiles  = array_merge(array(
    'php',
    'js',
    'json',
    'htaccess',
    'html',
    'htm',
    'tpl',
    'inc',
    'css',
    'txt',
    'sql',
    'ico',
    '',
    'susp',
    'suspected',
    'zip',
    'tar'
), $g_SuspiciousFiles);
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction|EICAR-STANDARD-ANTIVIRUS-TEST-FILE';
$g_VirusFiles      = array(
    'js',
    'json',
    'html',
    'htm',
    'suspicious'
);
$g_VirusEntries    = '<script|<iframe|<object|<embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles      = array(
    'js',
    'html',
    'htm',
    'suspected',
    'php',
    'phtml',
    'pht',
    'php7'
);
$g_PhishEntries    = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt    = array(
    'php',
    'php3',
    'php4',
    'php5',
    'php7',
    'pht',
    'html',
    'htm',
    'phtml',
    'shtml',
    'khtml',
    '',
    'ico',
    'txt'
);

if (LANG == 'RU') {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // RUSSIAN INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Отображать по _MENU_ записей\"";
    $msg2  = "\"Ничего не найдено\"";
    $msg3  = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
    $msg4  = "\"Нет файлов\"";
    $msg5  = "\"(всего записей _MAX_)\"";
    $msg6  = "\"Поиск:\"";
    $msg7  = "\"Первая\"";
    $msg8  = "\"Предыдущая\"";
    $msg9  = "\"Следующая\"";
    $msg10 = "\"Последняя\"";
    $msg11 = "\": активировать для сортировки столбца по возрастанию\"";
    $msg12 = "\": активировать для сортировки столбцов по убыванию\"";

    define('AI_STR_001', 'Отчет сканера <a href="https://github.com/rorry47/ai-bolit">AI-Bolit Fork</a> v@@VERSION@@:');
    define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>. <p>Лучшее лечение &mdash; это профилактика.');
    define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
    define('AI_STR_004', 'Путь');
    define('AI_STR_005', 'Изменение свойств');
    define('AI_STR_006', 'Изменение содержимого');
    define('AI_STR_007', 'Размер');
    define('AI_STR_008', 'Конфигурация PHP');
    define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
    define('AI_STR_010', "Сканер AI-Bolit Fork запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
    define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
    define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
    define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования.');
    define('AI_STR_015', '<div class="title">Критические замечания</div>');
    define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
    define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
    define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
    define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
    define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
    define('AI_STR_021', 'Подозрение на вредоносный скрипт');
    define('AI_STR_022', 'Символические ссылки (symlinks)');
    define('AI_STR_023', 'Скрытые файлы');
    define('AI_STR_024', 'Возможно, каталог с дорвеем');
    define('AI_STR_025', 'Не найдено директорий c дорвеями');
    define('AI_STR_026', 'Предупреждения');
    define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
    define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
    define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
    define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
    define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
    define('AI_STR_032', 'Невидимые ссылки');
    define('AI_STR_033', 'Отображены только первые ');
    define('AI_STR_034', 'Подозрение на дорвей');
    define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
    define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
    define('AI_STR_037', 'Версии найденных CMS');
    define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
    define('AI_STR_039', 'Не найдено файлов больше чем %s');
    define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
    define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
    define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
    define('AI_STR_043', 'Использовано памяти при сканировании: ');
    define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
    define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
    define('AI_STR_050', '');
    define('AI_STR_051', 'Отчет по ');
    define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
    define('AI_STR_053', 'Много косвенных вызовов функции');
    define('AI_STR_054', 'Подозрение на обфусцированные переменные');
    define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
    define('AI_STR_056', 'Дробление строки на символы');
    define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.');
    define('AI_STR_058', 'Обнаружены фишинговые страницы');
    define('AI_STR_059', 'Мобильных редиректов');
    define('AI_STR_060', 'Вредоносных скриптов');
    define('AI_STR_061', 'JS Вирусов');
    define('AI_STR_062', 'Фишинговых страниц');
    define('AI_STR_063', 'Исполняемых файлов');
    define('AI_STR_064', 'IFRAME вставок');
    define('AI_STR_065', 'Пропущенных больших файлов');
    define('AI_STR_066', 'Ошибок чтения файлов');
    define('AI_STR_067', 'Зашифрованных файлов');
    define('AI_STR_068', 'Подозрительных');
    define('AI_STR_069', 'Символических ссылок');
    define('AI_STR_070', 'Скрытых файлов');
    define('AI_STR_072', 'Рекламных ссылок и кодов');
    define('AI_STR_073', 'Пустых ссылок');
    define('AI_STR_074', 'Сводный отчет');

    define('AI_STR_075', 'Сканер бесплатный. Информация по сканеру: <a href="https://github.com/rorry47/ai-bolit">https://github.com/rorry47/ai-bolit</a>');

    $tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit Fork или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
HTML_FOOTER;

    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Подозрительные параметры времени изменения файла");
    define('AI_STR_078', "Подозрительные атрибуты файла");
    define('AI_STR_079', "Подозрительное местоположение файла");
    define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.");
    define('AI_STR_081', "Уязвимости в скриптах");
    define('AI_STR_082', "Добавленные файлы");
    define('AI_STR_083', "Измененные файлы");
    define('AI_STR_084', "Удаленные файлы");
    define('AI_STR_085', "Добавленные каталоги");
    define('AI_STR_086', "Удаленные каталоги");
    define('AI_STR_087', "Изменения в файловой структуре");

    $l_Offer = <<<OFFER
    <div>
     <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Cканер обнаружил подозрительный или вредоносный код</b>.</div> 
     <p>Возможно, ваш сайт был взломан.</p>
     <p><hr size=1></p>
    </div>
OFFER;

    $l_Offer2 = <<<OFFER2
       
OFFER2;

} else {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ENGLISH INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Display _MENU_ records\"";
    $msg2  = "\"Not found\"";
    $msg3  = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
    $msg4  = "\"No files\"";
    $msg5  = "\"(total _MAX_)\"";
    $msg6  = "\"Filter/Search:\"";
    $msg7  = "\"First\"";
    $msg8  = "\"Previous\"";
    $msg9  = "\"Next\"";
    $msg10 = "\"Last\"";
    $msg11 = "\": activate to sort row ascending order\"";
    $msg12 = "\": activate to sort row descending order\"";

    define('AI_STR_001', 'AI-Bolit Fork v@@VERSION@@ Scan Report:');
    define('AI_STR_002', '');
    define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
    define('AI_STR_004', 'Path');
    define('AI_STR_005', 'iNode Changed');
    define('AI_STR_006', 'Modified');
    define('AI_STR_007', 'Size');
    define('AI_STR_008', 'PHP Info');
    define('AI_STR_009', "Your password for AI-BOLIT Fork is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
    define('AI_STR_010', "Open AI-BOLIT Fork with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
    define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
    define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
    define('AI_STR_013', 'Scanned %s folders and %s files.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
    define('AI_STR_015', '<div class="title">Critical</div>');
    define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
    define('AI_STR_017', 'Shell scripts signatures not detected.');
    define('AI_STR_018', 'Javascript virus signatures detected:');
    define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
    define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
    define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
    define('AI_STR_022', 'Symlinks:');
    define('AI_STR_023', 'Hidden files:');
    define('AI_STR_024', 'Files might be a part of doorway:');
    define('AI_STR_025', 'Doorway folders not detected');
    define('AI_STR_026', 'Warnings');
    define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
    define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
    define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
    define('AI_STR_030', 'Reading error. Skipped.');
    define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
    define('AI_STR_032', 'List of invisible links:');
    define('AI_STR_033', 'Displayed first ');
    define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
    define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
    define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
    define('AI_STR_037', 'CMS found:');
    define('AI_STR_038', 'Large files (greater than %s! Skipped:');
    define('AI_STR_039', 'Files greater than %s not found');
    define('AI_STR_040', 'Files recommended to be remove due to security reason:');
    define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
    define('AI_STR_042', 'Writable folders not found');
    define('AI_STR_043', 'Memory used: ');
    define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
    define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT Fork is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
    define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script.");
    define('AI_STR_051', 'Report for ');
    define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
    define('AI_STR_053', 'Function called by reference');
    define('AI_STR_054', 'Suspected for obfuscated variables');
    define('AI_STR_055', 'Suspected for $GLOBAL array usage');
    define('AI_STR_056', 'Abnormal split of string');
    define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
    define('AI_STR_058', 'Phishing pages detected:');

    define('AI_STR_059', 'Mobile redirects');
    define('AI_STR_060', 'Malware');
    define('AI_STR_061', 'JS viruses');
    define('AI_STR_062', 'Phishing pages');
    define('AI_STR_063', 'Unix executables');
    define('AI_STR_064', 'IFRAME injections');
    define('AI_STR_065', 'Skipped big files');
    define('AI_STR_066', 'Reading errors');
    define('AI_STR_067', 'Encrypted files');
    define('AI_STR_068', 'Suspicious');
    define('AI_STR_069', 'Symbolic links');
    define('AI_STR_070', 'Hidden files');
    define('AI_STR_072', 'Adware and spam links');
    define('AI_STR_073', 'Empty links');
    define('AI_STR_074', 'Summary');
    define('AI_STR_075', '');

    $tmp_str = <<<HTML_FOOTER
           <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
           </div>
HTML_FOOTER;
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Suspicious file mtime and ctime");
    define('AI_STR_078', "Suspicious file permissions");
    define('AI_STR_079', "Suspicious file location");
    define('AI_STR_081', "Vulnerable Scripts");
    define('AI_STR_082', "Added files");
    define('AI_STR_083', "Modified files");
    define('AI_STR_084', "Deleted files");
    define('AI_STR_085', "Added directories");
    define('AI_STR_086', "Deleted directories");
    define('AI_STR_087', "Integrity Check Report");

    $l_Offer = <<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
</div>
<br/>
<div>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;

    $l_Offer2 = '';

    define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template = <<<MAIN_PAGE
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css">
 body 
 {
    font-family: Tahoma, sans-serif;
    color: #ffffff;
    background: #2c2c2c;
    font-size: 14px;
    margin: 20px;
    padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #3c0000;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #2c2c2c;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
    font-weight: 100;
    background: #FF0090;
    padding: 2px 0 2px 0;
    width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial, sans-serif;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #484848;
}

#table_crit {
    border: 7px solid #682b2b;
    padding: 5px;
}
a {
    color: #a9a7a7;
}
.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri, sans-serif;
   font-size: 12px;
   margin: 10px 10px 10px 0;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
    color: #6c6c6c;
    font-weight: 700;
    text-decoration: none;
    padding: 2px;
    background: #2c2c2c;
    -webkit-border-radius: 7px;
    -moz-border-radius: 7px;
    border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0 0;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #0e0d0d;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
    <div class="footer">
    @@FOOTER@@
    </div>
    
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
        "paging": true,
       "iDisplayLength": 500,
        "oLanguage": {
            "sLengthMenu": $msg1,
            "sZeroRecords": $msg2,
            "sInfo": $msg3,
            "sInfoEmpty": $msg4,
            "sInfoFiltered": $msg5,
            "sSearch":       $msg6,
            "sUrl":          "",
            "oPaginate": {
                "sFirst": $msg7,
                "sPrevious": $msg8,
                "sNext": $msg9,
                "sLast": $msg10
            },
            "oAria": {
                "sSortAscending": $msg11,
                "sSortDescending": $msg12   
            }
        }

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
        "paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
        "oLanguage": {
            "sLengthMenu": $msg1,
            "sZeroRecords": $msg2,
            "sInfo": $msg3,
            "sInfoEmpty": $msg4,
            "sInfoFiltered": $msg5,
            "sSearch":       $msg6,
            "sUrl":          "",
            "oPaginate": {
                "sFirst": $msg7,
                "sPrevious": $msg8,
                "sNext": $msg9,
                "sLast": $msg10
            },
            "oAria": {
                "sSortAscending":  $msg11,
                "sSortDescending": $msg12   
            }
        },

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
        "paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
                     "iDisplayLength": 500,
                    "oLanguage": {
                        "sLengthMenu": $msg1,
                        "sZeroRecords": $msg2,
                        "sInfo": $msg3,
                        "sInfoEmpty": $msg4,
                        "sInfoFiltered": $msg5,
                        "sSearch":       $msg6,
                        "sUrl":          "",
                        "oPaginate": {
                            "sFirst": $msg7,
                            "sPrevious": $msg8,
                            "sNext": $msg9,
                            "sLast": $msg10
                        },
                        "oAria": {
                            "sSortAscending":  $msg11,
                            "sSortDescending": $msg12   
                        }
        }

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
        "paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
                     "iDisplayLength": 500,
                    "oLanguage": {
                        "sLengthMenu": $msg1,
                        "sZeroRecords": $msg2,
                        "sInfo": $msg3,
                        "sInfoEmpty": $msg4,
                        "sInfoFiltered": $msg5,
                        "sSearch":       $msg6,
                        "sUrl":          "",
                        "oPaginate": {
                            "sFirst": $msg7,
                            "sPrevious": $msg8,
                            "sNext": $msg9,
                            "sLast": $msg10
                        },
                        "oAria": {
                            "sSortAscending":  $msg11,
                            "sSortDescending": $msg12   
                        }
        }

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
    $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$g_Mnemo = array();
$db_location = 'internal';

//BEGIN_SIG 13/01/2020 05:44:15
$g_DBShe = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$gX_DBShe = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_FlexDBShe = unserialize(gzinflate(/*1578926655*/base64_decode("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")));
$gX_FlexDBShe = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_ExceptFlex = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_AdwareSig = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_PhishingSig = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_JSVirSig = unserialize(gzinflate(/*1578926655*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_SusDB = unserialize(gzinflate(/*1578926655*/base64_decode("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")));
$g_SusDBPrio = unserialize(gzinflate(/*1578926655*/base64_decode("S7QysKquBQA=")));
$g_Mnemo = @array_flip(unserialize(gzinflate(/*1578926655*/base64_decode("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"))));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));
$db_meta_info = unserialize(base64_decode("YTozOntzOjEwOiJidWlsZC1kYXRlIjtzOjEwOiIxNTc4OTI2NTkwIjtzOjc6InZlcnNpb24iO3M6MTM6IjIwMjAwMTEzLTE3MzkiO3M6MTI6InJlbGVhc2UtdHlwZSI7czoxMDoicHJvZHVjdGlvbiI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
    echo "#####################################################\n";
    echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
    echo "#                                                   #\n";
    echo "# See FAQ: https://github.com/rorry47/ai-bolit      #\n";
    echo "#####################################################\n";
    exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
    echo "#####################################################\n";
    echo "# Warning: PHP Version < 5.3.1                      #\n";
    echo "# Some function might not work properly             #\n";
    echo "# See FAQ: https://github.com/rorry47/ai-bolit      #\n";
    echo "#####################################################\n";
    exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
    echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";
    exit;
}

define('AI_VERSION', '5.0');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_SpecificExt = false;

$g_UpdatedJsonLog      = 0;
$g_FileInfo            = array();
$g_Iframer             = array();
$g_PHPCodeInside       = array();
$g_Base64              = array();
$g_HeuristicDetected   = array();
$g_HeuristicType       = array();
$g_UnixExec            = array();
$g_UnsafeFilesFound    = array();
$g_HiddenFiles         = array();

$g_RegExpStat = array();


if (!isCli()) {
    $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/';
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 - 2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size', '16M');
ini_set('realpath_cache_ttl', '1200');
ini_set('pcre.backtrack_limit', '1000000');
ini_set('pcre.recursion_limit', '200000');
ini_set('pcre.jit', '1');

if (!function_exists('stripos')) {
    function stripos($par_Str, $par_Entry, $Offset = 0) {
        return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
    }
}

/**
 * Print file
 */
function printFile() {
    die("Not Supported");

    $l_FileName = $_GET['fn'];
    $l_CRC      = isset($_GET['c']) ? (int) $_GET['c'] : 0;
    $l_Content  = file_get_contents($l_FileName);
    $l_FileCRC  = realCRC($l_Content);
    if ($l_FileCRC != $l_CRC) {
        echo 'Доступ запрещен.';
        exit;
    }

    echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false) {
    $in = crc32($full ? normal($str_in) : $str_in);
    return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli() {
    return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
    return hash('crc32b', $str);
}

function generatePassword($length = 9) {

    // start with a blank password
    $password = "";

    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";

    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);

    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
        $length = $maxlength;
    }

    // set up a counter for how many characters are in the password so far
    $i = 0;

    // add random characters to $password until $length is reached
    while ($i < $length) {

        // pick a random character from the possible ones
        $char = substr($possible, mt_rand(0, $maxlength - 1), 1);

        // have we already used this character in $password?
        if (!strstr($password, $char)) {
            // no, so it's OK to add it onto the end of whatever we've already got...
            $password .= $char;
            // ... and increase the counter by one
            $i++;
        }

    }

    // done!
    return $password;

}

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true) {
    if (!isCli())
        return;

    if (is_bool($text)) {
        $text = $text ? 'true' : 'false';
    } else if (is_null($text)) {
        $text = 'null';
    }
    if (!is_scalar($text)) {
        $text = print_r($text, true);
    }

    if ((!BOOL_RESULT) && (!JSON_STDOUT)) {
        @fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
    }
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File, $vars) {
    global $g_Base64, $g_Iframer, $g_UpdatedJsonLog, $g_AddPrefix, $g_NoPrefix;

    $total_files  = $vars->foundTotalFiles;
    $elapsed_time = microtime(true) - START_TIME;
    $percent      = number_format($total_files ? $num * 100 / $total_files : 0, 1);
    $stat         = '';
    if ($elapsed_time >= 1) {
        $elapsed_seconds = round($elapsed_time, 0);
        $fs              = floor($num / $elapsed_seconds);
        $left_files      = $total_files - $num;
        if ($fs > 0) {
            $left_time = ($left_files / $fs); //ceil($left_files / $fs);
            $stat      = ' [Avg: ' . round($fs, 2) . ' files/s' . ($left_time > 0 ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($vars->criticalPHP) + count($g_Base64) + count($vars->warningPHP)) . '|' . (count($vars->criticalJS) + count($g_Iframer) + count($vars->phishing)) . ']';
        }
    }

    $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File);
    $l_FN = substr($par_File, -60);

    $text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
    $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
    stdOut(str_repeat(chr(8), 160) . $text, false);


    $data = array(
        'self' => __FILE__,
        'started' => AIBOLIT_START_TIME,
        'updated' => time(),
        'progress' => $percent,
        'time_elapsed' => $elapsed_seconds,
        'time_left' => round($left_time),
        'files_left' => $left_files,
        'files_total' => $total_files,
        'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160)
    );

    if (function_exists('aibolit_onProgressUpdate')) {
        aibolit_onProgressUpdate($data);
    }

    if (defined('PROGRESS_LOG_FILE') && (time() - $g_UpdatedJsonLog > 1)) {
        if (function_exists('json_encode')) {
            file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
        } else {
            file_put_contents(PROGRESS_LOG_FILE, serialize($data));
        }

        $g_UpdatedJsonLog = time();
    }

    if (defined('SHARED_MEMORY')) {
        shmop_write(SHARED_MEMORY, str_repeat("\0", shmop_size(SHARED_MEMORY)), 0);
        if (function_exists('json_encode')) {
            shmop_write(SHARED_MEMORY, json_encode($data), 0);
        } else {
            shmop_write(SHARED_MEMORY, serialize($data), 0);
        }
    }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds) {
    $r        = '';
    $_seconds = floor($seconds);
    $ms       = $seconds - $_seconds;
    $seconds  = $_seconds;
    if ($hours = floor($seconds / 3600)) {
        $r .= $hours . (isCli() ? ' h ' : ' час ');
        $seconds = $seconds % 3600;
    }

    if ($minutes = floor($seconds / 60)) {
        $r .= $minutes . (isCli() ? ' m ' : ' мин ');
        $seconds = $seconds % 60;
    }

    if ($minutes < 3)
        $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек');

    return $r;
}

if (isCli()) {

    $cli_options = array(
        'y' => 'deobfuscate',
        'c:' => 'avdb:',
        'm:' => 'memory:',
        's:' => 'size:',
        'a' => 'all',
        'd:' => 'delay:',
        'l:' => 'list:',
        'r:' => 'report:',
        'f' => 'fast',
        'j:' => 'file:',
        'p:' => 'path:',
        'q' => 'quite',
        'e:' => 'cms:',
        'x:' => 'mode:',
        'k:' => 'skip:',
        'i:' => 'idb:',
        'n' => 'sc',
        'o:' => 'json_report:',
        't:' => 'php_report:',
        'z:' => 'progress:',
        'g:' => 'handler:',
        'b' => 'smart',
        'u:' => 'username:',
        'h' => 'help'
    );

    $cli_longopts = array(
        'deobfuscate',
        'avdb:',
        'cmd:',
        'noprefix:',
        'addprefix:',
        'scan:',
        'one-pass',
        'smart',
        'quarantine',
        'with-2check',
        'skip-cache',
        'username:',
        'imake',
        'icheck',
        'no-html',
        'json-stdout',
        'listing:',
        'encode-b64-fn',
        'cloud-assist:',
        'cloudscan-size:',
        'with-suspicious',
        'rapid-account-scan:',
        'rapid-account-scan-type:',
        'extended-report',
        'factory-config:',
        'shared-mem-progress:',
        'create-shared-mem',
        'max-size-scan-bytes:',
        'input-fn-b64-encoded',
        'use-heuristics',
        'use-heuristics-suspicious',
        'resident',
        'detached:',
        'log:',
        'log-level:'
    );

    $cli_longopts = array_merge($cli_longopts, array_values($cli_options));

    $options = getopt(implode('', array_keys($cli_options)), $cli_longopts);

    if (isset($options['h']) OR isset($options['help'])) {
        $memory_limit = ini_get('memory_limit');
        echo <<<HELP
AI-Bolit Fork - an Intelligent Malware File Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE                       Full path to single file to check
  -p, --path=PATH                       Directory path to scan, by default the file directory is used
                                        Current path: {$defaults['path']}
  -p, --listing=FILE                    Scan files from the listing. E.g. --listing=/tmp/myfilelist.txt
                                            Use --listing=stdin to get listing from stdin stream
      --extended-report                 To expand the report
  -x, --mode=INT                        Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...                    Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...                    Scan only specific extensions. E.g. --scan=php,htaccess,js
      --cloud-assist=TOKEN              Enable cloud assisted scanning. Disabled by default.
      --with-suspicious                 Detect suspicious files. Disabled by default.
      --rapid-account-scan=<dir>        Enable rapid account scan. Use <dir> for base db dir. Need to set only root permissions(700)
      --rapid-account-scan-type=<type>  Type rapid account scan. <type> = NONE|ALL|SUSPICIOUS, def:SUSPICIOUS
      --use-heuristics                  Enable heuristic algorithms and mark found files as malicious.
      --use-heuristics-suspicious       Enable heuristic algorithms and mark found files as suspicious.
  -r, --report=PATH
  -o, --json_report=FILE                Full path to create json-file with a list of found malware
  -l, --list=FILE                       Full path to create plain text file with a list of found malware
      --no-html                         Disable HTML report
      --encode-b64-fn                   Encode file names in a report with base64 (for internal usage)
      --input-fn-b64-encoded            Base64 encoded input filenames in listing or stdin
      --smart                           Enable smart mode (skip cache files and optimize scanning)
  -m, --memory=SIZE                     Maximum amount of memory a script may consume. Current value: $memory_limit
                                        Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE                       Scan files are smaller than SIZE with signatures. 0 - All files. Current value: {$defaults['max_size_to_scan']}
      --max-size-scan-bytes=SIZE        Scan first <bytes> for large(can set by --size) files with signatures.
      --cloudscan-size                  Scan files are smaller than SIZE with cloud assisted scan. 0 - All files. Current value: {$defaults['max_size_to_cloudscan']}
  -d, --delay=INT                       Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -a, --all                             Scan all files (by default scan. js,. php,. html,. htaccess)
      --one-pass                        Do not calculate remaining time
      --quarantine                      Archive all malware from report
      --with-2check                     Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file                        Integrity Check database file

  -z, --progress=FILE                   Runtime progress of scanning, saved to the file, full path required. 
      --shared-mem-progress=<ID>        Runtime progress of scanning, saved to the shared memory <ID>.
      --create-shared-mem               Need to create shared memory segment <ID> for --shared-mem-progress. 
  -u, --username=<username>             Run scanner with specific user id and group id, e.g. --username=www-data
  -g, --hander=FILE                     External php handler for different events, full path to php file required.
      --cmd="command [args...]"         Run command after scanning

      --help                            Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
        exit;
    }

    $l_FastCli = false;

    if ((isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory'])) OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))) {
        $memory = getBytes($memory);
        if ($memory > 0) {
            $defaults['memory_limit'] = $memory;
            ini_set('memory_limit', $memory);
        }
    }


    $avdb = '';
    if ((isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb'])) OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))) {
        if (file_exists($avdb)) {
            $defaults['avdb'] = $avdb;
        }
    }

    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)) {
        define('SCAN_FILE', $file);
    }


    if (isset($options['deobfuscate']) OR isset($options['y'])) {
        define('AI_DEOBFUSCATE', true);
    }

    if ((isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false) OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)) {

        define('PLAIN_FILE', $file);
    }

    if ((isset($options['listing']) AND !empty($options['listing']) AND ($listing = $options['listing']) !== false)) {

        if (file_exists($listing) && is_file($listing) && is_readable($listing)) {
            define('LISTING_FILE', $listing);
        }

        if ($listing == 'stdin') {
            define('LISTING_FILE', $listing);
        }
    }

    if ((isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false) OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)) {
        define('JSON_FILE', $file);

        if (!function_exists('json_encode')) {
            die('json_encode function is not available. Enable json extension in php.ini');
        }
    }

    if ((isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false) OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)) {
        define('PHP_FILE', $file);
    }

    $env_log = getenv('AIBOLIT_RESIDENT_LOG');
    $env_log_level = getenv('AIBOLIT_RESIDENT_LOG_LEVEL');

    if ((isset($options['log']) AND !empty($options['log']) AND ($log_file = $options['log']) !== false) OR ($env_log !== false AND ($log_file = $env_log) !== false)) {
        define('LOG_FILE', $log_file);
    }

    if ((isset($options['log-level']) AND !empty($options['log-level']) AND ($log_level = $options['log-level']) !== false) OR ($env_log_level !== false AND ($log_level = $env_log_level) !== false)) {
        define('LOG_LEVEL', $log_level);
    }

    if (defined('LOG_FILE') AND !defined('LOG_LEVEL')) {
        define('LOG_LEVEL', 'INFO');
    }

    if ((isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false) OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)) {
        if (file_exists($file)) {
            define('AIBOLIT_EXTERNAL_HANDLER', $file);
        }
    }

    if ((isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false) OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)) {
        define('PROGRESS_LOG_FILE', $file);
    }

    if (isset($options['create-shared-mem'])) {
        define('CREATE_SHARED_MEMORY', true);
    } else {
        define('CREATE_SHARED_MEMORY', false);
    }

    if (isset($options['shared-mem-progress']) AND !empty($options['shared-mem-progress']) AND ($sh_mem = $options['shared-mem-progress']) !== false) {
        if (CREATE_SHARED_MEMORY) {
            @$shid = shmop_open(intval($sh_mem), "n", 0666, 5000);
        } else {
            @$shid = shmop_open(intval($sh_mem), "w", 0, 0);
        }
        if (!empty($shid)) {
            define('SHARED_MEMORY', $shid);
        } else {
            die('Error with shared-memory.');
        }
    }

    if ((isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false) OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)) {
        $size                         = getBytes($size);
        $defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
    }

    if (isset($options['cloudscan-size']) AND !empty($options['cloudscan-size']) AND ($cloudscan_size = $options['cloudscan-size']) !== false) {
        $cloudscan_size                         = getBytes($cloudscan_size);
        $defaults['max_size_to_cloudscan'] = $cloudscan_size > 0 ? $cloudscan_size : 0;
    }

    if (isset($options['max-size-scan-bytes']) && !empty($options['max-size-scan-bytes'])) {
        define('MAX_SIZE_SCAN_BYTES', getBytes($options['max-size-scan-bytes']));
    } else {
        define('MAX_SIZE_SCAN_BYTES', 0);
    }

    if ((isset($options['username']) AND !empty($options['username']) AND ($username = $options['username']) !== false) OR (isset($options['u']) AND !empty($options['u']) AND ($username = $options['u']) !== false)) {

        if (!empty($username) && ($info = posix_getpwnam($username)) !== false) {
            posix_setgid($info['gid']);
            posix_setuid($info['uid']);
            $defaults['userid']  = $info['uid'];
            $defaults['groupid'] = $info['gid'];
        } else {
            echo ('Invalid username');
            exit(-1);
        }
    }

    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false) AND (isset($options['q']))) {
        $BOOL_RESULT = true;
    }

    if (isset($options['json-stdout'])) {
        define('JSON_STDOUT', true);
    } else {
        define('JSON_STDOUT', false);
    }

    if (isset($options['f'])) {
        $l_FastCli = true;
    }

    if (isset($options['q']) || isset($options['quite'])) {
        $BOOL_RESULT = true;
    }

    if (isset($options['x'])) {
        define('AI_EXPERT', $options['x']);
    } else if (isset($options['mode'])) {
        define('AI_EXPERT', $options['mode']);
    } else {
        define('AI_EXPERT', AI_EXPERT_MODE);
    }

    if (AI_EXPERT < 2) {
        $g_SpecificExt              = true;
        $defaults['scan_all_files'] = false;
    } else {
        $defaults['scan_all_files'] = true;
    }

    define('BOOL_RESULT', $BOOL_RESULT);

    if ((isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false) OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)) {
        $delay = (int) $delay;
        if (!($delay < 0)) {
            $defaults['scan_delay'] = $delay;
        }
    }

    if ((isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false) OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)) {
        $defaults['skip_ext'] = $ext_list;
    }

    if (isset($options['n']) OR isset($options['skip-cache'])) {
        $defaults['skip_cache'] = true;
    }

    if (isset($options['scan'])) {
        $ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
        if ($ext_list != '') {
            $l_FastCli        = true;
            $g_SensitiveFiles = explode(",", $ext_list);
            for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
                if ($g_SensitiveFiles[$i] == '.') {
                    $g_SensitiveFiles[$i] = '';
                }
            }

            $g_SpecificExt = true;
        }
    }
    
    if (isset($options['cloud-assist'])) {
        define('CLOUD_ASSIST_TOKEN', $options['cloud-assist']);
    }
    

    if (isset($options['rapid-account-scan'])) {
        define('RAPID_ACCOUNT_SCAN', $options['rapid-account-scan']);
    }
    
    if (defined('RAPID_ACCOUNT_SCAN')) {
        if (isset($options['rapid-account-scan-type'])) {
            define('RAPID_ACCOUNT_SCAN_TYPE', $options['rapid-account-scan-type']);
        }
        else {
            define('RAPID_ACCOUNT_SCAN_TYPE', 'SUSPICIOUS');
        }
    }

    if (isset($options['with-suspicious'])) {
        define('AI_EXTRA_WARN', true);
    }

    if (isset($options['extended-report'])) {
        define('EXTENDED_REPORT', true);
    }

    if (isset($options['all']) OR isset($options['a'])) {
        $defaults['scan_all_files'] = true;
        $g_SpecificExt              = false;
    }

    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }


    if (!defined('SMART_SCAN')) {
        define('SMART_SCAN', 0);
    }

    if (!defined('AI_DEOBFUSCATE')) {
        define('AI_DEOBFUSCATE', false);
    }

    if (!defined('AI_EXTRA_WARN')) {
        define('AI_EXTRA_WARN', false);
    }


    $l_SpecifiedPath = false;
    if ((isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false) OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)) {
        $defaults['path'] = $path;
        $l_SpecifiedPath  = true;
    }

    if (isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false) {
    } else {
        $g_NoPrefix = '';
    }

    if (isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false) {
    } else {
        $g_AddPrefix = '';
    }

    if (isset($options['use-heuristics'])) {
        define('USE_HEURISTICS', true);
    }

    if (isset($options['use-heuristics-suspicious'])) {
        define('USE_HEURISTICS_SUSPICIOUS', true);
    }

    if (defined('USE_HEURISTICS') && defined('USE_HEURISTICS_SUSPICIOUS')) {
        die('You can not use --use-heuristic and --use-heuristic-suspicious the same time.');
    }

    $l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
    $l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
    $l_SuffixReport = preg_replace('~[/\\\.\s]~', '_', $l_SuffixReport);
    $l_SuffixReport .= "-" . rand(1, 999999);

    if ((isset($options['report']) AND ($report = $options['report']) !== false) OR (isset($options['r']) AND ($report = $options['r']) !== false)) {
        $report = str_replace('@PATH@', $l_SuffixReport, $report);
        $report = str_replace('@RND@', rand(1, 999999), $report);
        $report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
        define('REPORT', $report);
        define('NEED_REPORT', true);
    }

    if (isset($options['no-html'])) {
        define('REPORT', 'no@email.com');
    }

    defined('ENCODE_FILENAMES_WITH_BASE64') || define('ENCODE_FILENAMES_WITH_BASE64', isset($options['encode-b64-fn']));
    
    defined('INPUT_FILENAMES_BASE64_ENCODED') || define('INPUT_FILENAMES_BASE64_ENCODED', isset($options['input-fn-b64-encoded']));
    
    if ((isset($options['idb']) AND ($ireport = $options['idb']) !== false)) {
        $ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
        $ireport = str_replace('@RND@', rand(1, 999999), $ireport);
        $ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
        define('INTEGRITY_DB_FILE', $ireport);
    }


    defined('REPORT') OR define('REPORT', 'AI-BOLIT-Fork-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');

    defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));

    $last_arg = max(1, sizeof($_SERVER['argv']) - 1);
    if (isset($_SERVER['argv'][$last_arg])) {
        $path = $_SERVER['argv'][$last_arg];
        if (substr($path, 0, 1) != '-' AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options))) {
            $defaults['path'] = $path;
        }
    }

    define('ONE_PASS', isset($options['one-pass']));

    define('IMAKE', isset($options['imake']));
    define('ICHECK', isset($options['icheck']));

    if (IMAKE && ICHECK)
        die('One of the following options must be used --imake or --icheck.');

    // BEGIN of configuring the factory
    $factoryConfig = [
        RapidAccountScan::class             => RapidAccountScan::class,
        RapidScanStorage::class             => RapidScanStorage::class,
        CloudAssistedStorage::class         => CloudAssistedStorage::class,
        DbFolderSpecification::class        => DbFolderSpecification::class,
        CriticalFileSpecification::class    => CriticalFileSpecification::class,
        CloudAssistedRequest::class         => CloudAssistedRequest::class,
        JSONReport::class                   => JSONReport::class,
        DetachedMode::class                 => DetachedMode::class,
        ResidentMode::class                 => ResidentMode::class,
        Logger::class                       => Logger::class,
    ];

    if (isset($options['factory-config'])) {
        $optionalFactoryConfig = require($options['factory-config']);
        $factoryConfig = array_merge($factoryConfig, $optionalFactoryConfig);
    }

    Factory::configure($factoryConfig);
    // END of configuring the factory

} else {
    define('AI_EXPERT', AI_EXPERT_MODE);
    define('ONE_PASS', true);
}

if (ONE_PASS && defined('CLOUD_ASSIST_TOKEN')) {
    die('Both parameters(one-pass and cloud-assist) not supported');
}

if (defined('RAPID_ACCOUNT_SCAN') && !defined('CLOUD_ASSIST_TOKEN')) { 
    die('CloudScan should be enabled');
}

if (defined('CREATE_SHARED_MEMORY') && CREATE_SHARED_MEMORY == true && !defined('SHARED_MEMORY')) {
    die('shared-mem-progress should be enabled and ID specified.');
}

if (defined('RAPID_ACCOUNT_SCAN')) {
    @mkdir(RAPID_ACCOUNT_SCAN, 0700, true);
    $specification = Factory::instance()->create(DbFolderSpecification::class);
    if (!$specification->satisfiedBy(RAPID_ACCOUNT_SCAN)) {
        @unlink(RAPID_ACCOUNT_SCAN);
        die('Rapid DB folder error! Please check the folder.');
    }
}

if (defined('RAPID_ACCOUNT_SCAN_TYPE') && !in_array(RAPID_ACCOUNT_SCAN_TYPE, array('NONE', 'ALL', 'SUSPICIOUS'))) {
    die('Wrong Rapid account scan type');
}

if (defined('RAPID_ACCOUNT_SCAN') && !extension_loaded('leveldb')) { 
    die('LevelDB extension needed for Rapid DB');
}

$vars->blackFiles = [];

if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));

    $g_DBShe       = explode("\n", base64_decode($avdb[0]));
    $gX_DBShe      = explode("\n", base64_decode($avdb[1]));
    $g_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
    $gX_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
    $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
    $g_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
    $g_AdwareSig   = explode("\n", base64_decode($avdb[6]));
    $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
    $g_JSVirSig    = explode("\n", base64_decode($avdb[8]));
    $gX_JSVirSig   = explode("\n", base64_decode($avdb[9]));
    $g_SusDB       = explode("\n", base64_decode($avdb[10]));
    $g_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
    $g_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
    $g_Mnemo    = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));

    // get meta information
    $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);
    $db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
    $db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
    $db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

    if (count($g_DBShe) <= 1) {
        $g_DBShe = array();
    }

    if (count($gX_DBShe) <= 1) {
        $gX_DBShe = array();
    }

    if (count($g_FlexDBShe) <= 1) {
        $g_FlexDBShe = array();
    }

    if (count($gX_FlexDBShe) <= 1) {
        $gX_FlexDBShe = array();
    }

    if (count($gXX_FlexDBShe) <= 1) {
        $gXX_FlexDBShe = array();
    }

    if (count($g_ExceptFlex) <= 1) {
        $g_ExceptFlex = array();
    }

    if (count($g_AdwareSig) <= 1) {
        $g_AdwareSig = array();
    }

    if (count($g_PhishingSig) <= 1) {
        $g_PhishingSig = array();
    }

    if (count($gX_JSVirSig) <= 1) {
        $gX_JSVirSig = array();
    }

    if (count($g_JSVirSig) <= 1) {
        $g_JSVirSig = array();
    }

    if (count($g_SusDB) <= 1) {
        $g_SusDB = array();
    }

    if (count($g_SusDBPrio) <= 1) {
        $g_SusDBPrio = array();
    }
    $db_location = 'external';
    stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
    $gX_FlexDBShe  = array();
    $gXX_FlexDBShe = array();
    $gX_JSVirSig   = array();
}

if (isset($defaults['userid'])) {
    stdOut('Running from ' . $defaults['userid'] . ':' . $defaults['groupid']);
}

$sign_count = count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe);

if (AI_EXTRA_WARN) {
    $sign_count += count($g_SusDB);
}

stdOut('Malware signatures: ' . $sign_count);

if ($g_SpecificExt) {
    stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

// Black list database
try {
    $file = dirname(__FILE__) . '/AIBOLIT-BINMALWARE.db';
    if (isset($defaults['avdb'])) {
        $file = dirname($defaults['avdb']) . '/AIBOLIT-BINMALWARE.db';
    }
    $vars->blacklist = FileHashMemoryDb::open($file);
    stdOut("Binary malware signatures: " . ceil($vars->blacklist->count()));
} catch (Exception $e) {
    $vars->blacklist = null;
}

if (!DEBUG_PERFORMANCE) {
    OptimizeSignatures();
} else {
    stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) {
    define('PLAIN_FILE', '');
}

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 120);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
    include_once(AIBOLIT_EXTERNAL_HANDLER);
    stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
    if (function_exists("aibolit_onStart")) {
        aibolit_onStart();
    }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
    $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
    $defaults['scan_all_files'] = 0;
}

if (!isCli()) {
    define('ICHECK', isset($_GET['icheck']));
    define('IMAKE', isset($_GET['imake']));

    define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));
define('MAX_SIZE_TO_CLOUDSCAN', getBytes($defaults['max_size_to_cloudscan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
    ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH) {
    if (isCli()) {
        die(stdOut("Directory '{$defaults['path']}' not found!"));
    }
} elseif (!is_readable(ROOT_PATH)) {
    if (isCli()) {
        die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
    }
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT)) {
    $report      = str_replace('\\', '/', REPORT);
    $abs         = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
    $report      = array_values(array_filter(explode('/', $report)));
    $report_file = array_pop($report);
    $report_path = realpath($abs . implode(DIR_SEPARATOR, $report));

    define('REPORT_FILE', $report_file);
    define('REPORT_PATH', $report_path);

    if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE)) {
        @unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
    }
}

if (defined('REPORT_PATH')) {
    $l_ReportDirName = REPORT_PATH;
}

$path                       = $defaults['path'];
$report_mask                = $defaults['report_mask'];
$extended_report            = defined('EXTENDED_REPORT') && EXTENDED_REPORT;
$rapid_account_scan_report  = defined('RAPID_ACCOUNT_SCAN');

$reportFactory = function () use ($g_Mnemo, $path, $db_location, $db_meta_info, $report_mask, $extended_report, $rapid_account_scan_report, $g_AddPrefix, $g_NoPrefix) {
    return Factory::instance()->create(JSONReport::class, [$g_Mnemo, $path, $db_location, $db_meta_info['version'], $report_mask, $extended_report, $rapid_account_scan_report, AI_VERSION, AI_HOSTER, AI_EXTRA_WARN, $g_AddPrefix, $g_NoPrefix]);
};

if (isset($options['detached'])) {
    Factory::instance()->create(DetachedMode::class, [$options['detached'], $vars, LISTING_FILE, START_TIME, $reportFactory, INPUT_FILENAMES_BASE64_ENCODED]);
    exit(0);
}

if (isset($options['resident'])) {
    $logger = null;
    $levels = explode(',', LOG_LEVEL);
    $logger = new Logger(LOG_FILE, $levels);
    Factory::instance()->create(ResidentMode::class, [$reportFactory, $vars->blacklist, $logger]);
    exit(0);
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000, 9999) . '.txt');

if (function_exists('phpinfo')) {
    ob_start();
    phpinfo();
    $l_PhpInfo = ob_get_contents();
    ob_end_clean();

    $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
    preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
    $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>';
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email) {
    $email = preg_split('~[,\s;]~', $email, -1, PREG_SPLIT_NO_EMPTY);
    $r     = array();
    for ($i = 0, $size = sizeof($email); $i < $size; $i++) {
        if (function_exists('filter_var')) {
            if (filter_var($email[$i], FILTER_VALIDATE_EMAIL)) {
                $r[] = $email[$i];
            }
        } else {
            // for PHP4
            if (strpos($email[$i], '@') !== false) {
                $r[] = $email[$i];
            }
        }
    }
    return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val) {
    $val  = trim($val);
    $last = strtolower($val{strlen($val) - 1});
    switch ($last) {
        case 't':
            $val *= 1024;
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }
    return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites) {
    if ($bites < 1024) {
        return $bites . ' b';
    } elseif (($kb = $bites / 1024) < 1024) {
        return number_format($kb, 2) . ' Kb';
    } elseif (($mb = $kb / 1024) < 1024) {
        return number_format($mb, 2) . ' Mb';
    } elseif (($gb = $mb / 1024) < 1024) {
        return number_format($gb, 2) . ' Gb';
    } else {
        return number_format($gb / 1024, 2) . 'Tb';
    }
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
    global $g_IgnoreList;

    for ($i = 0; $i < count($g_IgnoreList); $i++) {
        if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
            if ($par_CRC == $g_IgnoreList[$i][1]) {
                return true;
            }
        }
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
    global $g_AddPrefix, $g_NoPrefix;
    if ($replace_path) {
        $lines = explode("\n", $par_Str);
        array_walk($lines, function(&$n) {
            global $g_AddPrefix, $g_NoPrefix;
            $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
        });

        $par_Str = implode("\n", $lines);
    }

    return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
    global $g_AddPrefix, $g_NoPrefix;
    array_walk($par_Arr, function(&$n) {
        global $g_AddPrefix, $g_NoPrefix;
        $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
    });

    return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $vars, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_NoPrefix, $g_AddPrefix;

    $i = 0;

    if ($par_TableName == null) {
        $par_TableName = 'table_' . rand(1000000, 9000000);
    }

    $l_Result = '';
    $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";

    $l_Result .= "<thead><tr class=\"tbgh" . ($i % 2) . "\">";
    $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
    $l_Result .= "<th>" . AI_STR_005 . "</th>";
    $l_Result .= "<th>" . AI_STR_006 . "</th>";
    $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
    $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";

    $l_Result .= "</tr></thead><tbody>";

    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_z' . rand(1000000, 9000000);
        }

        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($vars->structure['n'][$par_List[$i]], $vars->structure['crc'][$l_Pos])) {
                continue;
            }
        }

        $l_Creat = $vars->structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $vars->structure['c'][$l_Pos]) : '-';
        $l_Modif = $vars->structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $vars->structure['m'][$l_Pos]) : '-';
        $l_Size  = $vars->structure['s'][$l_Pos] > 0 ? bytes2Human($vars->structure['s'][$l_Pos]) : '-';

        if ($par_Details != null) {
            $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
            $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
            $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);

            $l_Body = '<div class="details">';

            if ($par_SigId != null) {
                $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
            }

            $l_Body .= $l_WithMarker . '</div>';
        } else {
            $l_Body = '';
        }

        $l_Result .= '<tr class="tbg' . ($i % 2) . '" o="' . $l_SigId . '">';

        if (is_file($vars->structure['n'][$l_Pos])) {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $vars->structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
        } else {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $vars->structure['n'][$par_List[$i]])) . '</a></div></td>';
        }

        $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $vars->structure['crc'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $vars->structure['m'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
        $l_Result .= '</tr>';

    }

    $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";

    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $vars, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_NoPrefix, $g_AddPrefix;

    $l_Result = "";

    $l_Src = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;'
    );
    $l_Dst = array(
        '"',
        '<',
        '>',
        '&',
        '\''
    );

    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($vars->structure['n'][$par_List[$i]], $vars->structure['crc'][$l_Pos])) {
                continue;
            }
        }


        if ($par_Details != null) {

            $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
            $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
            $l_Body = str_replace($l_Src, $l_Dst, $l_Body);

        } else {
            $l_Body = '';
        }

        if (is_file($vars->structure['n'][$l_Pos])) {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $vars->structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
        } else {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $vars->structure['n'][$par_List[$i]]) . "\n";
        }

    }

    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
    if (preg_match('|<tr><td class="e">\s*' . $par_Name . '\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
        return str_replace('no value', '', strip_tags($l_Result[1]));
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
    $l_PhpInfoSystem    = extractValue($par_Str, 'System');
    $l_PhpPHPAPI        = extractValue($par_Str, 'Server API');
    $l_AllowUrlFOpen    = extractValue($par_Str, 'allow_url_fopen');
    $l_AllowUrlInclude  = extractValue($par_Str, 'allow_url_include');
    $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
    $l_DisplayErrors    = extractValue($par_Str, 'display_errors');
    $l_ErrorReporting   = extractValue($par_Str, 'error_reporting');
    $l_ExposePHP        = extractValue($par_Str, 'expose_php');
    $l_LogErrors        = extractValue($par_Str, 'log_errors');
    $l_MQGPC            = extractValue($par_Str, 'magic_quotes_gpc');
    $l_MQRT             = extractValue($par_Str, 'magic_quotes_runtime');
    $l_OpenBaseDir      = extractValue($par_Str, 'open_basedir');
    $l_RegisterGlobals  = extractValue($par_Str, 'register_globals');
    $l_SafeMode         = extractValue($par_Str, 'safe_mode');

    $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
    $l_OpenBaseDir      = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);

    $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
    $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
    $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI . '</span><br/>';
    $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen . '</span><br/>';
    $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude . '</span><br/>';
    $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction . '</span><br/>';
    $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors . '</span><br/>';
    $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting . '</span><br/>';
    $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP . '</span><br/>';
    $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
    $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC . '</span><br/>';
    $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT . '</span><br/>';
    $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
    $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';

    if (phpversion() < '5.3.0') {
        $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode . '</span><br/>';
    }

    return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
function addSlash($dir) {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
    if (!DEBUG_MODE) {
        return;
    }

    $l_MemInfo = ' ';
    if (function_exists('memory_get_usage')) {
        $l_MemInfo .= ' curmem=' . bytes2Human(memory_get_usage());
    }

    if (function_exists('memory_get_peak_usage')) {
        $l_MemInfo .= ' maxmem=' . bytes2Human(memory_get_peak_usage());
    }

    stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir, $vars) {
    global $defaults, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, $g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;

    static $l_Buffer = '';

    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $vars->counter - 1;

    $l_SkipSample = array();

    QCR_Debug('Scan ' . $l_RootDir);

    $l_QuotedSeparator = quotemeta(DIR_SEPARATOR);
    $l_DIRH = @opendir($l_RootDir);
    if ($l_DIRH === false) {
        return;
    }
    while (($l_FileName = readdir($l_DIRH)) !== false) {
            
        if ($l_FileName == '.' || $l_FileName == '..') {
            continue;
        }
        $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
        $l_Type = filetype($l_FileName);
            
        if ($l_Type == "link") {
            $vars->symLinks[] = $l_FileName;
            continue;
        } 
        elseif ($l_Type != "file" && $l_Type != "dir") {
            continue;
        }

        $l_Ext   = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
        $l_IsDir = is_dir($l_FileName);
            
        // which files should be scanned
        $l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));

        if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {
            $l_NeedToScan = false;
        }

        // if folder in ignore list
        $l_Skip = false;
        for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
            if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                    $l_SkipSample[] = $g_DirIgnoreList[$dr];
                } 
                else {
                    $l_Skip       = true;
                    $l_NeedToScan = false;
                }
            }
        }

        if ($l_IsDir) {
            // skip on ignore
            if ($l_Skip) {
                $vars->skippedFolders[] = $l_FileName;
                continue;
            }

            $l_BaseName = basename($l_FileName);

            if (ONE_PASS) {
                $vars->structure['n'][$vars->counter] = $l_FileName . DIR_SEPARATOR;
            } 
            else {
                $l_Buffer .= FilepathEscaper::encodeFilepathByBase64($l_FileName . DIR_SEPARATOR) . "\n";
            }

            $l_DirCounter++;

            if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                $vars->doorway[]  = $l_SourceDirIndex;
                $l_DirCounter = -655360;
            }

            $vars->counter++;
            $vars->foundTotalDirs++;

            QCR_ScanDirectories($l_FileName, $vars);
        } 
        elseif ($l_NeedToScan) {
            $vars->foundTotalFiles++;
            if (in_array($l_Ext, $g_ShortListExt)) {
                $l_DoorwayFilesCounter++;

                if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $vars->doorway[]           = $l_SourceDirIndex;
                    $l_DoorwayFilesCounter = -655360;
                }
            }

            if (ONE_PASS) {
                QCR_ScanFile($l_FileName, $vars, null, $vars->counter++);
            } 
            else {
                $l_Buffer .= FilepathEscaper::encodeFilepathByBase64($l_FileName) . "\n";
            }

            $vars->counter++;
        }

        if (strlen($l_Buffer) > 32000) {
            file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
            $l_Buffer = '';
        }

    }

    closedir($l_DIRH);

    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }

}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
//echo "\n *********** --------------------------------------------------------\n";

    $l_MaxChars = MAX_PREVIEW_LEN;

    $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

    $l_MaxLen   = strlen($par_Content);
    $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
    $l_MinPos   = max(0, $par_Pos - $l_MaxChars);

    $l_FoundStart = substr($par_Content, 0, $par_Pos);
    $l_FoundStart = str_replace("\r", '', $l_FoundStart);
    $l_LineNo     = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

//echo "\nMinPos=" . $l_MinPos . " Pos=" . $par_Pos . " l_RightPos=" . $l_RightPos . "\n";
//var_dump($par_Content);
//echo "\n-----------------------------------------------------\n";


    $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

    $l_Res = makeSafeFn(UnwrapObfu($l_Res));

    $l_Res = str_replace('~', ' ', $l_Res);

    $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);

    $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

//echo "\nFinal:\n";
//var_dump($l_Res);
//echo "\n-----------------------------------------------------\n";
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(hexdec($escaped[1]));
}
function escapedOctDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(octdec($escaped[1]));
}
function escapedDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr($escaped[1]);
}

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
    define('T_ML_COMMENT', T_COMMENT);
} else {
    define('T_DOC_COMMENT', T_ML_COMMENT);
}

function UnwrapObfu($par_Content) {
    $GLOBALS['g_EncObfu'] = 0;

    $search      = array(
        ' ;',
        ' =',
        ' ,',
        ' .',
        ' (',
        ' )',
        ' {',
        ' }',
        '; ',
        '= ',
        ', ',
        '. ',
        '( ',
        '( ',
        '{ ',
        '} ',
        ' !',
        ' >',
        ' <',
        ' _',
        '_ ',
        '< ',
        '> ',
        ' $',
        ' %',
        '% ',
        '# ',
        ' #',
        '^ ',
        ' ^',
        ' &',
        '& ',
        ' ?',
        '? '
    );
    $replace     = array(
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        '!',
        '>',
        '<',
        '_',
        '_',
        '<',
        '>',
        '$',
        '%',
        '%',
        '#',
        '#',
        '^',
        '^',
        '&',
        '&',
        '?',
        '?'
    );
    $par_Content = str_replace('@', '', $par_Content);
    $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
    $par_Content = str_replace($search, $replace, $par_Content);
    $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) {
        return "'" . chr(intval($m[1], 0)) . "'";
    }, $par_Content);

    $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', 'escapedHexToHex', $par_Content);
    $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i', 'escapedOctDec', $par_Content);

    $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
    $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);

    $content = str_replace('<?$', '<?php$', $content);
    $content = str_replace('<?php', '<?php ', $content);

    return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define('UTF32_BIG_ENDIAN_BOM', chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define('UTF16_BIG_ENDIAN_BOM', chr(0xFE) . chr(0xFF));
define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define('UTF8_BOM', chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);

    if ($first3 == UTF8_BOM)
        return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM)
        return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM)
        return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM)
        return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM)
        return 'UTF-16LE';

    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src) {
    if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }

    if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }

    return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
    global $g_UrlIgnoreList;

    for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
        if (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
            return true;
        }
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
    return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content, $vars) {
    global $g_CmsListDetector;

    if (!($g_CmsListDetector instanceof CmsVersionDetector)) {
        return false;
    }

    $l_Vuln = array();

    $par_Filename = strtolower($par_Filename);

    if ((strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) && (strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)) {
        $l_Vuln['id']   = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
        $l_Vuln['ndx']  = $par_Index;
        $vars->vulnerable[] = $l_Vuln;
        return true;
    }

    if ((strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) && (strpos($par_Content, '$format == \'\' || $format == false ||') === false)) {
        if ($g_CmsListDetector->isCms(CmsVersionDetector::CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if ((strpos($par_Filename, 'joomla/filesystem/file.php') !== false) && (strpos($par_Content, '$file = rtrim($file, \'.\');') === false)) {
        if ($g_CmsListDetector->isCms(CmsVersionDetector::CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) || (stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) || (stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) || (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
        $l_Vuln['id']   = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
        $l_Vuln['ndx']  = $par_Index;
        $vars->vulnerable[] = $l_Vuln;
        return true;
    }

    if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) || (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
        if (strpos($par_Content, 'showImageByID') === false) {
            $l_Vuln['id']   = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) || (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
        $l_Vuln['id']   = 'AFU : elFinder';
        $l_Vuln['ndx']  = $par_Index;
        $vars->vulnerable[] = $l_Vuln;
        return true;
    }

    if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
        if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
            $l_Vuln['id']   = 'SQLI : DRUPAL : CVE-2014-3704';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
        if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
            $l_Vuln['id']   = 'AFD : MINIFY : CVE-2013-6619';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if ((strpos($par_Filename, 'timthumb.php') !== false) || (strpos($par_Filename, 'thumb.php') !== false) || (strpos($par_Filename, 'cache.php') !== false) || (strpos($par_Filename, '_img.php') !== false)) {
        if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false) {
            $l_Vuln['id']   = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
        if (preg_match('~define\s*\(\s*\'_rsform_version\'\s*,\s*\'([^\']+)\'\s*\)\s*;~msi', $par_Content, $version)) {
            $version = $version[1];
            if (version_compare($version, '1.5.2') !== 1) {
                $l_Vuln['id']   = 'RCE : RSFORM : rsform.php, LINE 1605';
                $l_Vuln['ndx']  = $par_Index;
                $vars->vulnerable[] = $l_Vuln;
                return true;
            }
        }
        return false;
    }


    if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
        if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : FANCYBOX';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }


    if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
        if (strpos($par_Content, 'verify nonce') === false) {
            $l_Vuln['id']   = 'AFU : Cherry Plugin';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }


    if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {
        $l_Vuln['id']   = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
        $l_Vuln['ndx']  = $par_Index;
        $vars->vulnerable[] = $l_Vuln;

        return true;
    }

    if (strpos($par_Filename, '/bx_1c_import.php') !== false) {
        if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
            $l_Vuln['id']   = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;

            return true;
        }
    }

    if (strpos($par_Filename, 'scripts/setup.php') !== false) {
        if (strpos($par_Content, 'PMA_Config') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, '/uploadify.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
            $l_Vuln['id']   = 'AFU : UPLOADIFY : CVE: 2012-1153';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
            $l_Vuln['id']   = 'AFU : https://github.com/rorry47/ai-bolit';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {
        if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
            $l_Vuln['id']   = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }


    if (strpos($par_Filename, 'core/lib/drupal.php') !== false) {
        $version = '';
        if (preg_match('|VERSION\s*=\s*\'(8\.\d+\.\d+)\'|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }

        if (($version !== '') && (version_compare($version, '8.5.1', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }


        return false;
    }

    if (strpos($par_Filename, 'changelog.txt') !== false) {
        $version = '';
        if (preg_match('|Drupal\s+(7\.\d+),|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }

        if (($version !== '') && (version_compare($version, '7.58', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $vars->vulnerable[] = $l_Vuln;
            return true;
        }

        return false;
    }

    if (strpos($par_Filename, 'phpmailer.php') !== false) {
        $l_Detect = false;
        if (strpos($par_Content, 'PHPMailer') !== false) {
            $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);

            if ($l_Found) {
                $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];

                if ($l_Version < 2520) {
                    $l_Detect = true;
                }
            }

            if (!$l_Found) {

                $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~i', $par_Content, $l_Match);
                if ($l_Found) {
                    $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                    if ($l_Version < 5220) {
                        $l_Detect = true;
                    }
                }
            }


            if ($l_Detect) {
                $l_Vuln['id']   = 'RCE : CVE-2016-10045, CVE-2016-10031';
                $l_Vuln['ndx']  = $par_Index;
                $vars->vulnerable[] = $l_Vuln;
                return true;
            }
        }

        return false;
    }
}

///////////////////////////////////////////////////////////////////////////
function CloudAssitedFilter($files_list, &$vars)
{
    $black_files = [];
    $white_files = [];
    try {
        $car                = Factory::instance()->create(CloudAssistedRequest::class, [CLOUD_ASSIST_TOKEN]);
        $cloud_assist_files = new CloudAssistedFiles($car, $files_list);
        $white_files        = $cloud_assist_files->getWhiteList();
        $black_files        = $cloud_assist_files->getBlackList();
        unset($cloud_assist_files);
    }
    catch (\Exception $e) {
        QCR_Debug($e->getMessage());
    }
    $vars->blackFiles = array_merge($vars->blackFiles, $black_files);
    return array_diff($files_list, array_keys($black_files), array_keys($white_files));
}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($s_file, $vars, $callback = null, $base64_encoded = true, $skip_first_line = false)
{
    QCR_Debug('QCR_GoScan ');
    try {
        $i = 0;
        $filesForCloudAssistedScan = [];

        foreach ($s_file as $index => $filepath_encoded) {
            if ($skip_first_line && $index == 0) {
                $i = 1;
                continue;
            }

            $filepath = $base64_encoded ? FilepathEscaper::decodeFilepathByBase64($filepath_encoded) : $filepath_encoded;
            $filepath = trim($filepath);

            if (!file_exists($filepath) || !is_file($filepath) || !is_readable($filepath)) {
                stdOut("Error:" . $filepath . " either is not a file or readable");
                continue;
            }
            
            $filesize = filesize($filepath);
            if ($filesize > MAX_FILE_SIZE_FOR_CHECK) {
                stdOut('Error:' . $filepath . ' is too big');
                continue;
            }

            if (substr($filepath, -1) == DIR_SEPARATOR || !defined('CLOUD_ASSIST_TOKEN')) {
                QCR_ScanFile($filepath, $vars, $callback, $i++);
                continue;
            }
            
            if (isFileTooBigForCloudscan($filesize)) {
                QCR_ScanFile($filepath, $vars, $callback, $i++);
                continue;
            }

            // collecting files to scan with Cloud Assistant
            $filesForCloudAssistedScan[] = $filepath;
        }

        if (count($filesForCloudAssistedScan) == 0) {
            return;
        }

        if (defined('RAPID_ACCOUNT_SCAN')) {
            $cloud_assited_storage = Factory::instance()->create(CloudAssistedStorage::class, [RAPID_ACCOUNT_SCAN]);
            $storage = Factory::instance()->create(RapidScanStorage::class, [RAPID_ACCOUNT_SCAN]);
            /** @var RapidAccountScan $scanner */
            $scanner = Factory::instance()->create(RapidAccountScan::class, [$storage, $cloud_assited_storage, &$vars, $i]);
            $scanner->scan($filesForCloudAssistedScan, $vars, constant('RapidAccountScan::RESCAN_' . RAPID_ACCOUNT_SCAN_TYPE));
            if ($scanner->getStrError()) {
                QCR_Debug('Rapid scan log: ' . $scanner->getStrError());
            }
            $vars->rescanCount += $scanner->getRescanCount();
        } else {
            $scan_bufer_files = function ($files_list, &$i) use ($callback, $vars) {
                $files_to_scan = CloudAssitedFilter($files_list, $vars);
                foreach ($files_to_scan as $filepath) {
                    QCR_ScanFile($filepath, $vars, $callback, $i++);
                }
            };
            $files_bufer = [];
            foreach ($filesForCloudAssistedScan as $l_Filename) {
                $files_bufer[] = $l_Filename;
                if (count($files_bufer) >= CLOUD_ASSIST_LIMIT) {
                    $scan_bufer_files($files_bufer, $i);
                    $files_bufer = [];
                }
            }
            if (count($files_bufer)) {
                $scan_bufer_files($files_bufer, $i);
            }
            unset($files_bufer);
        }
    } catch (Exception $e) {
        QCR_Debug($e->getMessage());
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $vars, $callback = null, $i = 0, $show_progress = true)
{
    static $_files_and_ignored = 0;
    
    $return = array(RapidScanStorageRecord::RX_GOOD, '', '');

    $g_Content = '';
    $vars->crc = 0;

    $l_CriticalDetected = false;
    $l_Stat             = stat($l_Filename);

    if (substr($l_Filename, -1) == DIR_SEPARATOR) {
        // FOLDER
        $vars->structure['n'][$i] = $l_Filename;
        $vars->totalFolder++;
        printProgress($_files_and_ignored, $l_Filename, $vars);

        return null;
    }

    QCR_Debug('Scan file ' . $l_Filename);
    if ($show_progress) {
        printProgress(++$_files_and_ignored, $l_Filename, $vars);
    }

    $fd = @fopen($l_Filename, 'r');
    $firstFourBytes = @fread($fd, 4);
    @fclose($fd);

    if ($firstFourBytes === chr(127) . 'ELF') {
        if(defined('USE_HEURISTICS') || defined('USE_HEURISTICS_SUSPICIOUS')) {
            $vars->crc = sha1_file($l_Filename);
            AddResult($l_Filename, $i, $vars, $g_Content);

            if (defined('USE_HEURISTICS')) {
                $vars->criticalPHP[] = $i;
                $vars->criticalPHPFragment[] = 'SMW-HEUR-ELF';
                $vars->criticalPHPSig[] = 'SMW-HEUR-ELF';
            }

            if (defined('USE_HEURISTICS_SUSPICIOUS')) {
                $vars->warningPHP[] = $i;
                $vars->warningPHPFragment[] = 'SMW-HEUR-ELF';
                $vars->warningPHPSig[] = 'SMW-HEUR-ELF';
            }

            $return = array(RapidScanStorageRecord::HEURISTIC, 'SMW-HEUR-ELF', 'SMW-HEUR-ELF');

            return $return;
        }

        return null;
    }

    // FILE
    $is_too_big = isFileTooBigForScanWithSignatures($l_Stat['size']);
    $hash = sha1_file($l_Filename);
    if (check_binmalware($hash, $vars)) {
        $vars->totalFiles++;

        $vars->crc = $hash;

        AddResult($l_Filename, $i, $vars, $g_Content);

        $vars->criticalPHP[] = $i;
        $vars->criticalPHPFragment[] = "BIN-" . $vars->crc;
        $vars->criticalPHPSig[] = "bin_" . $vars->crc;
        $return = array(RapidScanStorageRecord::RX_MALWARE, "bin_" . $vars->crc, "BIN-" . $vars->crc);
    } elseif (!MAX_SIZE_SCAN_BYTES && $is_too_big) {
        $vars->bigFiles[] = $i;

        if (function_exists('aibolit_onBigFile')) {
            aibolit_onBigFile($l_Filename);
        }

        AddResult($l_Filename, $i, $vars, $g_Content);

        /** @var CriticalFileSpecification $criticalFileSpecification */
        $criticalFileSpecification = Factory::instance()->create(CriticalFileSpecification::class);
        if ((!AI_HOSTER) && $criticalFileSpecification->satisfiedBy($l_Filename)) {
            $vars->criticalPHP[]         = $i;
            $vars->criticalPHPFragment[] = "BIG FILE. SKIPPED.";
            $vars->criticalPHPSig[]      = "big_1";
        }
    } else {
        $vars->totalFiles++;

        $l_TSStartScan = microtime(true);

        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        $l_Content = '';

        if (filetype($l_Filename) == 'file') {
            if ($is_too_big && MAX_SIZE_SCAN_BYTES) {
                $handle     = @fopen($l_Filename, 'r');
                $l_Content  = @fread($handle, MAX_SIZE_SCAN_BYTES);
                @fclose($handle);
            } else {
                $l_Content  = @file_get_contents($l_Filename);
            }
            $l_Unwrapped = @php_strip_whitespace($l_Filename);
            $g_Content = $l_Content;
        }

        if (($l_Content == '' || $l_Unwrapped == '') && $l_Stat['size'] > 0) {
            $vars->notRead[] = $i;
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 'io');
            }
            $return = array(RapidScanStorageRecord::CONFLICT, 'notread','');
            AddResult('[io] ' . $l_Filename, $i, $vars, $g_Content);
            return $return;
        }

        // ignore itself
        if (strpos($l_Content, '0c26723daf5c1cbeafb4b34be8b8a363') !== false) {
            return false;
        }

        $vars->crc = _hash_($l_Unwrapped);

        $l_UnicodeContent = detect_utf_encoding($l_Content);
        //$l_Unwrapped = $l_Content;

        // check vulnerability in files
        $l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content, $vars);

        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
            } else {
                $vars->notRead[] = $i;
                if (function_exists('aibolit_onReadError')) {
                    aibolit_onReadError($l_Filename, 'ec');
                }
                $return = array(RapidScanStorageRecord::CONFLICT, 'no_iconv', '');
                AddResult('[ec] ' . $l_Filename, $i, $vars, $g_Content);
            }
        }

        // critical
        $g_SkipNextCheck = false;

        if ((!AI_HOSTER) || AI_DEOBFUSCATE) {
            $l_DeobfObj = new Deobfuscator($l_Unwrapped, $l_Content);
            $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        }

        if ($l_DeobfType != '') {
            $hangs = 0;
            while($l_DeobfObj->getObfuscateType($l_Unwrapped)!=='' && $hangs < 10) {
                $l_Unwrapped = $l_DeobfObj->deobfuscate();
                $l_DeobfObj = new Deobfuscator($l_Unwrapped);
                $hangs++;
            }
            $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
        } else {
            if (DEBUG_MODE) {
                stdOut("\n...... NOT OBFUSCATED\n");
            }
        }

        $l_Unwrapped = UnwrapObfu($l_Unwrapped);

        if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId)) {
            if ($l_Ext == 'js') {
                $vars->criticalJS[]         = $i;
                $vars->criticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $vars->criticalJSSig[]      = $l_SigId;
            } else {
                $vars->criticalPHP[]         = $i;
                $vars->criticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $vars->criticalPHPSig[]      = $l_SigId;
            }
            $return = array(RapidScanStorageRecord::RX_MALWARE, $l_SigId, getFragment($l_Unwrapped, $l_Pos));
            $g_SkipNextCheck = true;
        } else {
            if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId)) {
                if ($l_Ext == 'js') {
                    $vars->criticalJS[]         = $i;
                    $vars->criticalJSFragment[] = getFragment($l_Content, $l_Pos);
                    $vars->criticalJSSig[]      = $l_SigId;
                } else {
                    $vars->criticalPHP[]         = $i;
                    $vars->criticalPHPFragment[] = getFragment($l_Content, $l_Pos);
                    $vars->criticalPHPSig[]      = $l_SigId;
                }
                $return = array(RapidScanStorageRecord::RX_MALWARE, $l_SigId, getFragment($l_Content, $l_Pos));
                $g_SkipNextCheck = true;
            }
        }

        $l_TypeDe = 0;

        // critical JS
        if (!$g_SkipNextCheck) {
            $l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos !== false) {
                if ($l_Ext == 'js') {
                    $vars->criticalJS[]         = $i;
                    $vars->criticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $vars->criticalJSSig[]      = $l_SigId;
                } else {
                    $vars->criticalPHP[]         = $i;
                    $vars->criticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $vars->criticalPHPSig[]      = $l_SigId;
                }
                $return = array(RapidScanStorageRecord::RX_MALWARE, $l_SigId, getFragment($l_Unwrapped, $l_Pos));
                $g_SkipNextCheck = true;
            }
        }

        // warnings (suspicious)
        if (!$g_SkipNextCheck) {
            $l_Pos = WarningPHP($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos !== false) {
                $vars->warningPHP[]         = $i;
                $vars->warningPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $vars->warningPHPSig[]      = $l_SigId;

                $return = array(RapidScanStorageRecord::RX_SUSPICIOUS, $l_SigId, getFragment($l_Unwrapped, $l_Pos)) ;
                $g_SkipNextCheck = true;
            }
        }

        // phishing
        if (!$g_SkipNextCheck) {
            $l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId, $vars);
            if ($l_Pos === false) {
                $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId, $vars);
            }

            if ($l_Pos !== false) {
                $vars->phishing[]            = $i;
                $vars->phishingFragment[]    = getFragment($l_Unwrapped, $l_Pos);
                $vars->phishingSigFragment[] = $l_SigId;

                $return = array(RapidScanStorageRecord::RX_SUSPICIOUS, $l_SigId, getFragment($l_Unwrapped, $l_Pos));
                $g_SkipNextCheck         = true;
            }
        }

        if (!$g_SkipNextCheck) {
            // warnings
            $l_Pos = '';

            // adware
            if (Adware($l_Filename, $l_Unwrapped, $l_Pos)) {
                $vars->adwareList[]         = $i;
                $vars->adwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $l_CriticalDetected     = true;
            }

            // articles
            if (stripos($l_Filename, 'article_index')) {
                $vars->adwareList[]     = $i;
                $l_CriticalDetected = true;
            }
        }
    } // end of if (!$g_SkipNextCheck) {

    //printProgress(++$_files_and_ignored, $l_Filename);
    delayWithCallback(SCAN_DELAY, $callback);
    $l_TSEndScan = microtime(true);
    if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
        delayWithCallback(SCAN_DELAY, $callback);
    }

    if ($g_SkipNextCheck || $l_CriticalDetected) {
        AddResult($l_Filename, $i, $vars, $g_Content);
    }

    unset($l_Unwrapped);
    unset($l_Content);

    return $return;
}

function callCallback($callback)
{
    if ($callback !== null) {
        call_user_func($callback);
    }
}

function delayWithCallback($delay, $callback)
{
    $delay = $delay * 1000;
    callCallback($callback);
    while ($delay > 500000) {
        $delay -= 500000;
        usleep(500000);
        callCallback($callback);
    }
    usleep($delay);
    callCallback($callback);
}

function AddResult($l_Filename, $i, $vars, $g_Content = '')
{
    $l_Stat                 = stat($l_Filename);
    if (!isFileTooBigForScanWithSignatures($l_Stat['size']) && $g_Content == '') {
        $g_Content = file_get_contents($l_Filename);
    }
    $vars->structure['n'][$i]   = $l_Filename;
    $vars->structure['s'][$i]   = $l_Stat['size'];
    $vars->structure['c'][$i]   = $l_Stat['ctime'];
    $vars->structure['m'][$i]   = $l_Stat['mtime'];
    $vars->structure['e'][$i]   = time();
    $vars->structure['crc'][$i] = $vars->crc;

    if ($g_Content !== '') {
        $vars->structure['sha256'][$i] = hash('sha256', $g_Content);
        $g_Content = '';
    }
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_SusDB, $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;

    if (AI_EXTRA_WARN) {
        foreach ($g_SusDB as $l_Item) {
            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    return $l_Pos;
                }
            }
        }
    }
    return false;

}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos) {
    global $g_AdwareSig;

    $l_Res = false;

    foreach ($g_AdwareSig as $l_Item) {
        $offset = 0;
        while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos = $l_Found[0][1];
                return true;
            }

            $offset = $l_Found[0][1] + 1;
        }
    }

    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
    global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

    foreach ($g_ExceptFlex as $l_ExceptItem) {
        if (@preg_match('~' . $l_ExceptItem . '~smi', $l_FoundStrPlus, $l_Detected)) {
            return true;
        }
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId, $vars) {
    global $g_PhishFiles, $g_PhishEntries, $g_PhishingSig;

    $l_Res = false;

    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;

    if ($l_SkipCheck) {
        foreach ($g_PhishFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }

    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }

    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped phs file, not critical.\n";
        }

        return false;
    }

    foreach ($g_PhishingSig as $l_Item) {
        $offset = 0;
        while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);

                if (DEBUG_MODE) {
                    echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
                }

                return $l_Pos;
            }
            $offset = $l_Found[0][1] + 1;

        }
    }

    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;

    $l_Res = false;

    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;

    if ($l_SkipCheck) {
        foreach ($g_VirusFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }

    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }

    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped js file, not critical.\n";
        }

        return false;
    }


    foreach ($g_JSVirSig as $l_Item) {
        $offset = 0;
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }

        while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {

            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);

                if (DEBUG_MODE) {
                    echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
                }

                return $l_Pos;
            }

            $offset = $l_Found[0][1] + 1;

        }

        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }

    }

    if (AI_EXPERT > 1) {
        foreach ($gX_JSVirSig as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = getSigId($l_Found);

                    if (DEBUG_MODE) {
                        echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
                    }

                    return $l_Pos;
                }
            }

            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }

        }
    }

    return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

function get_descr_heur($type) {
    switch ($type) {
        case SUSP_MTIME:
            return AI_STR_077;
        case SUSP_PERM:
            return AI_STR_078;
        case SUSP_PHP_IN_UPLOAD:
            return AI_STR_079;
    }

    return "---";
}

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment, $g_CriticalEntries, $g_RegExpStat;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;

    if ($l_SkipCheck) {
        /** @var CriticalFileSpecification $criticalFileSpecification */
        $criticalFileSpecification = Factory::instance()->create(CriticalFileSpecification::class);

        if ($criticalFileSpecification->satisfiedBy($l_FN) && (strpos($l_FN, '.js') === false)) {
            $l_SkipCheck = false;
        }
    }

    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    

    // if not critical - skip it 
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped file, not critical.\n";
        }

        return false;
    }

    foreach ($g_FlexDBShe as $l_Item) {
        $offset = 0;

        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }

        while (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                //$l_SigId = myCheckSum($l_Item);
                $l_SigId = getSigId($l_Found);

                if (DEBUG_MODE) {
                    echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }

            $offset = $l_Found[0][1] + 1;

        }

        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }

    }

    if (AI_EXPERT > 0) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);

                    if (DEBUG_MODE) {
                        echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }

        }
    }

    if (AI_EXPERT > 1) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);

                    if (DEBUG_MODE) {
                        echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }

        }
    }

    $l_Content_lo = strtolower($l_Content);

    foreach ($g_DBShe as $l_Item) {
        $l_Pos = strpos($l_Content_lo, $l_Item);
        if ($l_Pos !== false) {
            $l_SigId = myCheckSum($l_Item);

            if (DEBUG_MODE) {
                echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
            }

            return true;
        }
    }

    if (AI_EXPERT > 0) {
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);

                if (DEBUG_MODE) {
                    echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
    }

    if (AI_HOSTER)
        return false;

    if (AI_EXPERT > 0) {
        if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false)) {
            $l_Pos = 0;

            if (DEBUG_MODE) {
                echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
            }

            return true;
        }
    }

    // detect uploaders / droppers
    if (AI_EXPERT > 1) {
        $l_Found = null;
        if ((filesize($l_FN) < 2048) && (strpos($l_FN, '.ph') !== false) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
            }
            if (DEBUG_MODE) {
                echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
            }

            return true;
        }
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
    header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {

    $l_PassOK = false;
    if (strlen(PASS) > 8) {
        $l_PassOK = true;
    }

    if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found)) {
        $l_PassOK = true;
    }

    if (!$l_PassOK) {
        echo sprintf(AI_STR_009, generatePassword());
        exit;
    }

    if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
        printFile();
        exit;
    }

    if ($_GET['p'] != PASS) {
        $generated_pass = generatePassword();
        echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
        exit;
    }
}

if (!is_readable(ROOT_PATH)) {
    echo AI_STR_011;
    exit;
}

if (isCli()) {
    if (defined('REPORT_PATH') AND REPORT_PATH) {
        if (!is_writable(REPORT_PATH)) {
            die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
        }

        else if (!REPORT_FILE) {
            die2("\nCannot write report. Report filename is empty.");
        }

        else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file)) {
            die2("\nCannot write report. Report file '$file' exists but is not writable.");
        }
    }
}


// detect version CMS
$g_KnownCMS        = array();
$tmp_cms           = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum  = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $vars->CMS[]                                              = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
    $g_KnownCMS = array_keys($tmp_cms);
    $len        = count($g_KnownCMS);
    for ($i = 0; $i < $len; $i++) {
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_WORDPRESS))
            $g_KnownCMS[] = 'wp';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_WEBASYST))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_IPB))
            $g_KnownCMS[] = 'ipb';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_DLE))
            $g_KnownCMS[] = 'dle';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_INSTANTCMS))
            $g_KnownCMS[] = 'instantcms';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_SHOPSCRIPT))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CmsVersionDetector::CMS_DRUPAL))
            $g_KnownCMS[] = 'drupal';
    }
}


$g_DirIgnoreList = array();
$g_IgnoreList    = array();
$g_UrlIgnoreList = array();
$g_KnownList     = array();

$l_IgnoreFilename    = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) {
        $g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);

    for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
        $g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
    }
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);

    for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
        $g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
    }
}


$l_SkipMask = array(
    '/template_\w{32}.css',
    '/cache/templates/.{1,150}\.tpl\.php',
    '/system/cache/templates_c/\w{1,40}\.php',
    '/assets/cache/rss/\w{1,60}',
    '/cache/minify/minify_\w{32}',
    '/cache/page/\w{32}\.php',
    '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
    '/cache/wp-cache-\d{32}\.php',
    '/cache/page/\w{32}\.php_expire',
    '/cache/page/\w{32}-cache-page-\w{32}\.php',
    '\w{32}-cache-com_content-\w{32}\.php',
    '\w{32}-cache-mod_custom-\w{32}\.php',
    '\w{32}-cache-mod_templates-\w{32}\.php',
    '\w{32}-cache-_system-\w{32}\.php',
    '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php',
    '/autoptimize/js/autoptimize_\w{32}\.js',
    '/bitrix/cache/\w{32}\.php',
    '/bitrix/cache/.{1,200}/\w{32}\.php',
    '/bitrix/cache/iblock_find/',
    '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
    '/bitrix/cache/s1/bitrix/catalog\.section/',
    '/bitrix/cache/s1/bitrix/catalog\.element/',
    '/bitrix/cache/s1/bitrix/menu/',
    '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
    '/bitrix/managed\_cache/.{1,150}/\.\w{32}\.php',
    '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
    '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
    '/smarty/compiled/SC/.{1,100}/%%.{1,200}\.php',
    '/smarty/.{1,150}\.tpl\.php',
    '/smarty/compile/.{1,150}\.tpl\.cache\.php',
    '/files/templates_c/.{1,150}\.html\.php',
    '/uploads/javascript_global/.{1,150}\.js',
    '/assets/cache/rss/\w{32}',
    'сore/cache/resource/web/resources/\d+\.cache\.php',
    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
    '/t3-assets/dev/t3/.{1,150}-cache-\w{1,20}-.{1,150}\.php',
    '/t3-assets/js/js-\w{1,30}\.js',
    '/temp/cache/SC/.{1,100}/\.cache\..{1,100}\.php',
    '/tmp/sess\_\w{32}$',
    '/assets/cache/docid\_.{1,100}\.pageCache\.php',
    '/stat/usage\_\w{1,100}\.html',
    '/stat/site\_\w{1,100}\.html',
    '/gallery/item/list/\w{1,100}\.cache\.php',
    '/core/cache/registry/.{1,100}/ext-.{1,100}\.php',
    '/core/cache/resource/shk\_/\w{1,50}\.cache\.php',
    '/cache/\w{1,40}/\w+-cache-\w+-\w{32,40}\.php',
    '/webstat/awstats.{1,150}\.txt',
    '/awstats/awstats.{1,150}\.txt',
    '/awstats/.{1,80}\.pl',
    '/awstats/.{1,80}\.html',
    '/inc/min/styles_\w+\.min\.css',
    '/inc/min/styles_\w+\.min\.js',
    '/logs/error\_log\.',
    '/logs/xferlog\.',
    '/logs/access_log\.',
    '/logs/cron\.',
    '/logs/exceptions/.{1,200}\.log$',
    '/hyper-cache/[^/]{1,50}/[^/]{1,50}/[^/]{1,50}/index\.html',
    '/mail/new/[^,]+,S=[^,]+,W=',
    '/mail/new/[^,]=,S=',
    '/application/logs/\d+/\d+/\d+\.php',
    '/sites/default/files/js/js_\w{32}\.js',
    '/yt-assets/\w{32}\.css',
    '/wp-content/cache/object/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/catalog\.section/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/simpla/design/compiled/[\w\.]{40,60}\.php',
    '/compile/\w{2}/\w{2}/\w{2}/[\w.]{40,80}\.php',
    '/sys-temp/static-cache/[^/]{1,60}/userCache/[\w\./]{40,100}\.php',
    '/session/sess_\w{32}',
    '/webstat/awstats\.[\w\./]{3,100}\.html',
    '/stat/webalizer\.current',
    '/stat/usage_\d+\.html'
);

$l_SkipSample = array();

if (SMART_SCAN) {
    $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures
if (file_exists($g_AiBolitAbsolutePath . "/ai-bolit.sig")) {
    try {
        $s_file = new SplFileObject($g_AiBolitAbsolutePath . "/ai-bolit.sig");
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        foreach ($s_file as $line) {
            $g_FlexDBShe[] = preg_replace('#\G(?:[^~\\\\]+|\\\\.)*+\K~#', '\\~', $line); // escaping ~
        }

        stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
        $s_file = null; // file handler is closed
    }
    catch (Exception $e) {
        QCR_Debug("Import ai-bolit.sig " . $e->getMessage());
    }
}

QCR_Debug();

$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
if ($defaults['skip_ext'] != '') {
    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
        $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
    }

    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
}

// scan single file
/**
 * @param Variables $vars
 * @param array $g_IgnoredExt
 * @param array $g_DirIgnoreList
 */
function processIntegrity(Variables $vars, array $g_IgnoredExt, array $g_DirIgnoreList)
{
    global $g_IntegrityDB;
// INTEGRITY CHECK
    IMAKE and unlink(INTEGRITY_DB_FILE);
    ICHECK and load_integrity_db();
    QCR_IntegrityCheck(ROOT_PATH, $vars);
    stdOut("Found $vars->foundTotalFiles files in $vars->foundTotalDirs directories.");
    if (IMAKE) {
        exit(0);
    }
    if (ICHECK) {
        $i = $vars->counter;
        $vars->crc = 0;
        $changes = array();
        $ref =& $g_IntegrityDB;
        foreach ($g_IntegrityDB as $l_FileName => $type) {
            unset($g_IntegrityDB[$l_FileName]);
            $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
            if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                continue;
            }
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName,
                        $l_Found)) {
                    continue 2;
                }
            }
            $type = in_array($type, array(
                'added',
                'modified'
            )) ? $type : 'deleted';
            $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
            $changes[$type][] = ++$i;
            AddResult($l_FileName, $i, $vars);
        }
        $vars->foundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
        stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
    }
}

if (isset($_GET['2check'])) {
    $options['with-2check'] = 1;
}

$use_doublecheck = isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE);
$use_listingfile = defined('LISTING_FILE');

$listing = false;

if ($use_doublecheck) {
    $listing = DOUBLECHECK_FILE;
} elseif ($use_listingfile) {
    $listing = LISTING_FILE;
}
$base64_encoded = INPUT_FILENAMES_BASE64_ENCODED;

try {
    if (defined('SCAN_FILE')) {
        // scan single file
        $filepath = INPUT_FILENAMES_BASE64_ENCODED ? FilepathEscaper::decodeFilepathByBase64(SCAN_FILE) : SCAN_FILE;
        stdOut("Start scanning file '" . $filepath . "'.");
        if (file_exists($filepath) && is_file($filepath) && is_readable($filepath)) {
            $s_file[] = $filepath;
            $base64_encoded = false;
        } else {
            stdOut("Error:" . $filepath . " either is not a file or readable");
        }
    } elseif ($listing) {
        //scan listing
        if ($listing == 'stdin') {
            $lines = explode("\n", getStdin());
        } else {
            $lines = new SplFileObject($listing);
            $lines->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        }
        if (is_array($lines)) {
            $vars->foundTotalFiles = count($lines);
        } else if ($lines instanceof SplFileObject) {
            $lines->seek($lines->getSize());
            $vars->foundTotalFiles = $lines->key();
            $lines->seek(0);
        }

        $s_file = $lines;
        stdOut("Start scanning the list from '" . $listing . "'.\n");
    } else {
        //scan by path
        $base64_encoded = true;
        file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
        QCR_ScanDirectories(ROOT_PATH, $vars);
        stdOut("Found $vars->foundTotalFiles files in $vars->foundTotalDirs directories.");
        stdOut("Start scanning '" . ROOT_PATH . "'.\n");
        if (ICHECK || IMAKE) {
            processIntegrity($vars);
        }

        QCR_Debug();
        stdOut(str_repeat(' ', 160), false);
        $s_file = new SplFileObject(QUEUE_FILENAME);
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
    }

    QCR_GoScan($s_file, $vars, null, $base64_encoded, $use_doublecheck);
    unset($s_file);
    @unlink(QUEUE_FILENAME);
    $vars->foundTotalDirs  = $vars->totalFolder;

    if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE)) {
        @unlink(PROGRESS_LOG_FILE);
    }
    if (CREATE_SHARED_MEMORY) {
        shmop_delete(SHARED_MEMORY);
    }
    if (defined('SHARED_MEMORY')) {
        shmop_close(SHARED_MEMORY);
    }
} catch (Exception $e) {
    QCR_Debug($e->getMessage());
}
QCR_Debug();

if (true) {
    $g_HeuristicDetected = array();
    $g_Iframer           = array();
    $g_Base64            = array();
}
/**
 * @param Variables $vars
 * @return array
 */
function whitelisting(Variables $vars)
{
// whitelist

    $snum = 0;
    $list = check_whitelist($vars->structure['crc'], $snum);
    $keys = array(
        'criticalPHP',
        'criticalJS',
        'g_Iframer',
        'g_Base64',
        'phishing',
        'adwareList',
        'g_Redirect',
        'warningPHP'
    );

    foreach ($keys as $p) {
        if (empty($vars->{$p})) {
            continue;
        }
        $p_Fragment = $p . 'Fragment';
        $p_Sig      = $p . 'Sig';
        
        if ($p == 'g_Redirect') {
            $p_Fragment = $p . 'PHPFragment';
        }
        elseif ($p == 'g_Phishing') {
            $p_Sig = $p . 'SigFragment';
        }

        $count = count($vars->{$p});
        for ($i = 0; $i < $count; $i++) {
            $id = $vars->{$p}[$i];
            if ($vars->structure['crc'][$id] !== 0 && in_array($vars->structure['crc'][$id], $list)) {
                unset($vars->{$p}[$i]);
                unset($vars->{$p_Sig}[$i]);
                unset($vars->{$p_Fragment}[$i]);
            }
        }

        $vars->{$p}             = array_values($vars->{$p});
        $vars->{$p_Fragment}    = array_values($vars->{$p_Fragment});
        if (!empty($vars->{$p_Sig})) {
            $vars->{$p_Sig} = array_values($vars->{$p_Sig});
        }
    }
    return array($snum, $i);
}

whitelisting($vars);


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
    $g_IframerFragment       = array();
    $g_Iframer               = array();
    $vars->redirect          = array();
    $vars->doorway           = array();
    $g_EmptyLink             = array();
    $g_HeuristicType         = array();
    $g_HeuristicDetected     = array();
    $vars->adwareList            = array();
    $vars->phishing              = array();
    $g_PHPCodeInside         = array();
    $g_PHPCodeInsideFragment = array();
    $vars->bigFiles              = array();
    $vars->redirectPHPFragment  = array();
    $g_EmptyLinkSrc          = array();
    $g_Base64Fragment        = array();
    $g_UnixExec              = array();
    $vars->phishingSigFragment   = array();
    $vars->phishingFragment      = array();
    $g_PhishingSig           = array();
    $g_IframerFragment       = array();
    $vars->CMS                  = array();
    $vars->adwareListFragment    = array();
}

if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
    if ((count($vars->criticalPHP) > 0) OR (count($vars->criticalJS) > 0) OR (count($g_PhishingSig) > 0)) {
        exit(2);
    } else {
        exit(0);
    }
}
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $vars->totalFolder, $vars->totalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE)) {
    if (isset($options['with-2check']) || isset($options['quarantine'])) {
        if ((count($vars->criticalPHP) > 0) OR (count($vars->criticalJS) > 0) OR (count($g_Base64) > 0) OR (count($g_Iframer) > 0) OR (count($g_UnixExec))) {
            if (!file_exists(DOUBLECHECK_FILE)) {
                if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
                    fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");

                    $l_CurrPath = dirname(__FILE__);

                    if (!isset($vars->criticalPHP)) {
                        $vars->criticalPHP = array();
                    }
                    if (!isset($vars->criticalJS)) {
                        $vars->criticalJS = array();
                    }
                    if (!isset($g_Iframer)) {
                        $g_Iframer = array();
                    }
                    if (!isset($g_Base64)) {
                        $g_Base64 = array();
                    }
                    if (!isset($vars->phishing)) {
                        $vars->phishing = array();
                    }
                    if (!isset($vars->adwareList)) {
                        $vars->adwareList = array();
                    }
                    if (!isset($vars->redirect)) {
                        $vars->redirect = array();
                    }

                    $tmpIndex = array_merge($vars->criticalPHP, $vars->criticalJS, $vars->phishing, $g_Base64, $g_Iframer, $vars->adwareList, $vars->redirect);
                    $tmpIndex = array_values(array_unique($tmpIndex));

                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        $tmpIndex[$i] = str_replace($l_CurrPath, '.', $vars->structure['n'][$tmpIndex[$i]]);
                    }

                    for ($i = 0; $i < count($g_UnixExec); $i++) {
                        $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
                    }

                    $tmpIndex = array_values(array_unique($tmpIndex));

                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        fputs($l_FH, $tmpIndex[$i] . "\n");
                    }

                    fclose($l_FH);
                } else {
                    stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
                }
            } else {
                stdOut(DOUBLECHECK_FILE . ' already exists.');
                if (AI_STR_044 != '') {
                    $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
                }
            }
        }
    }
}
////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($vars->redirect) > 0) {
    $l_Summary .= makeSummary(AI_STR_059, count($vars->redirect), 'crit');
}

if (count($vars->criticalPHP) > 0) {
    $l_Summary .= makeSummary(AI_STR_060, count($vars->criticalPHP), "crit");
}

if (count($vars->criticalJS) > 0) {
    $l_Summary .= makeSummary(AI_STR_061, count($vars->criticalJS), "crit");
}

if (count($vars->phishing) > 0) {
    $l_Summary .= makeSummary(AI_STR_062, count($vars->phishing), "crit");
}

if (count($vars->notRead) > 0) {
    $l_Summary .= makeSummary(AI_STR_066, count($vars->notRead), "crit");
}

if (count($vars->warningPHP) > 0) {
    $l_Summary .= makeSummary(AI_STR_068, count($vars->warningPHP), "warn");
}

if (count($vars->bigFiles) > 0) {
    $l_Summary .= makeSummary(AI_STR_065, count($vars->bigFiles), "warn");
}

if (count($vars->symLinks) > 0) {
    $l_Summary .= makeSummary(AI_STR_069, count($vars->symLinks), "warn");
}

$l_Summary .= "</table>";

$l_ArraySummary                      = array();
$l_ArraySummary["redirect"]          = count($vars->redirect);
$l_ArraySummary["critical_php"]      = count($vars->criticalPHP);
$l_ArraySummary["critical_js"]       = count($vars->criticalJS);
$l_ArraySummary["phishing"]          = count($vars->phishing);
$l_ArraySummary["unix_exec"]         = 0; // count($g_UnixExec);
$l_ArraySummary["iframes"]           = 0; // count($g_Iframer);
$l_ArraySummary["not_read"]          = count($vars->notRead);
$l_ArraySummary["base64"]            = 0; // count($g_Base64);
$l_ArraySummary["heuristics"]        = 0; // count($g_HeuristicDetected);
$l_ArraySummary["symlinks"]          = count($vars->symLinks);
$l_ArraySummary["big_files_skipped"] = count($vars->bigFiles);
$l_ArraySummary["suspicious"]        = count($vars->warningPHP);

if (function_exists('json_encode')) {
    $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->";
}

$l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

$l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);

$l_Result .= AI_STR_015;

$l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);

////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
    $l_HostName = gethostname();
} else {
    $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit Fork (https://github.com/rorry47/ai-bolit) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName . "\n\n";


$scan_time = round(microtime(true) - START_TIME, 1);
$json_report = $reportFactory();
$json_report->addVars($vars, $scan_time);

if (!AI_HOSTER) {
    stdOut("Building list of vulnerable scripts " . count($vars->vulnerable));

    if (count($vars->vulnerable) > 0) {
        $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($vars->vulnerable) . ')</div><div class="crit">';
        foreach ($vars->vulnerable as $l_Item) {
            $l_Result .= '<li>' . makeSafeFn($vars->structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
            $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($vars->structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
        }

        $l_Result .= '</div><p>' . PHP_EOL;
        $l_PlainResult .= "\n";
    }
}


stdOut("Building list of shells " . count($vars->criticalPHP));

if (count($vars->criticalPHP) > 0) {
    $vars->criticalPHP              = array_slice($vars->criticalPHP, 0, 15000);
    $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($vars->criticalPHP) . ')</div><div class="crit">';
    $l_Result .= printList($vars->criticalPHP, $vars, $vars->criticalPHPFragment, true, $vars->criticalPHPSig, 'table_crit');
    $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($vars->criticalPHP, $vars,  $vars->criticalPHPFragment, true, $vars->criticalPHPSig, 'table_crit') . "\n";
    $l_Result .= '</div>' . PHP_EOL;

    $l_ShowOffer = true;
} else {
    $l_Result .= '<div class="ok"><b>' . AI_STR_017 . '</b></div>';
}

stdOut("Building list of js " . count($vars->criticalJS));

if (count($vars->criticalJS) > 0) {
    $vars->criticalJS              = array_slice($vars->criticalJS, 0, 15000);
    $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($vars->criticalJS) . ')</div><div class="crit">';
    $l_Result .= printList($vars->criticalJS, $vars, $vars->criticalJSFragment, true, $vars->criticalJSSig, 'table_vir');
    $l_PlainResult .= '[CLIENT MALWARE / JS]' . "\n" . printPlainList($vars->criticalJS, $vars,  $vars->criticalJSFragment, true, $vars->criticalJSSig, 'table_vir') . "\n";
    $l_Result .= "</div>" . PHP_EOL;

    $l_ShowOffer = true;
}

stdOut("Building list of unread files " . count($vars->notRead));

if (count($vars->notRead) > 0) {
    $vars->notRead               = array_slice($vars->notRead, 0, AIBOLIT_MAX_NUMBER);
    $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($vars->notRead) . ')</div><div class="crit">';
    $l_Result .= printList($vars->notRead, $vars);
    $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
    $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($vars->notRead, $vars) . "\n\n";
}

if (!AI_HOSTER) {
    stdOut("Building list of phishing pages " . count($vars->phishing));

    if (count($vars->phishing) > 0) {
        $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($vars->phishing) . ')</div><div class="crit">';
        $l_Result .= printList($vars->phishing, $vars, $vars->phishingFragment, true, $vars->phishingSigFragment, 'table_vir');
        $l_PlainResult .= '[PHISHING]' . "\n" . printPlainList($vars->phishing, $vars,  $vars->phishingFragment, true, $vars->phishingSigFragment, 'table_vir') . "\n";
        $l_Result .= "</div>" . PHP_EOL;

        $l_ShowOffer = true;
    }

    stdOut('Building list of redirects ' . count($vars->redirect));
    if (count($vars->redirect) > 0) {
        $l_ShowOffer             = true;
        $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($vars->redirect) . ')</div><div class="crit">';
        $l_Result .= printList($vars->redirect, $vars, $vars->redirectPHPFragment, true);
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of symlinks " . count($vars->symLinks));

    if (count($vars->symLinks) > 0) {
        $vars->symLinks               = array_slice($vars->symLinks, 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($vars->symLinks) . ')</div><div class="crit">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $vars->symLinks), true));
        $l_Result .= "</div><div class=\"spacer\"></div>";
    }

}

if (AI_EXTRA_WARN) {
    $l_WarningsNum = count($vars->warningPHP);
    if ($l_WarningsNum > 0) {
        $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
    }

    stdOut("Building list of suspicious files " . count($vars->warningPHP));

    if ((count($vars->warningPHP) > 0) && JSONReport::checkMask($defaults['report_mask'], JSONReport::REPORT_MASK_FULL)) {
        $vars->warningPHP              = array_slice($vars->warningPHP, 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= '<div class="note_warn">' . AI_STR_035 . ' (' . count($vars->warningPHP) . ')</div><div class="warn">';
        $l_Result .= printList($vars->warningPHP, $vars, $vars->warningPHPFragment, true, $vars->warningPHPSig, 'table_warn');
        $l_PlainResult .= '[SUSPICIOUS]' . "\n" . printPlainList($vars->warningPHP, $vars,  $vars->warningPHPFragment, true, $vars->warningPHPSig, 'table_warn') . "\n";
        $l_Result .= '</div>' . PHP_EOL;
    }
}
////////////////////////////////////
if (!AI_HOSTER) {
    $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($vars->bigFiles) + count($g_PHPCodeInside) + count($vars->adwareList) + count($g_EmptyLink) + count($vars->doorway) + count($vars->warningPHP) + count($vars->skippedFolders);

    if ($l_WarningsNum > 0) {
        $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
    }

    stdOut("Building list of adware " . count($vars->adwareList));

    if (count($vars->adwareList) > 0) {
        $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
        $l_Result .= printList($vars->adwareList, $vars, $vars->adwareListFragment, true);
        $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($vars->adwareList, $vars,  $vars->adwareListFragment, true) . "\n";
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of bigfiles " . count($vars->bigFiles));
    $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
    $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');

    if (count($vars->bigFiles) > 0) {
        $vars->bigFiles               = array_slice($vars->bigFiles, 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
        $l_Result .= printList($vars->bigFiles, $vars);
        $l_Result .= "</div>";
        $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($vars->bigFiles, $vars) . "\n\n";
    }

    stdOut("Building list of doorways " . count($vars->doorway));

    if ((count($vars->doorway) > 0) && JSONReport::checkMask($defaults['report_mask'], JSONReport::REPORT_MASK_DOORWAYS)) {
        $vars->doorway              = array_slice($vars->doorway, 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
        $l_Result .= printList($vars->doorway, $vars);
        $l_Result .= "</div>" . PHP_EOL;

    }

    if (count($vars->CMS) > 0) {
        $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
        $l_Result .= nl2br(makeSafeFn(implode("\n", $vars->CMS)));
        $l_Result .= "</div>";
    }
}

if (ICHECK) {
    $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";

    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedFiles'], $vars);
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['modifiedFiles'], $vars);
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedFiles'], $vars);
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedDirs'], $vars);
        $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedDirs'], $vars);
        $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
    $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
    $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
    $l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
    $l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)), date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli()) {
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '') {
    die2('Report not written.');
}

// write plain text result
if (PLAIN_FILE != '') {

    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);

    if ($l_FH = fopen(PLAIN_FILE, "w")) {
        fputs($l_FH, $l_PlainResult);
        fclose($l_FH);
    }
}

// write json result
if (defined('JSON_FILE')) {
    $res = $json_report->write(JSON_FILE);
    if (JSON_STDOUT) {
        echo $res;
    }
}

// write serialized result
if (defined('PHP_FILE')) {
    $json_report->writePHPSerialized(PHP_FILE);
}

$emails = getEmails(REPORT);

if (!$emails) {
    if ($l_FH = fopen($file, "w")) {
        fputs($l_FH, $l_Template);
        fclose($l_FH);
        stdOut("\nReport written to '$file'.");
    } else {
        stdOut("\nCannot create '$file'.");
    }
} else {
    $headers = array(
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : '')
    );

    for ($i = 0, $size = sizeof($emails); $i < $size; $i++) {
        //$res = @mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
    }

    if ($res) {
        stdOut("\nReport sended to " . implode(', ', $emails));
    }
}

$time_taken = microtime(true) - START_TIME;
$time_taken = round($time_taken, 5);

stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
    $keys = array_keys($g_RegExpStat);
    for ($i = 0; $i < count($keys); $i++) {
        $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
    }

    arsort($g_RegExpStat);

    foreach ($g_RegExpStat as $r => $v) {
        echo $v . "\t\t" . $r . "\n";
    }

    die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-Fork-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
    Quarantine();
}

if (isset($options['cmd'])) {
    stdOut("Run \"{$options['cmd']}\" ");
    system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($vars->criticalPHP);
$l_EC2 = count($vars->criticalJS) + count($vars->phishing) + count($vars->warningPHP);
$code  = 0;

if ($l_EC1 > 0) {
    $code = 2;
} else {
    if ($l_EC2 > 0) {
        $code = 1;
    }
}

$stat = array(
    'php_malware'   => count($vars->criticalPHP),
    'cloudhash'     => count($vars->blackFiles),
    'js_malware'    => count($vars->criticalJS),
    'phishing'      => count($vars->phishing)
);

if (function_exists('aibolit_onComplete')) {
    aibolit_onComplete($code, $stat);
}

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine() {
    if (!file_exists(DOUBLECHECK_FILE)) {
        return;
    }

    $g_QuarantinePass = 'aibolit';

    $archive  = "AI-QUARANTINE-" . rand(100000, 999999) . ".zip";
    $infoFile = substr($archive, 0, -3) . "txt";
    $report   = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;


    foreach (file(DOUBLECHECK_FILE) as $file) {
        $file = trim($file);
        if (!is_file($file))
            continue;

        $lStat = stat($file);

        // skip files over 300KB
        if ($lStat['size'] > 300 * 1024)
            continue;

        // http://www.askapache.com/security/chmod-stat.html
        $p    = $lStat['mode'];
        $perm = '-';
        $perm .= (($p & 0x0100) ? 'r' : '-') . (($p & 0x0080) ? 'w' : '-');
        $perm .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
        $perm .= (($p & 0x0020) ? 'r' : '-') . (($p & 0x0010) ? 'w' : '-');
        $perm .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
        $perm .= (($p & 0x0004) ? 'r' : '-') . (($p & 0x0002) ? 'w' : '-');
        $perm .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));

        $owner = (function_exists('posix_getpwuid')) ? @posix_getpwuid($lStat['uid']) : array(
            'name' => $lStat['uid']
        );
        $group = (function_exists('posix_getgrgid')) ? @posix_getgrgid($lStat['gid']) : array(
            'name' => $lStat['uid']
        );

        $inf['permission'][] = $perm;
        $inf['owner'][]      = $owner['name'];
        $inf['group'][]      = $group['name'];
        $inf['size'][]       = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
        $inf['ctime'][]      = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
        $inf['mtime'][]      = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
        $files[]             = strpos($file, './') === 0 ? substr($file, 2) : $file;
    }

    // get config files for cleaning
    $configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
    $configFiles      = preg_grep("~$configFilesRegex~", $files);

    // get columns width
    $width = array();
    foreach (array_keys($inf) as $k) {
        $width[$k] = strlen($k);
        for ($i = 0; $i < count($inf[$k]); ++$i) {
            $len = strlen($inf[$k][$i]);
            if ($len > $width[$k])
                $width[$k] = $len;
        }
    }

    // headings of columns
    $info = '';
    foreach (array_keys($inf) as $k) {
        $info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT) . ' ';
    }
    $info .= "name\n";

    for ($i = 0; $i < count($files); ++$i) {
        foreach (array_keys($inf) as $k) {
            $info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT) . ' ';
        }
        $info .= $files[$i] . "\n";
    }
    unset($inf, $width);

    exec("zip -v 2>&1", $output, $code);

    if ($code == 0) {
        $filter = '';
        if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
            $filter = "|grep -v -E '$configFilesRegex'";
        }

        exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
        if ($code == 0) {
            file_put_contents($infoFile, $info);
            $m = array();
            if (!empty($filter)) {
                foreach ($configFiles as $file) {
                    $tmp  = file_get_contents($file);
                    // remove  passwords
                    $tmp  = preg_replace('~^.*?pass.*~im', '', $tmp);
                    // new file name
                    $file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
                    file_put_contents($file, $tmp);
                    $m[] = $file;
                }
            }

            exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
            stdOut("\nCreate archive '" . realpath($archive) . "'");
            stdOut("This archive have password '$g_QuarantinePass'");
            foreach ($m as $file)
                unlink($file);
            unlink($infoFile);
            return;
        }
    }

    $zip = new ZipArchive;

    if ($zip->open($archive, ZipArchive::CREATE | ZipArchive::OVERWRITE) === false) {
        stdOut("Cannot create '$archive'.");
        return;
    }

    foreach ($files as $file) {
        if (in_array($file, $configFiles)) {
            $tmp = file_get_contents($file);
            // remove  passwords
            $tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
            $zip->addFromString($file, $tmp);
        } else {
            $zip->addFile($file);
        }
    }
    $zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
    $zip->addFile($report, REPORT_FILE);
    $zip->addFromString($infoFile, $info);
    $zip->close();

    stdOut("\nCreate archive '" . realpath($archive) . "'.");
    stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir, $vars) {
    global $defaults, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';

    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $vars->g_counter - 1;

    QCR_Debug('Check ' . $l_RootDir);

    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;

            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;

            $l_Type  = filetype($l_FileName);
            $l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") {
                $vars->symLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && (!$l_IsDir)) {
                $g_UnixExec[] = $l_FileName;
                continue;
            }

            $l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);

            $l_NeedToScan = true;
            $l_Ext2       = substr(strstr(basename($l_FileName), '.'), 1);
            if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }

            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }

            if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE)
                $l_NeedToScan = false;

            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $vars->skippedFolders[] = $l_FileName;
                    continue;
                }

                $l_BaseName = basename($l_FileName);

                $l_DirCounter++;

                $vars->counter++;
                $vars->foundTotalDirs++;

                QCR_IntegrityCheck($l_FileName, $vars);

            } else {
                if ($l_NeedToScan) {
                    $vars->foundTotalFiles++;
                    $vars->counter++;
                }
            }

            if (!$l_NeedToScan)
                continue;

            if (IMAKE) {
                write_integrity_db_file($l_FileName);
                continue;
            }

            // ICHECK
            // skip if known and not modified.
            if (icheck($l_FileName))
                continue;

            $l_Buffer .= getRelativePath($l_FileName);
            $l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";

            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }

        }

        closedir($l_DIRH);
    }

    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }

    if (($l_RootDir == ROOT_PATH)) {
        write_integrity_db_file();
    }

}


function getRelativePath($l_FileName) {
    return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}

/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    static $l_status = array('modified' => 'modified', 'added' => 'added');

    $l_RelativePath = getRelativePath($l_FileName);
    $l_known        = isset($g_IntegrityDB[$l_RelativePath]);

    if (is_dir($l_FileName)) {
        if ($l_known) {
            unset($g_IntegrityDB[$l_RelativePath]);
        } else {
            $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        }
        return $l_known;
    }

    if ($l_known == false) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        return false;
    }

    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';

    if ($g_IntegrityDB[$l_RelativePath] != $hash) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
        return false;
    }

    unset($g_IntegrityDB[$l_RelativePath]);
    return true;
}

function write_integrity_db_file($l_FileName = '') {
    static $l_Buffer = '';

    if (empty($l_FileName)) {
        empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
        return;
    }

    $l_RelativePath = getRelativePath($l_FileName);

    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';

    $l_Buffer .= "$l_RelativePath|$hash\n";

    if (strlen($l_Buffer) > 32000) {
        file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
    }
}

function load_integrity_db() {
    global $g_IntegrityDB;
    file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);

    $s_file = new SplFileObject('compress.zlib://' . INTEGRITY_DB_FILE);
    $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);

    foreach ($s_file as $line) {
        $i = strrpos($line, '|');
        if (!$i)
            continue;
        $g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i + 1);
    }

    $s_file = null;
}


function getStdin()
{
    $stdin  = '';
    $f      = @fopen('php://stdin', 'r');
    while($line = fgets($f))
    {
        $stdin .= $line;
    }
    fclose($f);
    return $stdin;
}

function OptimizeSignatures() {
    global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
    global $g_JSVirSig, $gX_JSVirSig;
    global $g_AdwareSig;
    global $g_PhishingSig;
    global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;

    (AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
    (AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
    $gX_FlexDBShe = $gXX_FlexDBShe = array();

    (AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
    $gX_JSVirSig = array();

    $count = count($g_FlexDBShe);

    for ($i = 0; $i < $count; $i++) {
        if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
            $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
        if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
            $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
        if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
            $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

        $g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);

        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
    }

    optSig($g_FlexDBShe);

    optSig($g_JSVirSig);
    
    
    optSig($g_SusDB);
    //optSig($g_SusDBPrio);
    //optSig($g_ExceptFlex);

    // convert exception rules
    $cnt = count($g_ExceptFlex);
    for ($i = 0; $i < $cnt; $i++) {
        $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
        if (!strlen($g_ExceptFlex[$i]))
            unset($g_ExceptFlex[$i]);
    }

    $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs) {
    $sigs = array_unique($sigs);

    // Add SigId
    foreach ($sigs as &$s) {
        $s .= '(?<X' . myCheckSum($s) . '>)';
    }
    unset($s);

    $fix = array(
        '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
        'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
        '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
        '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
    );

    $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);

    $fix = array(
        '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
        '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
    );

    $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

    optSigCheck($sigs);

    $tmp = array();
    foreach ($sigs as $i => $s) {
        if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
            unset($sigs[$i]);
            $tmp[] = $s;
        }
    }

    usort($sigs, 'strcasecmp');
    $txt = implode("\n", $sigs);

    for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
        $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
    }

    $sigs = array_merge(explode("\n", $txt), $tmp);

    optSigCheck($sigs);
}

function optMergePrefixes($m) {
    $limit = 8000;

    $prefix     = $m[1];
    $prefix_len = strlen($prefix);

    $len = $prefix_len;
    $r   = array();

    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {

        if (strlen($line) > $limit) {
            $r[] = $line;
            continue;
        }

        $s = substr($line, $prefix_len);
        $len += strlen($s);
        if ($len > $limit) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
            $suffixes = array();
            $len      = $prefix_len + strlen($s);
        }
        $suffixes[] = $s;
    }

    if (!empty($suffixes)) {
        if (count($suffixes) == 1) {
            $r[] = $prefix . $suffixes[0];
        } else {
            $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
        }
    }

    return implode("\n", $r);
}

function optMergePrefixes_Old($m) {
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);

    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        $suffixes[] = substr($line, $prefix_len);
    }

    return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs) {
    $result = true;

    foreach ($sigs as $k => $sig) {
        if (trim($sig) == "") {
            if (DEBUG_MODE) {
                echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }

        if (@preg_match('~' . $sig . '~smiS', '') === false) {
            $error = error_get_last();
            if (DEBUG_MODE) {
                echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
    }

    return $result;
}

function _hash_($text) {
    static $r;

    if (empty($r)) {
        for ($i = 0; $i < 256; $i++) {
            if ($i < 33 OR $i > 127)
                $r[chr($i)] = '';
        }
    }

    return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) {
    global $defaults;

    if (empty($list)) {
        return array();
    }

    $file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';
    if (isset($defaults['avdb'])) {
        $file = dirname($defaults['avdb']) . '/AIBOLIT-WHITELIST.db';
    }

    try {
        $db = FileHashMemoryDb::open($file);
    } catch (Exception $e) {
        stdOut("\nAn error occurred while loading the white list database from " . $file . "\n");
        return array();
    }

    $snum = $db->count();
    stdOut("\nLoaded " . ceil($snum) . " known files from " . $file . "\n");

    return $db->find($list);
}

function check_binmalware($hash, $vars) {
    if (isset($vars->blacklist)) {
        return count($vars->blacklist->find(array($hash))) > 0;
    }

    return false;
}

function getSigId($l_Found) {
    foreach ($l_Found as $key => &$v) {
        if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
            return substr($key, 1);
        }
    }

    return null;
}

function die2($str) {
    if (function_exists('aibolit_onFatalError')) {
        aibolit_onFatalError($str);
    }
    die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
    global $g_DeMapper;

    if ($l_DeobfType != '') {
        if (DEBUG_MODE) {
            stdOut("\n-----------------------------------------------------------------------------\n");
            stdOut("[DEBUG]" . $l_Filename . "\n");
            var_dump(getFragment($l_Unwrapped, $l_Pos));
            stdOut("\n...... $l_DeobfType ...........\n");
            var_dump($l_Unwrapped);
            stdOut("\n");
        }

        switch ($l_DeobfType) {
            case '_GLOBALS_':
                foreach ($g_DeMapper as $fkey => $fvalue) {
                    if (DEBUG_MODE) {
                        stdOut("[$fkey] => [$fvalue]\n");
                    }

                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        if (DEBUG_MODE) {
                            stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                        }

                        return true;
                    }
                }
                break;
        }


        return false;
    }
}

function convertToUTF8($text)
{
    if (function_exists('mb_convert_encoding')) {
        $text = @mb_convert_encoding($text, 'utf-8', 'auto');
        $text = @mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    }

    return $text;
}

function isFileTooBigForScanWithSignatures($filesize)
{
    return (MAX_SIZE_TO_SCAN > 0 && $filesize > MAX_SIZE_TO_SCAN) || ($filesize < 0);
}

function isFileTooBigForCloudscan($filesize)
{
    return (MAX_SIZE_TO_CLOUDSCAN > 0 && $filesize > MAX_SIZE_TO_CLOUDSCAN) || ($filesize < 0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// The following instructions should be written the same pattern,
/// because they are replaced by file content while building a release.
/// See the release_aibolit_ru.sh file for details.


class Variables
{
    public $structure = array();
    public $totalFolder = 0;
    public $totalFiles = 0;
    public $adwareList = array();
    public $criticalPHP = array();
    public $phishing = array();
    public $CMS = array();
    public $redirect = array();
    public $redirectPHPFragment = array();
    public $criticalJS = array();
    public $criticalJSFragment = array();
    public $blackFiles = array();
    public $notRead = array();
    public $bigFiles = array();
    public $criticalPHPSig = array();
    public $criticalPHPFragment = array();
    public $phishingSigFragment = array();
    public $phishingFragment = array();
    public $criticalJSSig = array();
    public $adwareListFragment = array();
    public $warningPHPSig = array();
    public $warningPHPFragment = array();
    public $warningPHP = array();
    public $blacklist = array();
    public $vulnerable = array();
    public $crc = 0;

    public $counter = 0;
    public $foundTotalDirs = 0;
    public $foundTotalFiles = 0;
    public $doorway = array();
    public $symLinks = array();
    public $skippedFolders = array();

    public $rescanCount = 0;
}



class Logger
{
    /**
     * $log_file - path and log file name
     * @var string
     */
    protected $log_file;
    /**
     * $file - file
     * @var string
     */
    protected $file;
    /**
     * dateFormat
     * @var string
     */
    protected $dateFormat = 'd-M-Y H:i:s';

    /**
     * @var array
     */
    const LEVELS  = ['ERROR' => 1, 'DEBUG' => 2,  'INFO' => 4, 'ALL' => 7];

    /**
     * @var int
     */
    private $level;

    /**
     * Class constructor
     * @param string $log_file - path and filename of log
     * @param string|array $level - Level of logging
     */
    public function __construct($log_file = 'error.log', $level = 'INFO')
    {
        if (is_array($level)) {
            foreach ($level as $v) {
                if (!in_array($v, array_keys(self::LEVELS))) {
                    $v = 'INFO';
                }
                $this->level |= self::LEVELS[$v];
            }
        } else {
            if (in_array($level, array_keys(self::LEVELS))) {
                $this->level = self::LEVELS[$level];
            } else {
                $this->level = self::LEVELS['INFO'];
            }
        }

        $this->log_file = $log_file;
        //Create log file if it doesn't exist.
        if(!file_exists($log_file)){
            fopen($log_file, 'w') or exit("Can't create $log_file!");
        }
        //Check permissions of file.
        if(!is_writable($log_file)){
            //throw exception if not writable
            throw new Exception('ERROR: Unable to write to file!', 1);
        }
    }

    /**
     * Info method (write info message)
     * @param string $message
     * @return void
     */
    public function info($message)
    {
        if ($this->level & self::LEVELS['INFO']) {
            $this->writeLog($message, 'INFO');
        }

    }
    /**
     * Debug method (write debug message)
     * @param string $message
     * @return void
     */
    public function debug($message)
    {
        if ($this->level & self::LEVELS['DEBUG']) {
            $this->writeLog($message, 'DEBUG');
        }
    }
    /**
     * Error method (write error message)
     * @param string $message
     * @return void
     */
    public function error($message)
    {
        if ($this->level & self::LEVELS['ERROR']) {
            $this->writeLog($message, 'ERROR');
        }
    }

    /**
     * Write to log file
     * @param string $message
     * @param string $level
     * @return void
     */
    public function writeLog($message, $level)
    {
        // open log file
        if (!is_resource($this->file)) {
            $this->openLog();
        }
        //Grab time - based on timezone in php.ini
        $time = date($this->dateFormat);
        // Write time & message to end of file
        fwrite($this->file, "[$time] : [$level] - $message" . PHP_EOL);
    }
    /**
     * Open log file
     * @return void
     */
    private function openLog()
    {
        $openFile = $this->log_file;
        // 'a' option = place pointer at end of file
        $this->file = fopen($openFile, 'a') or exit("Can't open $openFile!");
    }
    /**
     * Class destructor
     */
    public function __destruct()
    {
        if ($this->file) {
            fclose($this->file);
        }
    }
}

class CmsVersionDetector
{
    const CMS_BITRIX = 'Bitrix';
    const CMS_WORDPRESS = 'WordPress';
    const CMS_JOOMLA = 'Joomla';
    const CMS_DLE = 'Data Life Engine';
    const CMS_IPB = 'Invision Power Board';
    const CMS_WEBASYST = 'WebAsyst';
    const CMS_OSCOMMERCE = 'OsCommerce';
    const CMS_DRUPAL = 'Drupal';
    const CMS_MODX = 'MODX';
    const CMS_INSTANTCMS = 'Instant CMS';
    const CMS_PHPBB = 'PhpBB';
    const CMS_VBULLETIN = 'vBulletin';
    const CMS_SHOPSCRIPT = 'PHP ShopScript Premium';
    
    const CMS_VERSION_UNDEFINED = '0.0';

    private $root_path;
    private $versions;
    private $types;

    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions  = array();
        $this->types     = array();

        $version = '';

        $dir_list   = $this->getDirList($root_path);
        $dir_list[] = $root_path;

        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
                $this->addCms(self::CMS_BITRIX, $version);
            }

            if ($this->checkWordpress($dir, $version)) {
                $this->addCms(self::CMS_WORDPRESS, $version);
            }

            if ($this->checkJoomla($dir, $version)) {
                $this->addCms(self::CMS_JOOMLA, $version);
            }

            if ($this->checkDle($dir, $version)) {
                $this->addCms(self::CMS_DLE, $version);
            }

            if ($this->checkIpb($dir, $version)) {
                $this->addCms(self::CMS_IPB, $version);
            }

            if ($this->checkWebAsyst($dir, $version)) {
                $this->addCms(self::CMS_WEBASYST, $version);
            }

            if ($this->checkOsCommerce($dir, $version)) {
                $this->addCms(self::CMS_OSCOMMERCE, $version);
            }

            if ($this->checkDrupal($dir, $version)) {
                $this->addCms(self::CMS_DRUPAL, $version);
            }

            if ($this->checkMODX($dir, $version)) {
                $this->addCms(self::CMS_MODX, $version);
            }

            if ($this->checkInstantCms($dir, $version)) {
                $this->addCms(self::CMS_INSTANTCMS, $version);
            }

            if ($this->checkPhpBb($dir, $version)) {
                $this->addCms(self::CMS_PHPBB, $version);
            }

            if ($this->checkVBulletin($dir, $version)) {
                $this->addCms(self::CMS_VBULLETIN, $version);
            }

            if ($this->checkPhpShopScript($dir, $version)) {
                $this->addCms(self::CMS_SHOPSCRIPT, $version);
            }

        }
    }

    function getDirList($target) {
        $remove      = array(
            '.',
            '..'
        );
        $directories = array_diff(scandir($target), $remove);

        $res = array();

        foreach ($directories as $value) {
            if (is_dir($target . '/' . $value)) {
                $res[] = $target . '/' . $value;
            }
        }

        return $res;
    }

    function isCms($name, $version) {
        for ($i = 0; $i < count($this->types); $i++) {
            if ((strpos($this->types[$i], $name) !== false) && (strpos($this->versions[$i], $version) !== false)) {
                return true;
            }
        }

        return false;
    }

    function getCmsList() {
        return $this->types;
    }

    function getCmsVersions() {
        return $this->versions;
    }

    function getCmsNumber() {
        return count($this->types);
    }

    function getCmsName($index = 0) {
        return $this->types[$index];
    }

    function getCmsVersion($index = 0) {
        return $this->versions[$index];
    }

    private function addCms($type, $version) {
        $this->types[]    = $type;
        $this->versions[] = $version;
    }

    private function checkBitrix($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/bitrix')) {
            $res = true;

            $tmp_content = @file_get_contents($this->root_path . '/bitrix/modules/main/classes/general/version.php');
            if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkWordpress($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/wp-admin')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/wp-includes/version.php');
            if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
        }

        return $res;
    }

    private function checkJoomla($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/libraries/joomla')) {
            $res = true;

            // for 1.5.x
            $tmp_content = @file_get_contents($dir . '/libraries/joomla/version.php');
            if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];

                if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }

            // for 1.7.x
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];

                if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }


            // for 2.5.x and 3.x
            $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');

            if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];

                if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }

        }

        return $res;
    }

    private function checkDle($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/engine/engine.php')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

            $tmp_content = @file_get_contents($dir . '/install.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkIpb($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/ips_kernel')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
            if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkWebAsyst($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/wbs/installer')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/license.txt');
            if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkOsCommerce($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/includes/version.php')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkDrupal($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/sites/all')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
            if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        if (file_exists($dir . '/core/lib/Drupal.php')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/core/lib/Drupal.php');
            if (preg_match('|VERSION\s*=\s*\'(\d+\.\d+\.\d+)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        if (file_exists($dir . 'modules/system/system.info')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . 'modules/system/system.info');
            if (preg_match('|version\s*=\s*"\d+\.\d+"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkMODX($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/manager/assets')) {
            $res = true;

            // no way to pick up version
        }

        return $res;
    }

    private function checkInstantCms($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/plugins/p_usertab')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/index.php');
            if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkPhpBb($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/includes/acp')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/config.php');
            if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }

    private function checkVBulletin($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        // removed dangerous code from here, see DEF-10390 for details

        return $res;
    }

    private function checkPhpShopScript($dir, &$version) {
        $version = self::CMS_VERSION_UNDEFINED;
        $res     = false;

        if (file_exists($dir . '/install/consts.php')) {
            $res = true;

            $tmp_content = @file_get_contents($dir . '/install/consts.php');
            if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }

        }

        return $res;
    }
}


class CloudAssistedRequest
{
    const API_URL = 'https://api.imunify360.com/api/hashes/check';

    private $timeout    = 60;
    private $server_id  = '';

    public function __construct($server_id, $timeout = 60) 
    {
        $this->server_id    = $server_id;
        $this->timeout      = $timeout;
    }

    public function checkFilesByHash($list_of_hashes = array())
    {
        if (empty($list_of_hashes)) {
            return array(
                [], 
                [],
                [],
                'white'             => [],
                'black'             => [],
                'verdicts_black'    => [],
            );
        }

        $result = $this->request($list_of_hashes);

        $white          = isset($result['white'])           ? $result['white']          : [];
        $black          = isset($result['black'])           ? $result['black']          : [];
        $verdicts_black = isset($result['verdicts_black'])  ? $result['verdicts_black'] : [];

        return [
            $white,
            $black,
            $verdicts_black,
            'white'             => $white,
            'black'             => $black,
            'verdicts_black'    => $verdicts_black,
        ];
    }
    
    // /////////////////////////////////////////////////////////////////////////

    private function request($list_of_hashes)
    {
        $url = self::API_URL . '?server_id=' . urlencode($this->server_id) . '&indexed=1';

        $data = array(
            'hashes' => $list_of_hashes,
        );

        $json_hashes = json_encode($data);

        $info = [];
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL            , $url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST  , 'GET');
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER , false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST , false);
            curl_setopt($ch, CURLOPT_TIMEOUT        , $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT , $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER , true);
            curl_setopt($ch, CURLOPT_HTTPHEADER     , array('Content-Type: application/json'));
            curl_setopt($ch, CURLOPT_POSTFIELDS     , $json_hashes);
            $response_data  = curl_exec($ch);
            $info           = curl_getinfo($ch);
            $errno          = curl_errno($ch);
            curl_close($ch);
        }
        catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

        $http_code      = isset($info['http_code']) ? $info['http_code'] : 0;
        if ($http_code !== 200) {
            if ($errno == 28) {
                throw new Exception('Reuqest timeout! Return code: ' . $http_code . ' Curl error num: ' . $errno);
            }
            throw new Exception('Invalid response from the Cloud Assisted server! Return code: ' . $http_code . ' Curl error num: ' . $errno);
        }
        $result = json_decode($response_data, true);
        if (is_null($result)) {
            throw new Exception('Invalid json format in the response!');
        }
        if (isset($result['error'])) {
            throw new Exception('API server returned error!');
        }
        if (!isset($result['result'])) {
            throw new Exception('API server returned error! Cannot find field "result".');
        }

        return $result['result'];
    }
}

class JSONReport
{
    const REPORT_MASK_DOORWAYS  = 1<<2;
    const REPORT_MASK_SUSP      = 1<<3;
    const REPORT_MASK_FULL      = self::REPORT_MASK_DOORWAYS | self::REPORT_MASK_SUSP;
    
    private $raw_report = array();
    private $extended_report;
    private $rapid_account_scan;
    private $ai_extra_warn;
    private $ai_hoster;
    private $report_mask;
    private $noPrefix;
    private $addPrefix;
    private $mnemo;
    
    public function __construct($mnemo, $path, $db_location, $db_meta_info_version, $report_mask, $extended_report, $rapid_account_scan, $ai_version, $ai_hoster, $ai_extra_warn, $add_prefix, $no_prefix)
    {
        $this->mnemo = $mnemo;
        $this->ai_extra_warn = $ai_extra_warn;
        $this->extended_report = $extended_report;
        $this->rapid_account_scan = $rapid_account_scan;
        $this->ai_hoster = $ai_hoster;
        $this->report_mask = $report_mask;
        $this->addPrefix = $add_prefix;
        $this->noPrefix = $no_prefix;

        $this->raw_report = [];
        $this->raw_report['summary'] = array(
            'scan_path'     => $path,
            'report_time'   => time(),
            'ai_version'    => $ai_version,
            'db_location'   => $db_location,
            'db_version'    => $db_meta_info_version,
        );
    }

    public function addVars($vars, $scan_time)
    {
        $summary_counters                       = array();
        $summary_counters['redirect']           = count($vars->redirect);
        $summary_counters['critical_php']       = count($vars->criticalPHP);
        $summary_counters['critical_js']        = count($vars->criticalJS);
        $summary_counters['phishing']           = count($vars->phishing);
        $summary_counters['unix_exec']          = 0; // count($g_UnixExec);
        $summary_counters['iframes']            = 0; // count($g_Iframer);
        $summary_counters['not_read']           = count($vars->notRead);
        $summary_counters['base64']             = 0; // count($g_Base64);
        $summary_counters['heuristics']         = 0; // count($g_HeuristicDetected);
        $summary_counters['symlinks']           = count($vars->symLinks);
        $summary_counters['big_files_skipped']  = count($vars->bigFiles);
        $summary_counters['suspicious']         = count($vars->warningPHP);

        $this->raw_report['summary']['counters'] = $summary_counters;
        $this->raw_report['summary']['total_files'] = $vars->foundTotalFiles;
        $this->raw_report['summary']['scan_time'] = $scan_time;

        if ($this->extended_report && $this->rapid_account_scan) {
            $this->raw_report['summary']['counters']['rescan_count'] = $vars->rescanCount;
        }

        $this->raw_report['vulners'] = $this->getRawJsonVuln($vars->vulnerable, $vars);

        if (count($vars->criticalPHP) > 0) {
            $this->raw_report['php_malware'] = $this->getRawJson($vars->criticalPHP, $vars, $vars->criticalPHPFragment, $vars->criticalPHPSig);
        }

        if (count($vars->blackFiles) > 0) {
            $this->raw_report['cloudhash'] = $this->getRawBlackData($vars->blackFiles);
        }

        if (count($vars->criticalJS) > 0) {
            $this->raw_report['js_malware'] = $this->getRawJson($vars->criticalJS, $vars, $vars->criticalJSFragment, $vars->criticalJSSig);
        }

        if (count($vars->notRead) > 0) {
            $this->raw_report['not_read'] = $vars->notRead;
        }

        if ($this->ai_hoster) {
            if (count($vars->phishing) > 0) {
                $this->raw_report['phishing'] = $this->getRawJson($vars->phishing, $vars, $vars->phishingFragment, $vars->phishingSigFragment);
            }
            if (count($vars->redirect) > 0) {
                $this->raw_report['redirect'] = $this->getRawJson($vars->redirect, $vars, $vars->redirectPHPFragment);
            }
            if (count($vars->symLinks) > 0) {
                $this->raw_report['sym_links'] = $vars->symLinks;
            }
        }
        else {
            if (count($vars->adwareList) > 0) {
                $this->raw_report['adware'] = $this->getRawJson($vars->adwareList, $vars, $vars->adwareListFragment);
            }
            if (count($vars->bigFiles) > 0) {
                $this->raw_report['big_files'] = $this->getRawJson($vars->bigFiles, $vars);
            }
            if ((count($vars->doorway) > 0) && JSONReport::checkMask($this->report_mask, JSONReport::REPORT_MASK_DOORWAYS)) {
                $this->raw_report['doorway'] = $this->getRawJson($vars->doorway, $vars);
            }
            if (count($vars->CMS) > 0) {
                $this->raw_report['cms'] = $vars->CMS;
            }
        }

        if ($this->ai_extra_warn) {
            if ((count($vars->warningPHP) > 0) && JSONReport::checkMask($this->report_mask, JSONReport::REPORT_MASK_FULL)) {
                $this->raw_report['suspicious'] = $this->getRawJson($vars->warningPHP, $vars, $vars->warningPHPFragment, $vars->warningPHPSig);
            }
        }
    }
    
    public static function checkMask($mask, $need)
    {
        return (($mask & $need) == $need);
    }
    
    public function write($filepath)
    {
        $res = @json_encode($this->raw_report);
        if ($l_FH = fopen($filepath, 'w')) {
            fputs($l_FH, $res);
            fclose($l_FH);
        }
        return $res;
    }
    
    public function writePHPSerialized($filepath)
    {
        if ($l_FH = fopen($filepath, 'w')) {
            fputs($l_FH, serialize($this->raw_report));
            fclose($l_FH);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    
    private function getRawJsonVuln($par_List, $vars) 
    {
        $results = array();
        $l_Src   = array(
            '&quot;',
            '&lt;',
            '&gt;',
            '&amp;',
            '&#039;',
            '<' . '?php.'
        );
        $l_Dst   = array(
            '"',
            '<',
            '>',
            '&',
            '\'',
            '<' . '?php '
        );

        for ($i = 0; $i < count($par_List); $i++) {
            $l_Pos      = $par_List[$i]['ndx'];

            $fn = $this->addPrefix . str_replace($this->noPrefix, '', $vars->structure['n'][$l_Pos]);
            if (ENCODE_FILENAMES_WITH_BASE64) {
                $res['fn'] = base64_encode($fn);
            } else {
                $res['fn']  = convertToUTF8($fn);
            }

            $res['sig'] = $par_List[$i]['id'];

            $res['ct']    = $vars->structure['c'][$l_Pos];
            $res['mt']    = $vars->structure['m'][$l_Pos];
            $res['et']    = $vars->structure['e'][$l_Pos];
            $res['sz']    = $vars->structure['s'][$l_Pos];
            $res['sigid'] = 'vuln_' . md5($vars->structure['n'][$l_Pos] . $par_List[$i]['id']);

            $results[] = $res;
        }

        return $results;
    }

    private function getRawJson($par_List, $vars, $par_Details = null, $par_SigId = null) 
    {
        $results = array();
        $l_Src   = array(
            '&quot;',
            '&lt;',
            '&gt;',
            '&amp;',
            '&#039;',
            '<' . '?php.'
        );
        $l_Dst   = array(
            '"',
            '<',
            '>',
            '&',
            '\'',
            '<' . '?php '
        );

        for ($i = 0; $i < count($par_List); $i++) {
            if ($par_SigId != null) {
                $l_SigId = 'id_' . $par_SigId[$i];
            } else {
                $l_SigId = 'id_n' . rand(1000000, 9000000);
            }

            $l_Pos     = $par_List[$i];

            $fn = $this->addPrefix . str_replace($this->noPrefix, '', $vars->structure['n'][$l_Pos]);
            if (ENCODE_FILENAMES_WITH_BASE64) {
                $res['fn'] = base64_encode($fn);
            } else {
                $res['fn']  = convertToUTF8($fn);
            }

            if ($par_Details != null) {
                $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
                $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
                $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
                $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
                $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);
            }

            $res['sig'] = convertToUTF8($res['sig']);

            $res['ct']    = $vars->structure['c'][$l_Pos];
            $res['mt']    = $vars->structure['m'][$l_Pos];
            $res['sz']    = $vars->structure['s'][$l_Pos];
            $res['et']    = $vars->structure['e'][$l_Pos];
            $res['hash']  = $vars->structure['crc'][$l_Pos];
            $res['sigid'] = $l_SigId;
            if (isset($vars->structure['sha256'][$l_Pos])) {
                $res['sha256'] = $vars->structure['sha256'][$l_Pos];
            } else {
                $res['sha256'] = '';
            }


            if (isset($par_SigId) && isset($this->mnemo[$par_SigId[$i]])) {
                $res['sn'] = $this->mnemo[$par_SigId[$i]];
            } else {
                $res['sn'] = '';
            }

            $results[] = $res;
        }

        return $results;
    }

    private function getRawBlackData($black_list)
    {
        $result = array();
        foreach ($black_list as $filename => $hash)
        {
            try {
                $stat = stat($filename);
                $sz   = $stat['size'];
                $ct   = $stat['ctime'];
                $mt   = $stat['mtime'];
            }
            catch (Exception $e) {
                continue;
            }

            $result[] = array(
                'fn'    => $filename,
                'sig'   => '',
                'ct'    => $ct,
                'mt'    => $mt,
                'et'    => $hash['ts'],
                'sz'    => $sz,
                'hash'  => $hash['h'],
                'sigid' => crc32($filename),
                'sn'    => isset($hash['sn']) ? $hash['sn'] : 'cld',
            );
        }
        return $result;
    }
}


class CloudAssistedFiles
{
    private $white = [];
    private $black = [];

    public function __construct(CloudAssistedRequest $car, $file_list)
    {
        $list_of_hash       = [];
        $list_of_filepath   = [];
        foreach ($file_list as $filepath)
        {
            if (!file_exists($filepath) || !is_readable($filepath) || is_dir($filepath)) {
                continue;
            }
            try {
                $list_of_hash[]     = hash('sha256', file_get_contents($filepath));
                $list_of_filepath[] = $filepath;
            }
            catch (Exception $e) {
                
            }
        }
        unset($file_list);
        
        try {
            list($white_raw, $black_raw, $verdicts_black_raw) = $car->checkFilesByHash($list_of_hash);
        }
        catch (Exception $e) {
            throw $e;
        }
        
        $this->white = $this->getListOfFile($white_raw, $list_of_hash, $list_of_filepath);
        $this->black = $this->getListOfFile($black_raw, $list_of_hash, $list_of_filepath, $verdicts_black_raw);
        
        unset($white_raw);
        unset($black_raw);
        unset($verdicts_black_raw);
        unset($list_of_hash);
        unset($list_of_filepath);
    }
    
    public function getWhiteList()
    {
        return $this->white;
    }

    public function getBlackList()
    {
        return $this->black;
    }
    
    // =========================================================================
    
    private function getListOfFile($data_raw, $list_of_hash, $list_of_filepath, $verdicts = [])
    {
        $result = [];
        foreach ($data_raw as $index => $hash_index)
        {
            if (!isset($list_of_hash[$hash_index])) {
                continue;
            }
            $hash_result = [
                'h'     => $list_of_hash[$hash_index],
                'ts'    => time(),
            ];
            if ($verdicts) {
                if (!isset($verdicts[$index])) {
                    throw new Exception('Wrong CloudAssisted format. List of verdicts has structure different from main list.');
                }
                $hash_result['sn'] = $verdicts[$index];
            }
            $result[$list_of_filepath[$hash_index]] = $hash_result;
        }
        return $result;
    }    
}


class DetachedMode
{
    protected $workdir;
    protected $scan_id;
    protected $pid_file;
    protected $report_file;
    protected $done_file;
    protected $vars;
    protected $start_time;
    protected $json_report;
    protected $sock_file;

    public function __construct($scan_id, $vars, $listing, $start_time, $json_report, $use_base64, $basedir = '/var/imunify360/aibolit/run', $sock_file = '/var/run/defence360agent/generic_sensor.sock.2')
    {
        $this->scan_id = $scan_id;
        $this->vars = $vars;
        $this->setWorkDir($basedir, $scan_id);
        $this->pid_file = $this->workdir . '/pid';
        $this->report_file = $this->workdir . '/report.json';
        $this->done_file = $this->workdir . '/done';
        $this->start_time = $start_time;
        $this->json_report = $json_report;
        $this->setSocketFile($sock_file);

        $this->checkSpecs($this->workdir, $listing);

        file_put_contents($this->pid_file, strval(getmypid()));

        $this->scan($listing, $use_base64);
        $this->writeReport();
        $this->complete();
    }

    protected function scan($listing, $use_base64)
    {
        $s_file = new SplFileObject($listing);
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        if (function_exists('QCR_GoScan')) {
            QCR_GoScan($s_file, $this->vars, $use_base64, false);
            whitelisting($this->vars);
        }
        unset($s_file);
    }

    protected function checkSpecs($workdir, $listing)
    {
        if (!file_exists($workdir) && !mkdir($workdir)) {
            die('Error! Cannot create workdir ' . $workdir . ' for detached scan.');
        } elseif (file_exists($workdir) && !is_writable($workdir)) {
            die('Error! Workdir ' . $workdir . ' is not writable.');
        } elseif (!file_exists($listing) || !is_readable($listing)) {
            die('Error! Listing file ' . $listing . ' not exists or not readable');
        }
    }

    protected function writeReport()
    {
        $scan_time = round(microtime(true) - $this->start_time, 1);
        $json_report = $this->json_report->call($this);
        $json_report->addVars($this->vars, $scan_time);
        $json_report->write($this->report_file);
    }

    protected function complete()
    {
        @touch($this->done_file);
        $complete = array(
            'method' => 'MALWARE_SCAN_COMPLETE',
            'scan_id' => $this->scan_id,
        );
        $json_complete = json_encode($complete) . "\n";
        $socket = fsockopen('unix://' . $this->sock_file);
        stream_set_blocking($socket, false);
        fwrite($socket, $json_complete);
        fclose($socket);
    }

    protected function setWorkDir($dir, $scan_id)
    {
        $this->workdir = $dir . '/' . $scan_id;
    }

    protected function setSocketFile($sock)
    {
        $this->sock_file = $sock;
    }
}


/**
 * Class ResidentMode used to stay aibolit alive in memory and wait for a job.
 */
class ResidentMode
{
    /**
     * parent dir for all resident aibolit related
     * @var string
     */
    protected $resident_dir;
    /**
     * directory for all jobs to be processed by aibolit
     * @var string
     */
    protected $resident_in_dir;
    /**
     * directory with all the malicious files reports to be processed by imunify
     * @var string
     */
    protected $resident_out_dir;
    /**
     * resident aibolit pid
     * @var string
     */
    protected $aibolit_pid;
    /**
     * file lock used to make sure we start only one aibolit
     * @var string
     */
    protected $aibolit_start_lock;
    /**
     * status file used to make sure aibolit didn't get stuck
     * @var string
     */
    protected $aibolit_status_file;
    /**
     * number of seconds while aibolit will stay alive, while not receiving any work
     * @var int
     */
    protected $stay_alive;
    /**
     * maximum number of seconds without updating ABOLIT_STATUS_FILE,
     * used to track if AIBOLIT is stuck, should be killed
     * @var int
     */
    protected $stuck_timeout;
    /**
     * number of seconds scripts would wait for aibolit to finish / send signal
     * @var int
     */
    protected $upload_timeout;
    /**
     * max number of files to pick
     * @var int
     */
    protected $max_files_per_notify_scan;
    /**
     * timestamp of last scan
     * @var int
     */
    protected $last_scan_time;
    /**
     * time to sleep between lifecycle iterations in microseconds
     */
    protected $sleep_time;

    protected $scannedNotify = 0;

    protected $report;

    protected $logger;

    protected $resident_in_dir_notify;
    protected $resident_in_dir_upload;
    protected $blacklist;
    protected $watchdog_socket;
    protected $activation_socket;
    protected $systemd = false;
    protected $interval = 0;
    protected $lastKeepAlive = 0;

    /**
     * ResidentMode constructor.
     * @param $options
     */
    public function __construct(
        Closure $report,
        $blacklist = null,
        Logger $logger = null,
        $resident_dir = '/var/imunify360/aibolit/resident',
        $stay_alive = 30,
        $stuck_timeout = 5,
        $upload_timeout = 10,
        $max_files_per_notify_scan = 500,
        $sleep_time = 100000
    ) {
        $this->setResidentDir($resident_dir);
        $this->resident_in_dir = $this->resident_dir . '/in';
        $this->resident_in_dir_upload = $this->resident_in_dir . '/upload-jobs';
        $this->resident_in_dir_notify = $this->resident_in_dir . '/notify-jobs';
        $this->resident_out_dir = $this->resident_dir . '/out';
        $this->aibolit_pid = $this->resident_dir . '/aibolit.pid';
        $this->aibolit_start_lock = $this->resident_dir . '/start.lock';
        $this->aibolit_status_file = $this->resident_dir . '/aibolit.status';
        $this->stay_alive = $stay_alive;
        $this->stuck_timeout = $stuck_timeout;
        $this->upload_timeout = $upload_timeout;
        /** @var int $max_files_per_notify_scan */
        if (!empty($max_files_per_notify_scan)) {
            $this->max_files_per_notify_scan = $max_files_per_notify_scan;
        }
        $this->sleep_time = $sleep_time;
        $this->report = $report;
        $this->blacklist = $blacklist;
        $this->logger = $logger;

        umask(0);
        if (!file_exists($this->resident_dir)) {
            mkdir($this->resident_dir, 0777, true);
        }
        if (!file_exists($this->resident_in_dir)) {
            mkdir($this->resident_in_dir, 0755);
        }
        if (!file_exists($this->resident_out_dir)) {
            mkdir($this->resident_out_dir, 0755);
        }
        if (!file_exists($this->resident_in_dir_notify)) {
            mkdir($this->resident_in_dir_notify, 0700);
        }
        if (!file_exists($this->resident_in_dir_upload)) {
            mkdir($this->resident_in_dir_upload, 01777);
        }

        $this->checkSpecs();

        $addr = getenv('NOTIFY_SOCKET');
        if ($addr[0] == '@') {
            $addr = "\0";
        }

        if ($addr) {
            $this->systemd = true;
        }

        if ($this->systemd) {
            $this->watchdog_socket = fsockopen('udg://' . $addr);
            stream_set_blocking($this->watchdog_socket, false);

            $this->activation_socket = fopen('php://fd/3', 'r');
            if ($this->activation_socket === false) {
                die("Something went wrong with activation socket.");
            }
            stream_set_blocking($this->activation_socket, false);

            if (getenv('WATCHDOG_USEC') !== false) {
                $this->interval = intval(getenv('WATCHDOG_USEC'));
            } else {
                $this->interval = 1000000;
            }
        }
        $this->lifeCycle();
    }

    protected function isRootWriteable($folder)
    {
        if (!file_exists($folder) || !is_dir($folder)) {
            return false;
        }

        $owner_id = (int)fileowner($folder);
        if (function_exists('posix_getpwuid')) {
            $owner = posix_getpwuid($owner_id);
            if (!isset($owner['name']) || $owner['name'] !== 'root') {
                return false;
            }
        } elseif ($owner_id != 0) {
            return false;
        }

        $perms = fileperms($folder);
        if (($perms & 0x0100)                           // owner r
            && ($perms & 0x0080)                        // owner w
            && ($perms & 0x0040) && !($perms & 0x0800)  // owner x
            && !($perms & 0x0010)                       // group without w
            && !($perms & 0x0002)                       // other without w
        ) {
            return true;
        }
        return false;
    }

    protected function isWorldWriteable($folder)
    {
        if (!file_exists($folder) || !is_dir($folder)) {
            return false;
        }

        $perms = fileperms($folder);
        if (($perms & 0x0004)                           // other r
            && ($perms & 0x0002)                        // other w
            && ($perms & 0x0200)                        // sticky bit
        ) {
            return true;
        }
        return false;
    }

    protected function checkSpecs()
    {
        if (!extension_loaded('posix')) {
            die('Error! For resident scan need posix extension.');
        } elseif (!$this->isRootWriteable($this->resident_in_dir_notify)) {
            die('Error! Notify in dir ' . $this->resident_in_dir_notify . ' must be root writeable.');
        } elseif (!$this->isWorldWriteable($this->resident_in_dir_upload)) {
            die('Error! Upload in dir ' . $this->resident_in_dir_upload . ' must be world writeable.');
        }
    }

    protected function setResidentDir($dir)
    {
        $this->resident_dir = $dir;
    }

    protected function writeReport($vars, $scan_time, $type, $file)
    {
        $file = basename($file);
        $report = $this->report->call($this);
        $critPHP = count($vars->criticalPHP);
        $critJS = count($vars->criticalJS);
        $black = count($vars->blackFiles);
        $warning = count($vars->warningPHP);
        $malware = ($critPHP > 0)
            || ($critJS > 0)
            || ($black > 0)
            || ($warning > 0);
        if ($malware) {
            $this->debugLog("Job {$file}: Found malware. PHP: {$critPHP}; JS: {$critJS}; Black: {$black}; SUS: {$warning}");
        } else {
            $this->debugLog("Job {$file}: No malware found.");
        }
        if ($type == 'upload') {
            $pid = intval(basename($file, '.upload_job'));
            if ($malware) {
                $this->debugLog("Job {$file}: Sending SIGUSR1 to {$pid}");
                posix_kill($pid, SIGUSR1);
            } else {
                $this->debugLog("Job {$file}: Sending SIGUSR2 to {$pid}");
                posix_kill($pid, SIGUSR2);
            }
        } elseif ($type == 'notify' && $malware) {
            $filename = basename($file, '.notify_job');
            $report->addVars($vars, $scan_time);

            $this->debugLog("Job {$file}: Creating report for job in {$filename}.report.tmp");

            $report->write($this->resident_out_dir . '/' . $filename . '.report.tmp');

            $this->debugLog("Job {$file}: Renaming report for job in {$filename}.report");

            @rename($this->resident_out_dir . '/' . $filename . '.report.tmp', $this->resident_out_dir . '/' . $filename . '.report');
            unset($report);
        }
    }

    protected function isJobFileExists($pattern)
    {
        if (count(glob($this->resident_in_dir . $pattern)) > 0) {
            return true;
        }
        return false;
    }

    protected function isUploadJob()
    {
        if ($this->isJobFileExists('/upload-jobs/*.upload_job')) {
            return true;
        }
        return false;
    }

    protected function scanJob($job_file, $type)
    {
        $start_time = microtime(true);

        $vars = new Variables();
        $vars->blacklist = $this->blacklist;

        $files_to_scan = array();
        $count = 0;

        $job = json_decode(file_get_contents($job_file));
        $file = basename($job_file);

        $this->debugLog("Job {$file} received from queue.");

        if ($type == 'notify') {
            $files_to_scan = $job->files;
            $count = count($files_to_scan);
            $this->debugLog("Job {$file}: notify. {$count} files to be scanned");

            if ($count > $this->max_files_per_notify_scan) {
                $this->debugLog("Job {$file}: Too many files to scan. Job skipped.");
                // TODO: show a warning: too many files to scan, the job was skipped
                return true;
            }

            if ($this->scannedNotify + $count > $this->max_files_per_notify_scan) {
                $this->scannedNotify = 0;
                unset($vars);
                unset($files_to_scan);
                return false;
            } else {
                $this->scannedNotify += $count;
            }
        } elseif ($type == 'upload') {
            $files_to_scan = $job->files;
            $count = count($files_to_scan);
            $this->debugLog("Job {$file}: upload. {$count} files to be scanned");

            if ($count > 1) {
                $this->debugLog("Job {$file}: Too many files to scan. Job skipped.");
                // TODO: show a warning: too many files to scan, the job was skipped
                return true;
            }
        }

        $vars->foundTotalFiles = $count;

        if (function_exists('QCR_GoScan')) {
            if ($this->systemd) {
                QCR_GoScan($files_to_scan, $vars, array($this, 'keepAlive'), true, false);
            } else {
                QCR_GoScan($files_to_scan, $vars, null, true, false);
            }

            whitelisting($vars);
        }

        $scan_time = round(microtime(true) - $start_time, 1);
        $this->writeReport($vars, $scan_time, $type, $job_file);

        unset($vars);
        unset($files_to_scan);

        if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE)) {
            @unlink(PROGRESS_LOG_FILE);
        }

        if (defined('CREATE_SHARED_MEMORY') && CREATE_SHARED_MEMORY) {
            shmop_delete(SHARED_MEMORY);
        }

        if (defined('SHARED_MEMORY')) {
            shmop_close(SHARED_MEMORY);
        }

        return true;
    }

    protected function isNotifyJob()
    {
        if ($this->isJobFileExists('/notify-jobs/*.notify_job')) {
            return true;
        }
        return false;
    }

    protected function scanUploadJob()
    {
        $files = glob($this->resident_in_dir_upload . '/*.upload_job');
        $this->scanJob($files[0], 'upload');
        $file = basename($files[0]);
        $this->debugLog("Job {$file}: Removing job.");
        unlink($files[0]);
    }

    protected function scanNotifyJob()
    {
        $files = glob($this->resident_in_dir_notify . '/*.notify_job');
        foreach ($files as $job) {
            $res = $this->scanJob($job, 'notify');
            if ($res) {
                $file = basename($job);
                $this->debugLog("Job {$file}: Removing job.");
                unlink($job);
            } else {
                break;
            }
        }
    }

    public function keepAlive()
    {
        if (intval((microtime(true) - $this->lastKeepAlive) * 1000000) > $this->interval / 2) {
            while (fread($this->activation_socket, 1024)) {
                // do nothing but read all dat from the socket
            }
            fwrite($this->watchdog_socket, 'WATCHDOG=1');
            $this->lastKeepAlive = microtime(true);
        }
    }

    protected function lifeCycle()
    {
        $this->debugLog("Starting resident-mode loop.");
        $this->last_scan_time = time();
        while (true) {
            if ($this->systemd) {
                $this->keepAlive();
            }
            while ($this->isUploadJob()) {
                $this->last_scan_time = time();
                $this->scanUploadJob();
            }

            while ($this->isNotifyJob() && !$this->isUploadJob()) {
                $this->last_scan_time = time();
                $this->scanNotifyJob();
            }
            if ($this->last_scan_time + $this->stay_alive < time()) {
                $this->debugLog("No more jobs. Shutting down.");
                break;
            }
            touch($this->aibolit_status_file);
            usleep($this->sleep_time); // 1\10 of second by default
        }
        if ($this->systemd) {
            fclose($this->watchdog_socket);
            fclose($this->activation_socket);
        }
        unlink($this->aibolit_status_file);
    }

    protected function debugLog($message)
    {
        if ($this->logger === null) {
            return;
        }
        $this->logger->debug($message);
    }
}


/**
 * Class FileHashMemoryDb.
 *
 * Implements operations to load the file hash database into memory and work with it.
 */
class FileHashMemoryDb
{
    const HEADER_SIZE = 1024;
    const ROW_SIZE = 20;

    /**
     * @var int
     */
    private $count;
    /**
     * @var array
     */
    private $header;
    /**
     * @var resource
     */
    private $fp;
    /**
     * @var array
     */
    private $data;

    /**
     * Creates a new DB file and open it.
     *
     * @param $filepath
     * @return FileHashMemoryDb
     * @throws Exception
     */
    public static function create($filepath)
    {
        if (file_exists($filepath)) {
            throw new Exception('File \'' . $filepath . '\' already exists.');
        }

        $value = pack('V', 0);
        $header = array_fill(0, 256, $value);
        file_put_contents($filepath, implode($header));

        return new self($filepath);
    }

    /**
     * Opens a particular DB file.
     *
     * @param $filepath
     * @return FileHashMemoryDb
     * @throws Exception
     */
    public static function open($filepath)
    {
        if (!file_exists($filepath)) {
            throw new Exception('File \'' . $filepath . '\' does not exist.');
        }

        return new self($filepath);
    }

    /**
     * FileHashMemoryDb constructor.
     *
     * @param mixed $filepath
     * @throws Exception
     */
    private function __construct($filepath)
    {
        $this->fp = fopen($filepath, 'rb');

        if (false === $this->fp) {
            throw new Exception('File \'' . $filepath . '\' can not be opened.');
        }

        try {
            $this->header = unpack('V256', fread($this->fp, self::HEADER_SIZE));
            $this->count = (int) (max(0, filesize($filepath) - self::HEADER_SIZE) / self::ROW_SIZE);
            foreach ($this->header as $chunk_id => $chunk_size) {
                if ($chunk_size > 0) {
                    $str = fread($this->fp, $chunk_size);
                } else {
                    $str = '';
                }
                $this->data[$chunk_id] = $str;
            }
        } catch (Exception $e) {
            throw new Exception('File \'' . $filepath . '\' is not a valid DB file. An original error: \'' . $e->getMessage() . '\'');
        }
    }

    /**
     * Calculates and returns number of hashes stored in a loaded database.
     *
     * @return int number of hashes stored in a DB
     */
    public function count()
    {
        return $this->count;
    }

    /**
     * Find hashes in a DB.
     *
     * @param array $list of hashes to find in a DB
     * @return array list of hashes from the $list parameter that are found in a DB
     */
    public function find($list)
    {
        sort($list);
        
        $hash = reset($list);

        $found = array();

        foreach ($this->header as $chunk_id => $chunk_size) {
            if ($chunk_size > 0) {
                $str = $this->data[$chunk_id];

                do {
                    $raw = pack("H*", $hash);
                    $id  = ord($raw[0]) + 1;

                    if ($chunk_id == $id AND $this->binarySearch($str, $raw)) {
                        $found[] = (string)$hash;
                    }

                } while ($chunk_id >= $id AND $hash = next($list));

                if ($hash === false) {
                    break;
                }
            }
        }

        return $found;
    }

    /**
     * Searches $item in the $str using an implementation of the binary search algorithm.
     *
     * @param $str
     * @param $item
     * @return bool
     */
    private function binarySearch($str, $item) {
        $item_size = strlen($item);
        if ($item_size == 0) {
            return false;
        }

        $first = 0;

        $last = floor(strlen($str) / $item_size);

        while ($first < $last) {
            $mid = $first + (($last - $first) >> 1);
            $b   = substr($str, $mid * $item_size, $item_size);
            if (strcmp($item, $b) <= 0) {
                $last = $mid;
            } else {
                $first = $mid + 1;
            }
        }

        $b = substr($str, $last * $item_size, $item_size);
        if ($b == $item) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * FileHashDB destructor.
     */
    public function __destruct()
    {
        fclose($this->fp);
    }
}

class FilepathEscaper
{
    public static function encodeFilepath($filepath)
    {
        return str_replace(array('\\', "\n", "\r"), array('\\\\', '\\n', '\\r'), $filepath);
    }
    
    public static function decodeFilepath($filepath)
    {
        return preg_replace_callback('~(\\\\+)(.)~', function ($matches) {
            $count = strlen($matches[1]);
            if ($count % 2 === 0) {
                return str_repeat('\\', $count/2) . $matches[2];
            }
            return str_repeat('\\', floor($count/2)) . stripcslashes('\\' . $matches[2]);
        }, $filepath);
    }
    
    public static function encodeFilepathByBase64($filepath)
    {
        return base64_encode($filepath);
    }
    
    public static function decodeFilepathByBase64($filepath_base64)
    {
        return base64_decode($filepath_base64);
    }
}


/**
 * Class RapidScanStorageRecord.
 *
 * Implements db record for RapidScan
 */
class RapidScanStorageRecord
{
    const WHITE = 1; // white listed file in cloud db
    const BLACK = 6; // black listed file in cloud db
    const DUAL_USE = 2; // dual used listed file in cloud db
    const UNKNOWN = 3; // unknown file --> file not listed in cloud db
    const HEURISTIC = 4; //detected as heuristic
    const CONFLICT = 5; // we have filename hashing conflict for this file
    const NEWFILE = 0; // this is a new file (or content changed)
    const RX_MALWARE = 7; // detected as malware by rx scan
    const RX_SUSPICIOUS = 8; // detected as suspicious by rx scan
    const RX_GOOD = 9; // detected as good by rx scan

    /**
     * @var string;
     */
    private $filename;
    /**
     * @var int
     */
    private $key;
    /**
     * @var int
     */
    private $updated_ts;
    /**
     * @var int
     */
    private $verdict;
    /**
     * @var string
     */
    private $sha2;
    /**
     * @var string
     */
    private $signature = '';
    /**
     * @var string
     */
    private $snippet = '';

    /**
     * RapidScanStorageRecord constructor.
     * @param $key
     * @param $updated_ts
     * @param int $verdict
     * @param $sha2
     * @param string $signature
     */
    private function __construct($key, $updated_ts, $verdict, $sha2, $signature, $filename, $snippet)
    {
        $this->filename = $filename;
        $this->key = $key;
        $this->updated_ts = $updated_ts;
        $this->verdict = $verdict;
        $this->sha2 = $sha2;
        $this->snippet = $snippet;
        if ($signature!=='') {
            $this->signature = self::padTo10Bytes($signature);
        }
    }

    /**
     * Create db storage record from file
     * @param $filename
     * @param string $signature
     * @param int $verdict
     * @return RapidScanStorageRecord
     * @throws Exception
     */
    public static function fromFile($filename, $signature = '', $verdict = self::UNKNOWN, $snippet = '')
    {
        if (!file_exists($filename)) {
            throw new Exception('File \'' . $filename . '\' doesn\'t exists.');
        }

        $key = intval(strval(self::fileNameHash($filename)) . strval(fileinode($filename)));
        $updated_ts = max(filemtime($filename), filectime($filename));
        $sha2 = '';
        if (!$verdict) {
            $verdict = self::NEWFILE;
        }
        if ($signature!=='') {
            $signature = self::padTo10Bytes($signature);
        }
        return new self($key, $updated_ts, $verdict, $sha2, $signature, $filename, $snippet);
    }

    /**
     * @param $array
     * @return RapidScanStorageRecord
     */
    public static function fromArray($array)
    {
        $key = $array['key'];
        $updated_ts = $array['updated_ts'];
        $sha2 = hex2bin($array['sha2']);
        $verdict = $array['verdict'];
        $signature = $array['signature'];
        return new self($key, $updated_ts, $verdict, $sha2, $signature, '', '');
    }

    /**
     * @return array
     */
    public function toArray()
    {
        $array['key'] = $this->key;
        $array['updated_ts'] = $this->updated_ts;
        $array['verdict'] = $this->verdict;
        $array['sha2'] = bin2hex($this->sha2);
        $array['signature'] = $this->signature;
        return $array;
    }

    /**
     * @return array
     */
    public function calcSha2()
    {
        $this->sha2 = hash('sha256', file_get_contents($this->filename), true);
    }

    /**
     * @param $verdict
     */
    public function setVerdict($verdict)
    {
        $this->verdict = $verdict;
    }

    /**
     * @return int
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param $signature
     */
    public function setSignature($signature)
    {
        if ($signature!=='') {
            $this->signature = self::padTo10Bytes($signature);
        }
    }

    /**
     * Unpack bytestring $value to RapidScanStorageRecord
     * @param $hash
     * @param $value
     * @return RapidScanStorageRecord
     */
    public static function unpack($hash, $value)
    {
        // pack format
        // 8 bytes timestamp
        // 1 byte verdict
        // 32 bytes sha2
        // 10 bytes signature (only for BLACK, DUAL_USE, RX_MALWARE, RX_SUSPICIOUS)
        // note - we will hold bloomfilter for file later on for those that are WHITE
        // it will be used to detect installed apps

        $signature = '';
        $timestamp = unpack("l", substr($value, 0, 8));
        $updated_ts = array_pop($timestamp);
        $verdict = $value[8];
        $verdict = intval(bin2hex($verdict));
        $sha2 = substr($value, 9, 32);
        if (in_array($verdict, array(self::BLACK, self::DUAL_USE, self::RX_MALWARE, self::RX_SUSPICIOUS))) {
            $signature = substr($value, 41, 10);  # 10 bytes signature string
        }
        if (strlen($value) > 51) {
            $snippet = substr($value, 51);
        } else {
            $snippet = '';
        }
        return new self($hash, $updated_ts, $verdict, $sha2, $signature, '', $snippet);
    }

    /**
     * Pack RapidScanStorageRecord to bytestring to save in db
     * @return string
     */
    public function pack()
    {
        $signature = '';
        if (strlen($this->signature) > 0) {
            $signature = $this->signature;
        }
        return (($this->updated_ts < 0) ? str_pad(pack("l", $this->updated_ts), 8, "\xff") : str_pad(pack("l", $this->updated_ts), 8, "\x00")) . pack("c", $this->verdict) . $this->sha2 . $signature . $this->snippet;
    }

    /**
     * Hash function for create hash of full filename to store in db as key
     * @param $str
     * @return int
     */
    private static function fileNameHash($str)
    {
        for ($i = 0, $h = 5381, $len = strlen($str); $i < $len; $i++) {
            $h = (($h << 5) + $h + ord($str[$i])) & 0x7FFFFFFF;
        }
        return $h;
    }

    /**
     * Convert string to utf-8 and fitting/padding it to 10 bytes
     * @param $str
     * @return string
     */
    private static function padTo10Bytes($str)
    {
        # convert string to bytes in UTF8, and add 0 bytes to pad it to 10
        # cut to 10 bytes of necessary
        $str = utf8_encode($str);
        $len = strlen($str);
        if ($len < 10) {
            $str = str_pad($str, 10, "\x00");
        } elseif ($len > 10) {
            $str = substr($str, 0, 10);
        }
        return $str;
    }

    /**
     * @return int
     */
    public function getUpdatedTs()
    {
        return $this->updated_ts;
    }

    /**
     * @return int
     */
    public function getVerdict()
    {
        return $this->verdict;
    }

    /**
     * @return string
     */
    public function getSha2()
    {
        return $this->sha2;
    }

    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return string
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * @param $filename
     */
    public function setFilename($filename)
    {
        $this->filename = $filename;
    }

    /**
     * @return string
     */
    public function getSnippet()
    {
        return $this->snippet;
    }

    /**
     * @param $filename
     */
    public function setSnippet($snippet)
    {
        $this->snippet = $snippet;
    }
}


/**
 * Interface RapidScanStorage implements class to work with RapidScan db
 * @package Aibolit\Lib\Scantrack
 */
class RapidScanStorage
{
    /**
     * @var string
     */
    protected $old_dir;
    /**
     * @var string
     */
    protected $new_dir;
    /**
     * @var resource
     */
    protected $new_db;
    /**
     * @var resource
     */
    protected $old_db;
    /**
     * @var resource
     */
    private $wb;
    /**
     * @var int
     */
    public $batch_count;

    /**
     * RapidScanStorage constructor.
     * @param $base - folder where db located
     */
    public function __construct($base)
    {
        if(!is_dir($base)) mkdir($base);
        $this->old_dir = $base . '/current';
        $this->new_dir = $base . '/new';
        $options = array('create_if_missing' => true, 'compression'=> LEVELDB_NO_COMPRESSION);

        $this->new_db = new LevelDB($this->new_dir, $options);
        $this->old_db = new LevelDB($this->old_dir, $options);

        $this->wb = NULL;  // will be use to track writing to batch
        $this->batch_count = 0;
    }

    /**
     * @param RapidScanStorageRecord $record
     * @return bool
     */
    public function put(RapidScanStorageRecord $record)
    {
        $this->startBatch();
        $this->batch_count++;
        $value = $this->wb->put($record->getKey(), $record->pack());
        return $value;
    }

    /**
     * @param $hash
     * @return bool|RapidScanStorageRecord
     */
    public function getNew($hash)
    {
        $value = $this->new_db->get($hash);
        if($value) {
            $return = RapidScanStorageRecord::unpack($hash, $value);
            return $return;
        }
        return false;
    }

    /**
     * @param $hash
     * @return bool|RapidScanStorageRecord
     */
    public function getOld($hash)
    {
        $value = $this->old_db->get($hash);
        if($value) {
            $return = RapidScanStorageRecord::unpack($hash, $value);
            return $return;
        }
        return false;
    }

    /**
     * @param $hash
     * @return bool
     */
    public function delete($hash)
    {
        $return = $this->new_db->delete($hash);
        return $return;
    }

    /**
     * Close db, remove old db, move new to a new space
     */
    public function finish()
    {
        $this->old_db->close();
        $this->flushBatch();
        $this->new_db->close();

        self::rmtree($this->old_dir);
        rename($this->new_dir, $this->old_dir);
    }

    /**
     * Start batch operations
     */
    private function startBatch()
    {
        if(!$this->wb) {
            $this->wb = new LevelDBWriteBatch();
            $this->batch_count = 0;
        }
    }

    /**
     *  write all data in a batch, reset batch
     */
    public function flushBatch()
    {
        if ($this->wb) {
            $this->new_db->write($this->wb);
            $this->batch_count = 0;
            $this->wb = NULL;
        }
    }
    /**
     * Helper function to remove folder tree
     * @param $path
     */
    public static function rmTree($path)
    {
        if (is_dir($path)) {
            foreach (scandir($path) as $name) {
                if (in_array($name, array('.', '..'))) {
                    continue;
                }
                $subpath = $path.DIRECTORY_SEPARATOR . $name;
                self::rmTree($subpath);
            }
            rmdir($path);
        } else {
            unlink($path);
        }
    }
}

/**
 * For work with Cloud Assisted Storage
 * @package Aibolit\Lib\Scantrack
 */
class CloudAssistedStorage
{
    private $db_filepath = '';

    public function __construct($folder)
    {
        if(!is_dir($folder)) {
            mkdir($folder);
        }
        $this->db_filepath = $folder . DIRECTORY_SEPARATOR . 'cloud_assisted_verdicts.json';
    }

    public function getList()
    {
        if (!file_exists($this->db_filepath)) {
            return [];
        }
        $content = file_get_contents($this->db_filepath);
        if (!$content) {
            return [];
        }
        $list = json_decode($content, true);
        if (!$list || !is_array($list)) {
            return [];
        }
        return $list;
    }

    public function putList($list)
    {
        file_put_contents($this->db_filepath, json_encode($list));
    }
    
    public function delete()
    {
        if (!file_exists($this->db_filepath)) {
            return;
        }
        unlink($this->db_filepath);
    }
}

/**
 * This is actual class that does account level scan
 * and remembers the state of scan
 * Class RapidAccountScan
 * @package Aibolit\Lib\Scantrack
 */
class RapidAccountScan
{
    const RESCAN_ALL        = 0; // mode of operation --> rescan all files that are not white/black/dual_use using cloud scanner & regex scanner
    const RESCAN_NONE       = 1; // don't re-scan any files that we already scanned
    const RESCAN_SUSPICIOUS = 2; // only re-scan suspicious files using only regex scanner

    const MAX_BATCH     = 1000; // max files to write in a db batch write
    const MAX_TO_SCAN   = 1000; // max files to scan using cloud/rx scanner at a time

    private $db;
    private $cas_db;
    private $cas_list = [];
    private $vars = null;
    private $scanlist;
    private $collisions;
    private $processedFiles;
    private $rescan_count = 0;
    private $counter = 0;
    private $str_error = false;

    /**
     * RapidAccountScan constructor.
     * @param RapidScanStorage $rapidScanStorage
     */
    public function __construct($rapidScanStorage, $cloudAssistedStorage, &$vars, $counter = 0)
    {
        $this->db = $rapidScanStorage;
        $this->cas_db = $cloudAssistedStorage;
        $this->vars = $vars;
        $this->scanlist = array();
        $this->collisions = array();
        $this->processedFiles = 0;
        $this->counter = $counter;
    }

    /**
     * Get str error
     */
    public function getStrError()
    {
        return $this->str_error;
    }

    /**
     * Get count of rescan(regexp) files
     */
    public function getRescanCount()
    {
        return $this->rescan_count;
    }

    /**
     * placeholder for actual regex scan
     * return RX_GOOD, RX_MALWARE, RX_SUSPICIOUS and signature from regex scaner
     * if we got one
     */
    private function regexScan($filename, $i, $vars)
    {
        $this->rescan_count++;
        printProgress(++$this->processedFiles, $filename, $vars);
        $return = QCR_ScanFile($filename, $vars, null, $i, false);
        return $return;
    }

    /**
     * we will have batch of new files that we will scan
     * here we will write them into db once we scanned them
     * we need to check that there is no conflicts/collisions
     * in names, for that we check for data in db if such filename_hash
     * already exists, but we also keep set of filename_hashes of given
     * batch, to rule out conflicts in current batch as well
     */
    private function writeNew()
    {
        $this->collisions = array();
        foreach ($this->scanlist as $fileinfo) {
            if (in_array($fileinfo->getKey(), $this->collisions) || $this->db->getNew($fileinfo->getKey())) {
                $fileinfo->setVerdict(RapidScanStorageRecord::CONFLICT);
            }
            $this->collisions [] = $fileinfo->getKey();
            $this->db->put($fileinfo);
        }
    }

    /**
     * given a batch do cloudscan
     * @throws \Exception
     */
    private function doCloudScan()
    {
        if (count($this->scanlist) <= 0) {
            return;
        }

        $index_table    = [];
        $blackfiles     = [];
        $sha_list       = [];

        foreach ($this->scanlist as $i => $fileinfo) {
            $sha_list[] = bin2hex($fileinfo->getSha2());
            $index_table[] = $i;
            $fileinfo->setVerdict(RapidScanStorageRecord::UNKNOWN);
        }

        $ca = Factory::instance()->create(CloudAssistedRequest::class, [CLOUD_ASSIST_TOKEN]);

        $white_raw          = [];
        $black_raw          = [];
        $verdicts_black_raw = [];
        
        try {
            list($white_raw, $black_raw, $verdicts_black_raw) = $ca->checkFilesByHash($sha_list);
        } catch (\Exception $e) {
            $this->str_error = $e->getMessage();
        }
        
        $dual = array_intersect($white_raw, $black_raw);

        foreach ($white_raw as $index) {
            $this->scanlist[$index_table[$index]]->setVerdict(RapidScanStorageRecord::WHITE);
        }
        $signatures_db = [];
        foreach ($black_raw as $i => $index) {
            $this->scanlist[$index_table[$index]]->setVerdict(RapidScanStorageRecord::BLACK);
            $signature      = isset($verdicts_black_raw[$i]) ? $verdicts_black_raw[$i] : '';
            $signature_id   = 'c_' . hash('crc32', $signature);
            $signatures_db[$signature_id] = $signature;
            $this->scanlist[$index_table[$index]]->setSignature($signature_id);
            $blackfiles[$this->scanlist[$index_table[$index]]->getFilename()] = [
                'h'         => $sha_list[$index],
                'ts'        => time(),
                'sn'        => $signature,
                'ras_sigid' => $signature_id,
            ];
        }

        $signatures_list = $this->cas_db->getList();
        foreach ($signatures_db as $hash => $sig) {
            $this->cas_list[$hash] = $sig;
            if (isset($signatures_list[$hash])) {
                continue;
            }
            $signatures_list[$hash] = $sig;
        }
        $this->cas_db->putList($signatures_list);
        
        foreach ($dual as $index) {
            $this->scanlist[$index_table[$index]]->setVerdict(RapidScanStorageRecord::DUAL_USE);
            $this->scanlist[$index_table[$index]]->setSignature('DUAL'); //later on we will get sig info from cloud
        }

        // we can now update verdicts in batch for those that we know
        //add entries to report, when needed

        $this->vars->blackFiles = array_merge($this->vars->blackFiles, $blackfiles);

        unset($white_raw);
        unset($black_raw);
        unset($dual);
        unset($sha_list);
        unset($index_table);
    }

    /**
     * regex scan a single file, add entry to report if needed
     * @param $fileInfo
     * @param $i
     */
    private function _regexScan($fileInfo, $i, $vars)
    {
        $regex_res = $this->regexScan($fileInfo->getFilename(), $i, $vars);
        if (!is_array($regex_res)) {
            return;
        }
        list($result, $sigId, $snippet) = $regex_res;
        $fileInfo->setVerdict($result);
        if ($result !== RapidScanStorageRecord::RX_GOOD) {
            $fileInfo->setSignature($sigId);
            $fileInfo->setSnippet($snippet);
        }
    }

    /**
     * regex scan batch of files.
     */
    private function doRegexScan($vars)
    {
        foreach ($this->scanlist as $i => $fileinfo) {
            if (!in_array($fileinfo->getVerdict(), array(
                RapidScanStorageRecord::WHITE,
                RapidScanStorageRecord::BLACK,
                RapidScanStorageRecord::DUAL_USE
            ))
            ) {
                $this->_regexScan($fileinfo, $i, $vars);
            }
        }
    }

    private function processScanList($vars)
    {
        $this->doCloudScan();
        $this->doRegexScan($vars);
        $this->writeNew();
        $this->scanlist = [];
    }

    private function scanFile($filename, $rescan, $i, $vars)
    {
        global $g_Mnemo;

        if (!file_exists($filename)) {
            return false;
        }
        $file = RapidScanStorageRecord::fromFile($filename);

        $old_value = $this->db->getOld($file->getKey());
        $old_mtime = 0;
        if ($old_value) {
            $old_mtime = $old_value->getUpdatedTs();
            if ($file->getUpdatedTs() == $old_mtime) {
                $file = $old_value;
                $file->setFilename($filename);
            }
        }

        if ($file->getVerdict() == RapidScanStorageRecord::UNKNOWN
            || $file->getVerdict() == RapidScanStorageRecord::CONFLICT
            || $file->getUpdatedTs() !== $old_mtime
        ) {
            // these files has changed or we know nothing about them, lets re-calculate sha2
            // and do full scan
            $file->calcSha2();
            $file->setVerdict(RapidScanStorageRecord::NEWFILE);
            $this->scanlist[$i] = $file;
        } elseif ($file->getVerdict() == RapidScanStorageRecord::BLACK
            || $file->getVerdict() == RapidScanStorageRecord::DUAL_USE
        ) {
            //these files hasn't changed, but need to be reported as they are on one of the lists
            $signature_id   = $file->getSignature();
            $signature      = isset($this->cas_list[$signature_id]) ? $this->cas_list[$signature_id] : '';
            $this->vars->blackFiles[$filename] = [
                'h'         => bin2hex($file->getSha2()),
                'ts'        => time(),
                'sn'        => $signature,
                'ras_sigid' => $signature_id,
            ];
            $this->db->put($file);
        } elseif (($rescan == self::RESCAN_SUSPICIOUS || $rescan == self::RESCAN_NONE)
            && $file->getVerdict() == RapidScanStorageRecord::RX_MALWARE
        ) {
            //this files were detected as rx malware before, let's report them

            $sigId = trim($file->getSignature(), "\0");

            if (isset($sigId) && isset($g_Mnemo[$sigId])) {
                $sigName = $g_Mnemo[$sigId];
                $snippet = $file->getSnippet();
                if (strpos($sigName, 'SUS') !== false && AI_EXTRA_WARN) {
                    $vars->warningPHP[] = $i;
                    $vars->warningPHPFragment[] = $snippet;
                    $vars->warningPHPSig[] = $sigId;
                } elseif (strtolower(pathinfo($filename, PATHINFO_EXTENSION)) == 'js') {
                    $vars->criticalJS[] = $i;
                    $vars->criticalJSFragment[] = $snippet;
                    $vars->criticalJSSig[] = $sigId;
                } else {
                    $vars->criticalPHP[] = $i;
                    $vars->criticalPHPFragment[] = $snippet;
                    $vars->criticalPHPSig[] = $sigId;
                }
                AddResult($filename, $i, $vars);
                $this->db->put($file);
            } else {
                $this->scanlist[$i] = $file;
            }
        } elseif ((
                $rescan == self::RESCAN_ALL
                && in_array($file->getVerdict(), array(
                    RapidScanStorageRecord::RX_SUSPICIOUS,
                    RapidScanStorageRecord::RX_GOOD,
                    RapidScanStorageRecord::RX_MALWARE
                ))
            )
            || (
                $rescan == self::RESCAN_SUSPICIOUS
                && $file->getVerdict() == RapidScanStorageRecord::RX_SUSPICIOUS
            )
        ) {
            //rescan all mode, all none white/black/dual listed files need to be re-scanned fully

            $this->scanlist[$i] = $file;
        } else {
            //in theory -- we should have only white files here...
            $this->db->put($file);
        }

        if (count($this->scanlist) >= self::MAX_TO_SCAN) {
            // our scan list is big enough
            // let's flush db, and scan the list
            $this->db->flushBatch();
            $this->processScanList($vars);
        }

        if ($this->db->batch_count >= self::MAX_BATCH) {
            //we have added many entries to db, time to flush it
            $this->db->flushBatch();
            $this->processScanList($vars);
        }
    }

    public function scan($files, $vars, $rescan = self::RESCAN_SUSPICIOUS)
    {
        $i = 0;
        $this->cas_list = $this->cas_db->getList();
        
        foreach ($files as $filepath) {
            $counter = $this->counter + $i;
            $vars->totalFiles++;
            $this->processedFiles = $counter - $vars->totalFolder - count($this->scanlist);
            printProgress($this->processedFiles, $filepath, $vars);
            $this->scanFile($filepath, $rescan, $counter, $vars);
            $i++;
        }
        
        if ($rescan == self::RESCAN_ALL) {
            $this->cas_db->delete();
            $this->cas_list = [];
            foreach ($this->vars->blackFiles as $blackfile) {
                $this->cas_list[$blackfile['ras_sigid']] = $blackfile['sn'];
            }
            $this->cas_db->putList($this->cas_list);
        }

        //let's flush db again
        $this->db->flushBatch();

        //process whatever is left in our scan list
        if (count($this->scanlist) > 0) {
            $this->processScanList($vars);
        }

        // whitelist

        $snum = 0;
        $list = check_whitelist($vars->structure['crc'], $snum);
        $keys = array(
            'criticalPHP',
            'criticalJS',
            'g_Iframer',
            'g_Base64',
            'phishing',
            'adwareList',
            'g_Redirect',
            'warningPHP'
        );
        foreach ($keys as $p) {
            if (empty($vars->{$p})) {
                continue;
            }
            $p_Fragment = $p . 'Fragment';
            $p_Sig      = $p . 'Sig';
            if ($p == 'g_Redirect') {
                $p_Fragment = $p . 'PHPFragment';
            }
            if ($p == 'g_Phishing') {
                $p_Sig = $p . 'SigFragment';
            }

            $count = count($vars->{$p});
            for ($i = 0; $i < $count; $i++) {
                $id = $vars->{$p}[$i];
                if ($vars->structure['crc'][$id] !== 0 && in_array($vars->structure['crc'][$id], $list)) {
                    $rec = RapidScanStorageRecord::fromFile($vars->structure['n'][$id]);
                    $rec->calcSha2();
                    $rec->setVerdict(RapidScanStorageRecord::RX_GOOD);
                    $this->db->put($rec);
                    unset($vars->{$p}[$i]);
                    unset($vars->{$p_Sig}[$i]);
                    unset($vars->{$p_Fragment}[$i]);
                }
            }

            $vars->{$p}             = array_values($vars->{$p});
            $vars->{$p_Fragment}    = array_values($vars->{$p_Fragment});
            if (!empty($vars->{$p_Sig})) {
                $vars->{$p_Sig} = array_values($vars->{$p_Sig});
            }

            //close databases and rename new into 'current'
            $this->db->finish();
        }
    }
}

/**
 * DbFolderSpecification class file.
 */

/**
 * Class DbFolderSpecification.
 *
 * It can be use for checking requirements for a folder that is used for storing a RapidScan DB.
 */
class DbFolderSpecification
{
    /**
     * Check whether a particular folder satisfies requirements.
     *
     * @param string $folder
     * @return bool
     */
    public function satisfiedBy($folder)
    {
        if (!file_exists($folder) || !is_dir($folder)) {
            return false;
        }

        $owner_id = (int)fileowner($folder);
        if (function_exists('posix_getpwuid')) {
            $owner = posix_getpwuid($owner_id);
            if (!isset($owner['name']) || $owner['name'] !== 'root') {
                return false;
            }
        }
        elseif ($owner_id != 0) {
            return false;
        }

        $perms = fileperms($folder);
        if (($perms & 0x0100)                           // owner r
            && ($perms & 0x0080)                        // owner w
            && ($perms & 0x0040) && !($perms & 0x0800)  // owner x
            && !($perms & 0x0020)                       // group without r
            && !($perms & 0x0010)                       // group without w
            && (!($perms & 0x0008) || ($perms & 0x0400))// group without x
            && !($perms & 0x0004)                       // other without r
            && !($perms & 0x0002)                       // other without w
            && (!($perms & 0x0001) || ($perms & 0x0200))// other without x
        ) {
            return true;
        }
        return false;
    }
}
/**
 * CriticalFileSpecification class file.
 */

/**
 * Class CriticalFileSpecification.
 */
class CriticalFileSpecification
{
    /**
     * @var array list of extension
     */
    private static $extensions = array(
        'php',
        'htaccess',
        'cgi',
        'pl',
        'o',
        'so',
        'py',
        'sh',
        'phtml',
        'php3',
        'php4',
        'php5',
        'php6',
        'php7',
        'pht',
        'shtml',
        'susp',
        'suspected',
        'infected',
        'vir',
        'ico',
        'js',
        'json',
        'com',
        ''
    );

    /**
     * Check whether a particular file with specified path is critical.
     *
     * @param string $path
     * @return bool
     */
    public function satisfiedBy($path)
    {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return in_array($ext, self::$extensions);
    }
}
class Helpers
{
    public static function format($source)
    {
        $t_count = 0;
        $in_object = false;
        $in_at = false;
        $in_php = false;
        $in_for = false;
        $in_comp = false;
        $in_quote = false;
        $in_var = false;

        if (!defined('T_ML_COMMENT')) {
            define('T_ML_COMMENT', T_COMMENT);
        }

        $result = '';
        @$tokens = token_get_all($source);
        foreach ($tokens as $token) {
            if (is_string($token)) {
                $token = trim($token);
                if ($token == '{') {
                    if ($in_for) {
                        $in_for = false;
                    }
                    if (!$in_quote && !$in_var) {
                        $t_count++;
                        $result = rtrim($result) . ' ' . $token . "\n" . str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                } elseif ($token == '$') {
                    $in_var = true;
                    $result = $result . $token;
                } elseif ($token == '}') {
                    if (!$in_quote && !$in_var) {
                        $new_line = true;
                        $t_count--;
                        if ($t_count < 0) {
                            $t_count = 0;
                        }
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) .
                            $token . "\n" . @str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                    if ($in_var) {
                        $in_var = false;
                    }
                } elseif ($token == ';') {
                    if ($in_comp) {
                        $in_comp = false;
                    }
                    if ($in_for) {
                        $result .= $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == ':') {
                    if ($in_comp) {
                        $result .= ' ' . $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == '(') {
                    $result .= ' ' . $token;
                } elseif ($token == ')') {
                    $result .= $token;
                } elseif ($token == '@') {
                    $in_at = true;
                    $result .= $token;
                } elseif ($token == '.') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '=') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '?') {
                    $in_comp = true;
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '"') {
                    if ($in_quote) {
                        $in_quote = false;
                    } else {
                        $in_quote = true;
                    }
                    $result .= $token;
                } else {
                    $result .= $token;
                }
            } else {
                list($id, $text) = $token;
                switch ($id) {
                    case T_OPEN_TAG:
                    case T_OPEN_TAG_WITH_ECHO:
                        $in_php = true;
                        $result .= trim($text) . "\n";
                        break;
                    case T_CLOSE_TAG:
                        $in_php = false;
                        $result .= trim($text);
                        break;
                    case T_FOR:
                        $in_for = true;
                        $result .= trim($text);
                        break;
                    case T_OBJECT_OPERATOR:
                        $result .= trim($text);
                        $in_object = true;
                        break;

                    case T_ENCAPSED_AND_WHITESPACE:
                    case T_WHITESPACE:
                        $result .= trim($text);
                        break;
                    case T_RETURN:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ELSE:
                    case T_ELSEIF:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_CASE:
                    case T_DEFAULT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count - 1) . trim($text) . ' ';
                        break;
                    case T_FUNCTION:
                    case T_CLASS:
                        $result .= "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_AND_EQUAL:
                    case T_AS:
                    case T_BOOLEAN_AND:
                    case T_BOOLEAN_OR:
                    case T_CONCAT_EQUAL:
                    case T_DIV_EQUAL:
                    case T_DOUBLE_ARROW:
                    case T_IS_EQUAL:
                    case T_IS_GREATER_OR_EQUAL:
                    case T_IS_IDENTICAL:
                    case T_IS_NOT_EQUAL:
                    case T_IS_NOT_IDENTICAL:
                    case T_LOGICAL_AND:
                    case T_LOGICAL_OR:
                    case T_LOGICAL_XOR:
                    case T_MINUS_EQUAL:
                    case T_MOD_EQUAL:
                    case T_MUL_EQUAL:
                    case T_OR_EQUAL:
                    case T_PLUS_EQUAL:
                    case T_SL:
                    case T_SL_EQUAL:
                    case T_SR:
                    case T_SR_EQUAL:
                    case T_START_HEREDOC:
                    case T_XOR_EQUAL:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_COMMENT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ML_COMMENT:
                        $result = rtrim($result) . "\n";
                        $lines = explode("\n", $text);
                        foreach ($lines as $line) {
                            $result .= str_repeat('    ', $t_count) . trim($line);
                        }
                        $result .= "\n";
                        break;
                    case T_INLINE_HTML:
                        $result .= $text;
                        break;
                    default:
                        $result .= trim($text);
                        break;
                }
            }
        }
        return $result;
    }

    public static function replaceCreateFunction($str)
    {
        $hangs = 20;
        while (strpos($str, 'create_function') !== false && $hangs--) {
            $start_pos = strpos($str, 'create_function');
            $end_pos = 0;
            $brackets = 0;
            $started = false;
            $opened = 0;
            $closed = 0;
            for ($i = $start_pos; $i < strlen($str); $i++) {
                if ($str[$i] == '(') {
                    $started = true;
                    $brackets++;
                    $opened++;
                } else if ($str[$i] == ')') {
                    $closed++;
                    $brackets--;
                }
                if ($brackets == 0 && $started) {
                    $end_pos = $i + 1;
                    break;
                }
            }

            $cr_func = substr($str, $start_pos, $end_pos - $start_pos);
            $func = implode('function(', explode('create_function(\'', $cr_func, 2));
            //$func = substr_replace('create_function(\'', 'function(', $cr_func);
            //$func = str_replace('\',\'', ') {', $func);
            $func = implode(') {', explode('\',\'', $func, 2));
            $func = substr($func, 0, -2) . '}';
            $str = str_replace($cr_func, $func, $str);
        }
        return $str;
    }

    public static function calc($expr)
    {
        if (is_array($expr)) {
            $expr = $expr[0];
        }
        preg_match('~(chr|min|max|round)?\(([^\)]+)\)~msi', $expr, $expr_arr);
        if (@$expr_arr[1] == 'min' || @$expr_arr[1] == 'max') {
            return $expr_arr[1](explode(',', $expr_arr[2]));
        } elseif (@$expr_arr[1] == 'chr') {
            if ($expr_arr[2][0] === '(') {
                $expr_arr[2] = substr($expr_arr[2], 1);
            }
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1](intval($expr_arr[2]));
        } elseif (@$expr_arr[1] == 'round') {
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]($expr_arr[2]);
        } else {
            preg_match_all('~([\d\.a-fx]+)([\*\/\-\+\^\|\&])?~', $expr, $expr_arr);
            foreach ($expr_arr[1] as &$expr_arg) {
                if (strpos($expr_arg, "0x")!==false) {
                    $expr = str_replace($expr_arg, hexdec($expr_arg), $expr);
                    $expr_arg = hexdec($expr_arg);
                }
            }
            if (in_array('*', $expr_arr[2]) !== false) {
                $pos = array_search('*', $expr_arr[2]);
                $res = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('/', $expr_arr[2]) !== false) {
                $pos = array_search('/', $expr_arr[2]);
                $res = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('-', $expr_arr[2]) !== false) {
                $pos = array_search('-', $expr_arr[2]);
                $res = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('+', $expr_arr[2]) !== false) {
                $pos = array_search('+', $expr_arr[2]);
                $res = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('^', $expr_arr[2]) !== false) {
                $pos = array_search('^', $expr_arr[2]);
                $res = $expr_arr[1][$pos] ^ $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('|', $expr_arr[2]) !== false) {
                $pos = array_search('|', $expr_arr[2]);
                $res = $expr_arr[1][$pos] | $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('&', $expr_arr[2]) !== false) {
                $pos = array_search('&', $expr_arr[2]);
                $res = $expr_arr[1][$pos] & $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } else {
                return $expr;
            }

            return $expr;
        }
    }

    public static function getEvalCode($string)
    {
        preg_match("/eval\(([^\)]+)\)/msi", $string, $matches);
        return (empty($matches)) ? '' : end($matches);
    }

    public static function getTextInsideQuotes($string)
    {
        if (preg_match_all('/("(.*)")/msi', $string, $matches)) {
            return @end(end($matches));
        } elseif (preg_match_all('/\((\'(.*)\')/msi', $string, $matches)) {
            return @end(end($matches));
        } else {
            return '';
        }
    }

    public static function getNeedles($string)
    {
        preg_match_all("/'(.*?)'/msi", $string, $matches);

        return (empty($matches)) ? array() : $matches[1];
    }

    public static function getHexValues($string)
    {
        preg_match_all('/0x[a-fA-F0-9]{1,8}/msi', $string, $matches);
        return (empty($matches)) ? array() : $matches[0];
    }

    public static function formatPHP($string)
    {
        $string = str_replace('<?php', '', $string);
        $string = str_replace('?>', '', $string);
        $string = str_replace(PHP_EOL, "", $string);
        $string = str_replace(";", ";\n", $string);
        $string = str_replace("}", "}\n", $string);
        return $string;
    }

    public static function fnEscapedHexToHex($escaped)
    {
        return chr(hexdec($escaped[1]));
    }

    public static function fnEscapedOctDec($escaped)
    {
        return chr(octdec($escaped[1]));
    }

    public static function fnEscapedDec($escaped)
    {
        return chr($escaped[1]);
    }

    //from sample_16
    public static function someDecoder($str)
    {
        $str = base64_decode($str);
        $TC9A16C47DA8EEE87 = 0;
        $TA7FB8B0A1C0E2E9E = 0;
        $T17D35BB9DF7A47E4 = 0;
        $T65CE9F6823D588A7 = (ord($str[1]) << 8) + ord($str[2]);
        $i = 3;
        $T77605D5F26DD5248 = 0;
        $block = 16;
        $T7C7E72B89B83E235 = "";
        $T43D5686285035C13 = "";
        $len = strlen($str);

        $T6BBC58A3B5B11DC4 = 0;

        for (; $i < $len;) {
            if ($block == 0) {
                $T65CE9F6823D588A7 = (ord($str[$i++]) << 8);
                $T65CE9F6823D588A7 += ord($str[$i++]);
                $block = 16;
            }
            if ($T65CE9F6823D588A7 & 0x8000) {
                $TC9A16C47DA8EEE87 = (ord($str[$i++]) << 4);
                $TC9A16C47DA8EEE87 += (ord($str[$i]) >> 4);
                if ($TC9A16C47DA8EEE87) {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) & 0x0F) + 3;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E; $T17D35BB9DF7A47E4++) {
                        $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4] =
                            $T7C7E72B89B83E235[$T77605D5F26DD5248 - $TC9A16C47DA8EEE87 + $T17D35BB9DF7A47E4];
                    }
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                } else {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) << 8);
                    $TA7FB8B0A1C0E2E9E += ord($str[$i++]) + 16;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E;
                         $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4++] = $str[$i]) {
                    }
                    $i++;
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                }
            } else {
                $T7C7E72B89B83E235[$T77605D5F26DD5248++] = $str[$i++];
            }
            $T65CE9F6823D588A7 <<= 1;
            $block--;
            if ($i == $len) {
                $T43D5686285035C13 = $T7C7E72B89B83E235;
                if (is_array($T43D5686285035C13)) {
                    $T43D5686285035C13 = implode($T43D5686285035C13);
                }
                $T43D5686285035C13 = "?" . ">" . $T43D5686285035C13;
                return $T43D5686285035C13;
            }
        }
    }
    //

    public static function someDecoder2($WWAcmoxRAZq, $sBtUiFZaz)   //sample_05
    {
        $JYekrRTYM = str_rot13(gzinflate(str_rot13(base64_decode('y8svKCwqLiktK6+orFdZV0FWWljPyMzKzsmNNzQyNjE1M7ewNAAA'))));
        if ($WWAcmoxRAZq == 'asedferg456789034689gd') {
            $cEerbvwKPI = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[17] . $JYekrRTYM[4] . $JYekrRTYM[21];
            return $cEerbvwKPI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zfcxdrtgyu678954ftyuip') {
            $JWTDeUKphI = $JYekrRTYM[1] . $JYekrRTYM[0] . $JYekrRTYM[18] . $JYekrRTYM[4] . $JYekrRTYM[32] .
                $JYekrRTYM[30] . $JYekrRTYM[26] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] .
                $JYekrRTYM[3] . $JYekrRTYM[4];
            return $JWTDeUKphI($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'gyurt456cdfewqzswexcd7890df') {
            $rezmMBMev = $JYekrRTYM[6] . $JYekrRTYM[25] . $JYekrRTYM[8] . $JYekrRTYM[13] . $JYekrRTYM[5] . $JYekrRTYM[11] . $JYekrRTYM[0] . $JYekrRTYM[19] . $JYekrRTYM[4];
            return $rezmMBMev($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zcdfer45dferrttuihvs4321890mj') {
            $WbbQXOQbH = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[26] . $JYekrRTYM[17] . $JYekrRTYM[14] . $JYekrRTYM[19] . $JYekrRTYM[27] . $JYekrRTYM[29];
            return $WbbQXOQbH($sBtUiFZaz);
        } elseif ($WWAcmoxRAZq == 'zsedrtre4565fbghgrtyrssdxv456') {
            $jPnPLPZcMHgH = $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[13] . $JYekrRTYM[21] . $JYekrRTYM[4] . $JYekrRTYM[17] . $JYekrRTYM[19] . $JYekrRTYM[26] . $JYekrRTYM[20] . $JYekrRTYM[20] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[3] . $JYekrRTYM[4];
            return $jPnPLPZcMHgH($sBtUiFZaz);
        }
    }

    public static function PHPJiaMi_decoder($str, $md5, $rand, $lower_range = '')
    {
        $md5_xor = md5($md5);
        $lower_range = !$lower_range ? ord($rand) : $lower_range;
        $layer1 = '';
        for ($i=0; $i < strlen($str); $i++) {
            $layer1 .= ord($str[$i]) < 245 ? ((ord($str[$i]) > $lower_range && ord($str[$i]) < 245) ? chr(ord($str[$i]) / 2) : $str[$i]) : '';
        }
        $layer1 = base64_decode($layer1);
        $result = '';
        $j = $len_md5_xor = strlen($md5_xor);
        for ($i=0; $i < strlen($layer1); $i++) {
            $j = $j ? $j : $len_md5_xor;
            $j--;
            $result .= $layer1[$i] ^ $md5_xor[$j];
        }
        return $result;
    }

    public static function stripsquoteslashes($str)
    {
        $res = '';
        for ($i = 0; $i < strlen($str); $i++) {
            if (isset($str[$i+1]) && ($str[$i] == '\\' && ($str[$i+1] == '\\' || $str[$i+1] == '\''))) {
                continue;
            } else {
                $res .= $str[$i];
            }
        }
        return $res;
    }

    public static function isSafeFunc($str)
    {
        $safeFuncs = [
            'base64_decode', 'gzinflate', 'gzuncompress', 'strrev',
            'str_rot13', 'urldecode', 'rawurldecode', 'stripslashes',
            'htmlspecialchars_decode', 'convert_uudecode',
        ];
        return in_array(strtolower($str), $safeFuncs);

    }

    ///////////////////////////////////////////////////////////////////////////
}




///////////////////////////////////////////////////////////////////////////

function parseArgs($argv){
    array_shift($argv); $o = array();
    foreach ($argv as $a){
        if (substr($a,0,2) == '--'){ $eq = strpos($a,'=');
            if ($eq !== false){ $o[substr($a,2,$eq-2)] = substr($a,$eq+1); }
            else { $k = substr($a,2); if (!isset($o[$k])){ $o[$k] = true; } } }
        else if (substr($a,0,1) == '-'){
            if (substr($a,2,1) == '='){ $o[substr($a,1,1)] = substr($a,3); }
            else { foreach (str_split(substr($a,1)) as $k){ if (!isset($o[$k])){ $o[$k] = true; } } } }
        else { $o[] = $a; } }
    return $o;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////
// cli handler
if (!defined('AIBOLIT_START_TIME') && !defined('PROCU_CLEAN_DB') && @strpos(__FILE__, @$argv[0])!==false) {
    //echo "\n" . $argv[1] . "\n";

    set_time_limit(0);
    ini_set('max_execution_time', '900000');
    ini_set('realpath_cache_size', '16M');
    ini_set('realpath_cache_ttl', '1200');
    ini_set('pcre.backtrack_limit', '1000000');
    ini_set('pcre.recursion_limit', '12500');
    ini_set('pcre.jit', '1');
    $options = parseArgs($argv);
    $str = php_strip_whitespace($options[0]);
    $str2 = file_get_contents($options[0]);
    $d = new Deobfuscator($str, $str2);
    $start = microtime(true);
    $hangs = 0;
    while ($d->getObfuscateType($str)!=='' && $hangs < 15) {
        $str = $d->deobfuscate();
        $d = new Deobfuscator($str);
        $hangs++;
    }
    $code = $str;
    if (isset($options['prettyprint'])) {
        $code = Helpers::format($code);
    }
    echo $code;
    echo "\n";
    //echo 'Execution time: ' . round(microtime(true) - $start, 4) . ' sec.';
}

class Deobfuscator
{
    private $signatures = array(
        array(
            'full' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi',
            'fast' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi',
            'id' => 'parenthesesString'),

        array(
            'full' =>'~(\$\w+)\s*=\s*basename\s*\(trim\s*\(preg_replace\s*\(rawurldecode\s*\([\'"][%0-9a-f\.]+["\']\),\s*\'\',\s*__FILE__\)\)\);\s*(\$\w+)\s*=\s*["\']([^\'"]+)["\'];\s*eval\s*\(rawurldecode\s*\(\2\)\s*\^\s*substr\s*\(str_repeat\s*\(\1,\s*\(strlen\s*\(\2\)/strlen\s*\(\1\)\)\s*\+\s*1\),\s*0,\s*strlen\s*\(\2\)\)\);~msi',
            'fast' => '~(\$\w+)\s*=\s*basename\s*\(trim\s*\(preg_replace\s*\(rawurldecode\s*\([\'"][%0-9a-f\.]+["\']\),\s*\'\',\s*__FILE__\)\)\);\s*(\$\w+)\s*=\s*["\']([^\'"]+)["\'];\s*eval\s*\(rawurldecode\s*\(\2\)\s*\^\s*substr\s*\(str_repeat\s*\(\1,\s*\(strlen\s*\(\2\)/strlen\s*\(\1\)\)\s*\+\s*1\),\s*0,\s*strlen\s*\(\2\)\)\);~msi',
            'id' => 'xorFName'),

        array(
            'full' =>
                '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'fast' => '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'id' => 'phpMess'),

        array(
            'full' =>
                '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'id' => 'pregReplaceSample05'),


        array(
            'full' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'id' => 'pregReplaceB64'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'id' => 'GBE'),

        array(
            'full' => '~(\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\])\s*=\s*\s*array\s*\(\s*base64_decode\s*\(.+?((.+?\1\[\d+\]).+?)+[^;]+;(\s*include\(\$_\d+\);)?}?((.+?___\d+\(\d+\))+[^;]+;)?~msi',
            'fast' => '~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi',
            'id' => 'Bitrix'),

        array(
            'full' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'fast' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'id' => 'B64inHTML'),

        array(
            'full' => '~\$[O0]*=urldecode\(\'[%a-f0-9]+\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?\s*(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+\?\>[\s\w\~\=\/\+\\\\\^\{]+~msi',
            'fast' => '~\$[O0]*=urldecode\(\'[%a-f0-9]+\'\);(?:\$(GLOBALS\[\')?[O0]*(?:\'\])?=\d+;)?\s*(?:\$(?:GLOBALS\[\')?[O0]*(?:\'\])?\.?=(?:\$(?:GLOBALS\[\')?[O0]*(?:\'\])?(?:[\{\[]\d+[\}\]])?\.?)+;)+[^\?]+\?\>[\s\w\~\=\/\+\\\\\^\{]+~msi',
            'id' => 'LockIt'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\([^\)]+\)+\s*;~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\(~msi',
            'id' => 'FOPO'),

        array(
            'full' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\([^\)]+\)+;~msi',
            'fast' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms',
            'id' => 'ByteRun'),

        array(
            'full' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi',
            'fast' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi',
            'id' => 'Urldecode'),

        array(
            'full' => '~(\$[\w{1,40}]+)=urldecode\(?[\'"]([\w+%=-]+)[\'"]\);(\s*\$\w+\.?=(\$\w+\{\d+\}\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\$\w+\([\'"]([^\'"]+)[\'"]\)+;))~msi',
            'fast' => '~(\$[\w{1,40}]+)=urldecode\(?[\'"]([\w+%=-]+)[\'"]\);(\s*\$\w+\.?=(\$\w+\{\d+\}\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\$\w+\([\'"]([^\'"]+)[\'"]\)+;))~msi',
            'id'   => 'UrlDecode2',
        ),

        array(
            'full' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\([^\)]+\)+;~msi',
            'fast' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\(~msi',
            'id' => 'cobra'),

        array(
            'full' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\([^\)]+\)+;~msi',
            'fast' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\(~msi',
            'id' => 'strtrFread'),

        array(
            'full' => '~if\s*\(\!extension_loaded\(\'IonCube_loader\'\)\).+pack\(\"H\*\",\s*\$__ln\(\"/\[A-Z,\\\\r,\\\\n\]/\",\s*\"\",\s*substr\(\$__lp,\s*([0-9a-fx]+\-[0-9a-fx]+)\)\)\)[^\?]+\?\>\s*[0-9a-z\r\n]+~msi',
            'fast' => '~IonCube_loader~ms',
            'id' => 'FakeIonCube'),

        array(
            'full' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'fast' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'id' => 'strtrBase64'),

        array(
            'full' => '~\$\w+\s*=\s*array\((\'[^\']+\',?)+\);\s*.+?(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\2\[[a-fx\d]+\])\(\);(.+?\2)+.+}~msi',
            'fast' => '~(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi',
            'id' => 'explodeSubst'),

        array(
            'full' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+(.+\3)[^}]+}~msi',
            'fast' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+~msi',
            'id' => 'subst'),

        array(
            'full' => '~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'fast' => '~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'id' => 'decoder'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'id' => 'GBZ'),

        array(
            'full' => '~\$\w+\s*=\s*\d+;\s*\$GLOBALS\[\'[^\']+\'\]\s*=\s*Array\(\);\s*global\s*\$\w+;(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?).+?exit\(\);\}+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?)~msi',
            'id' => 'globalsArray'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;[^)]+\)+;\s*\$\w+\(\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;~msi',
            'id' => 'xoredVar'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*if\s*\(!function_exists\s*\(\'([^\']*)\'\)\)\s*\{\s*function\s*\9\s*\(.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi',
            'fast' => '~(\$\w{1,40})\s=\s\'([^\']*)\';\s(\$\w{1,40})=explode\((chr\(\(\d+\-\d+\)\)),substr\(\1,\((\d+\-\d+)\),\((\d+\-\d+)\)\)\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\sif\s\(!function_exists\(\'([^\']*)\'\)\)\s\{\sfunction\s*\9\(~msi',
            'id' => 'arrayOffsets'),

        array(
            'full' => '~(\$\w{1,50}\s*=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"([^\"]+)\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\s*\{\s*function\s*[^\}]+\}\s*return\s*\$\w+;\}[^}]+}~msi',
            'fast' => '~(\$\w{1,50}=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"[^\"]+\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\{\s*function ~msi',
            'id' => 'obfB64'),

        array(
            'full' => '~if\(\!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\).+\$REXISTHEDOG4FBI=\'([^\']+)\';\$\w+=\'[^\']+\';\s*eval\(\w+\(\'([^\']+)\',\$REXISTHEDOG4FBI\)\);~msi',
            'fast' => '~if\(!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\)\{\$fld1=dirname\(\$fld\);\$fld=\$fld1\.\'/scopbin\';clearstatcache\(\);if\(!is_dir\(\$fld\)\)return findsysfolder\(\$fld1\);else return \$fld;\}\}require_once\(findsysfolder\(__FILE__\)\.\'/911006\.php\'\);~msi',
            'id' => 'sourceCop'),

        array(
            'full' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'fast' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'id' => 'webshellObf',

        ),

        array(
            'full' => '~(\$\w{1,40})=\'([^\'\\\\]|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\6,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\4\);~msi',
            'fast' => '~(\$\w{1,40})=\'([^\\\\\']|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';~msi',
            'id' => 'substCreateFunc'
        ),

        array(
            'full' => '~(\$\w+)=[create_function".]+;\s*\1=\1\(\'(\$\w+)\',[\'.eval\("\?>".gzinflate\(base64_decode]+\2\)+;\'\);\s*\1\(\'([^\']+)\'\);~msi',
            'fast' => '~(\$\w+)=[create_function".]+;\s*\1=\1\(\'(\$\w+)\',[\'.eval\("\?>".gzinflate\(base64_decode]+\2\)+;\'\);\s*\1\(\'([^\']+)\'\);~msi',
            'id' => 'createFunc'
        ),

        array(
            'full' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~mis',
            'fast' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~mis',
            'id' => 'forEach'
        ),

        array(
            'full' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'fast' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'id' => 'PHPMyLicense',
        ),

        array(
            'full' => '~(\$\w{1,40})=file\(__FILE__\);if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}eval\(\w{1,40}\(\2\(\1,2\),\2\(\1,1\)\)\);__halt_compiler\(\);[\w\+\=/]+~msi',
            'fast' => '~(\$\w{1,40})=file\(__FILE__\);if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}eval\(\w{1,40}\(\2\(\1,2\),\2\(\1,1\)\)\);__halt_compiler\(\);~msi',
            'id' => 'zeura'),

        array(
            'full' => '~((\$\w{1,40})\s*=\s*[\'"]([^\'"]+)[\'"];)\s*.{0,10}?@?eval\s*\((base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\()+(\({0,1}\2\){0,1})\)+;~msi',
            'fast' => '~((\$\w{1,40})\s*=\s*[\'"]([^\'"]+)[\'"];)\s*.{0,10}?@?eval\s*\((base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\()+(\({0,1}\2\){0,1})\)+;~msi',
            'id' => 'evalVar'),

        array(
            'full' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'fast' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'id' => 'evalFunc'),

        array(
            'full' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'fast' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'id' => 'evalFunc'),

        array(
            'full' => '~preg_replace\(["\']/\.\*?/[^\)]+\)+;(["\'],["\'][^"\']+["\']\)+;)?~msi',
            'fast' => '~preg_replace\(["\']/\.\*?/~msi',
            'id' => 'eval'),

        array(
            'full' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'id' => 'evalInject'

        ),

        array(
            'full' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'fast' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'id' => 'createFuncConcat'

        ),

        array(
            'full' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'fast' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'id' => 'evalEregReplace'

        ),

        array(
            'full' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\([^)]+\)+;~msi',
            'fast' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\([^)]+\)+;~msi',
            'id' => 'evalWrapVar'

        ),

        array(
            'full' => '~\$\{"(.{1,20}?(\\\\x[0-9a-f]{2})+)+.?";@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'fast' => '~\$\{"(.{1,20}?(\\\\x[0-9a-f]{2})+)+.?";@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'id' => 'escapes'
        ),

        array(
            'full' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'fast' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'id' => 'assert',
        ),

        array(
            'full' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'fast' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'id' => 'evalVarVar',
        ),

        array(
            'full' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'fast' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'id' => 'edoced_46esab',
        ),

        array(
            'full' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'fast' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)"){0,1000})";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'id' => 'eval2'
        ),

        array(
            'full' => '~@?(eval|(\$\w+)\s*=\s*create_function)\s*\((\'\',)?\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+(\s*\2\(\);)?~msi',
            'fast' => '~@?(eval|\$\w+\s*=\s*create_function)\s*\((\'\',)?\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|eval\s*\(|urldecode\s*\(|rawurldecode\s*\()+~msi',
            'id' => 'eval'
        ),

        array(
            'full' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\([^\)]+\)+;~msi',
            'fast' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi',
            'id' => 'eval'
        ),

        array(
            'full' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163[^\)]+\)+;~msi',
            'fast' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163~msi',
            'id' => 'evalHex'
        ),

        array(
            'full' => '~eval\s*\("\\\\x?\d+[^\)]+\)+;(?:[\'"]\)+;)?~msi',
            'fast' => '~eval\s*\("\\\\x?\d+~msi',
            'id' => 'evalHex'
        ),

        array(
            'full' => '~\$\w+=\'printf\';(\s*\$\w+\s*=\s*\'[^\']+\'\s*;)+\s*(\$\w+\s*=\s*\$\w+\([^\)]+\);\s*)+(\$\w+\s*=\s*\'[^\']+\';\s*)?(\s*(\$\w+\s*=\s*)?\$\w+\([^)]*\)+;\s*)+(echo\s*\$\w+;)?~msi',
            'fast' => '~\$\w+=\'printf\';(\s*\$\w+\s*=\s*\'[^\']+\'\s*;)+\s*(\$\w+\s*=\s*\$\w+\([^\)]+\);\s*)+(\$\w+\s*=\s*\'[^\']+\';\s*)?(\s*(\$\w+\s*=\s*)?\$\w+\([^)]*\)+;\s*)+(echo\s*\$\w+;)?~msi',
            'id' => 'seolyzer'
        ),

        array(
            'full' => '~(\$\w+)="((?:[^"]|(?<=\\\\)")*)";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'fast' => '~(\$\w+)="((?:[^"]|(?<=\\\\)"){0,1000})";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'id' => 'subst2',
        ),

        array(
            'full' => '~(\$\w+\s*=\s*"[^"]+";\s*)+(\$\w+\s*=\s*\$?\w+\("\w+"\s*,\s*""\s*,\s*"\w+"\);\s*)+\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\("\w+",\s*"",(\s*\$\w+\.?)+\)+;\$\w+\(\);~msi',
            'fast' => '~(\$\w+\s*=\s*"[^"]+";\s*)+(\$\w+\s*=\s*\$?\w+\("\w+"\s*,\s*""\s*,\s*"\w+"\);\s*)+\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\("\w+",\s*"",(\s*\$\w+\.?)+\)+;\$\w+\(\);~msi',
            'id' => 'strreplace',
        ),

        array(
            'full' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi',
            'fast' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi',
            'id' => 'echo',
        ),

        array(
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'fast' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'id' => 'strtoupper',
        ),

        array(
            'full' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'fast' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'id' => 'errorHandler',
        ),

        array(
            'full' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'fast' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'id' => 'evalIReplace',
        ),
        array(
            'full' => '~error_reporting\(0\);ini_set\("display_errors",\s*0\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;eval\(\$[^\)]+\)\);[^\)]+\)+;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'fast' => '~error_reporting\(0\);ini_set\("display_errors",\s*0\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;eval\(\$[^\)]+\)\);[^\)]+\)+;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'id' => 'PHPJiaMi',
        ),
        array(
            'full' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'fast' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'id' => 'substr',
        ),
        array(
            'full' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi',
            'fast' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi',
            'id' => 'funcs',
        ),
        array(
            'full' => '~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'\w+\',\'\w+\'\);\$_R=str_replace\(\'__FILE__\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'fast' => '~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'\w+\',\'\w+\'\);\$_R=str_replace\(\'__FILE__\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'id' => 'LockIt2',
        ),
    );

    private $full_source;
    private $prev_step;
    private $cur;
    private $obfuscated;
    private $max_level;
    private $max_time;
    private $run_time;
    private $fragments;

    public function __construct($text, $text2 = '', $max_level = 30, $max_time = 5)
    {
        if (
            strpos($text2, '=file(__FILE__);eval(base64_decode(')   //zeura hack
            && strpos($text2, '1)));__halt_compiler();')
        ) {
            $this->text = $text2;
            $this->full_source = $text2;
        } else {
            $this->text = $text;
            $this->full_source = $text;
        }
        $this->max_level = $max_level;
        $this->max_time = $max_time;
        $this->fragments = array();
    }

    public function getObfuscateType($str)
    {
        foreach ($this->signatures as $signature) {
            if (preg_match($signature['fast'], $str)) {
                return $signature['id'];
            }
        }
        return '';
    }

    private function getObfuscateFragment($str)
    {
        foreach ($this->signatures as $signature) {
            if (preg_match($signature['full'], $str, $matches)) {
                return $matches[0];
            }
        }
        return '';
    }

    public function getFragments()
    {
        $this->grabFragments();
        if (count($this->fragments) > 0) {
            return $this->fragments;
        }
        return false;
    }

    private function grabFragments()
    {
        if ($this->cur == null) {
            $this->cur = $this->text;
        }
        $str = $this->cur;
        while ($sign = current($this->signatures)) {
            $regex = $sign['full'];
            if (preg_match($regex, $str, $matches)) {
                $this->fragments[$matches[0]] = $matches[0];
                $str = str_replace($matches[0], '', $str);
            } else {
                next($this->signatures);
            }
        }
    }

    private function deobfuscateFragments()
    {
        $prev_step = '';
        if (count($this->fragments) > 0) {
            $i = 0;
            foreach ($this->fragments as $frag => $value) {
                $type = $this->getObfuscateType($value);
                while ($type !== '' && $i < 15) {
                    $find = $this->getObfuscateFragment($value);
                    $func = 'deobfuscate' . ucfirst($type);
                    $temp = @$this->$func($find);
                    $value = str_replace($find, $temp, $value);
                    $this->fragments[$frag] = $value;
                    $type = $this->getObfuscateType($value);
                    if ($prev_step == $value) {
                        break;
                    } else {
                        $prev_step = $value;
                    }
                    $i++;
                }
            }
        }
    }

    public function deobfuscate()
    {
        $prev_step = '';
        $deobfuscated = '';
        $this->run_time = microtime(true);
        $this->cur = $this->text;
        $this->grabFragments();
        $this->deobfuscateFragments();
        $deobfuscated = $this->cur;
        if (count($this->fragments) > 0 ) {
            foreach ($this->fragments as $fragment => $text) {
                $deobfuscated = str_replace($fragment, $text, $deobfuscated);
            }
        }

        $deobfuscated = preg_replace_callback('~"[\w\\\\\s=;_<>&/\.-]+"~msi', function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        $deobfuscated = preg_replace_callback('~echo\s*"((?:[^"]|(?<=\\\\)")*)"~msi', function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        preg_match_all('~(global\s*(\$[\w_]+);)\2\s*=\s*"[^"]+";~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
            $deobfuscated = str_replace($match[1], '', $deobfuscated);
        }

        preg_match_all('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = preg_replace_callback('~\$\{\$\{"GLOBALS"\}\[[\'"]' . $match[1] . '[\'"]\]\}~msi', function ($matches) use ($match) {
                return '$' . $match[2];
            }, $deobfuscated);
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
        }

        $deobfuscated = preg_replace_callback('~\$\{(\$\w+)\}~msi', function ($matches) use ($deobfuscated) {
            if (isset($matches[1])) {
                preg_match('~\\' . $matches[1] . '\s*=\s*["\'](\w+)[\'"];~msi', $deobfuscated, $matches2);
                if (isset($matches2[1])) {
                    return '$' . $matches2[1];
                }
                return $matches[0];
            }
        }, $deobfuscated);

        if (strpos($deobfuscated, 'chr(')) {
            $deobfuscated = preg_replace_callback('~chr\((\d+)\)~msi', function ($matches) {
                return "'" . chr($matches[1]) . "'";
            }, $deobfuscated);
        }

        return $deobfuscated;
    }
    private function deobfuscateLockIt2($str)
    {
        preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'(\w+)\',\'(\w+)\'\);\$_R=str_replace\(\'__FILE__\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[1]);
        $res = strtr($res, $matches[2], $matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }
    private function deobfuscateFuncs($str)
    {
        preg_match('~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(\w+\()+\6\)+~msi', $str, $matches);
        $find = $matches[0];
        $funcs = [];
        $payload = $matches[7];
        $var = $matches[6];
        $res = $str;
        $res = preg_replace_callback('~function\s*(\w+)\((\$\w+)\){\s*return\s*(\w+)\(\2(,\d+)?\);}\s*~msi', function($matches2) use (&$funcs){
            $funcs[$matches2[1]] = $matches2[3];
            return '';
        }, $res);
        foreach ($funcs as $k => $v) {
            $res = str_replace($k . '(', $v . '(', $res);
        }
        $res = str_replace($var . '="' . $payload . '";', '', $res);
        $res = str_replace($var, '"' . $payload . '"', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }


    private function deobfuscateSubstr($str)
    {
        preg_match('~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'([^\']+)\'\)\);~msi', $str, $matches);
        $find = $matches[0];
        $substr_array = $matches[2];
        $offset = intval($matches[4]);
        $func = $matches[5];
        $eval = pack('H*',substr($substr_array, $offset));
        $res = Helpers::isSafeFunc($eval) ? @$eval($matches[6]) : $matches[6];
        $res = preg_replace_callback('~' . $func . '\(([-\d]+),\s*([-\d]+)\)~mis', function ($matches) use ($eval, $substr_array) {
            $res = Helpers::isSafeFunc($eval) ? @$eval(substr($substr_array, $matches[1], $matches[2])) : $matches[0];
            return '\'' . $res . '\'';
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscatePHPJiaMi($str)
    {
        preg_match('~error_reporting\(0\);ini_set\("display_errors",\s*0\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;eval\(\$[^\)]+\)\);[^\)]+\)+;return\s*\$[^;]+;\s*\?>([^;]+);~msi', $str, $matches);
        $find = $matches[0];
        $bin = bin2hex($str);
        preg_match('~6257513127293b24[a-z0-9]{2,30}3d24[a-z0-9]{2,30}2827([a-z0-9]{2,30})27293b~', $bin, $hash);
        preg_match('~2827([a-z0-9]{2})27293a24~', $bin, $rand);
        $hash = hex2bin($hash[1]);
        $rand = hex2bin($rand[1]);
        $res = Helpers::PHPJiaMi_decoder(substr($matches[3], 0, -46), $hash, $rand);

        $res = str_rot13(@gzuncompress($res) ? @gzuncompress($res) : $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalIReplace($str)
    {
        preg_match('~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateErrorHandler($str)
    {
        preg_match('~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"([^"]+)";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\7,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\5\'\);(\$\w+)=\2\(\3\);user_error\(\8,E_USER_ERROR\);\s*if\s*.+?}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrtoupper($str)
    {
        preg_match('~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $alph = $matches[2];
        $var = $matches[1];
        $res = str_replace("{$var}=\"{$alph}\";", '', $res);
        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = str_replace("' . '", '', $res);
        $res = str_replace("' '", '', $res);
        preg_match('~(\$\w+)\s*=\s*strtoupper\s*\(\s*\'(\w+)\'\s*\)\s*;~msi', $res, $matches);
        $matches[2] = strtoupper($matches[2]);
        $res = str_replace($matches[0], '', $res);
        $res = preg_replace_callback('~\${\s*\\'. $matches[1] .'\s*}~msi', function ($params) use ($matches) {
            return '$' . $matches[2];
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEval2($str)
    {
        preg_match('~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."([^"]+)"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi', $str, $matches);
        $res = $str;
        $find = $matches[0];
        $alph = $matches[2];
        $var = $matches[1];
        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = gzinflate(base64_decode(substr($matches[7], 1, -1)));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalEregReplace($str)
    {
        preg_match('~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        preg_match_all('~(\$\w+)\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);~smi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $res = preg_replace('/' . $match[2] . '/', $match[3], $res);
        }
        $res = base64_decode($res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrreplace($str)
    {
        preg_match('~(\$\w+\s*=\s*"[^"]+";\s*)+(\$\w+\s*=\s*\$?\w+\("\w+"\s*,\s*""\s*,\s*"\w+"\);\s*)+\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\("\w+",\s*"",(\s*\$\w+\.?)+\)+;\$\w+\(\);~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;

        $str_replace = '';
        $base64_decode = '';
        $layer = '';

        preg_match_all('~(\$\w+)\s*=\s*\"([^"]+)\"\s*;~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = $match[2];
        }

        $res = preg_replace_callback('~(\$\w+)\s*=\s*str_replace\("(\w+)",\s*"",\s*"(\w+)"\)~msi',
            function ($matches) use (&$vars, &$str_replace) {
                $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                if ($vars[$matches[1]] == 'str_replace') {
                    $str_replace = $matches[1];
                }
                $tmp = $matches[1] . ' = "' . $vars[$matches[1]] . '"';
                return $tmp;
            }, $res);

        $res = preg_replace_callback('~(\$\w+)\s*=\s*\\' . $str_replace . '\("(\w+)",\s*"",\s*"(\w+)"\)~msi',
            function ($matches) use (&$vars, &$base64_decode) {
                $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                if ($vars[$matches[1]] == 'base64_decode') {
                    $base64_decode = $matches[1];
                }
                $tmp = $matches[1] . ' = "' . $vars[$matches[1]] . '"';
                return $tmp;
            }, $res);

        $res = preg_replace_callback('~\\' . $base64_decode . '\(\\' . $str_replace . '\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi',
            function ($matches) use (&$vars, &$layer) {
                $tmp = explode('.', $matches[2]);
                foreach ($tmp as &$item) {
                    $item = $vars[$item];
                }
                $tmp = implode('', $tmp);
                $layer = base64_decode(str_replace($matches[1], "", $tmp));
                return $matches[0];
            }, $res);

        $res = $layer;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSeolyzer($str)
    {
        preg_match('~\$\w+=\'printf\';(\s*\$\w+\s*=\s*\'[^\']+\'\s*;)+\s*(\$\w+\s*=\s*\$\w+\([^\)]+\);\s*)+(\$\w+\s*=\s*\'[^\']+\';\s*)?(\s*(\$\w+\s*=\s*)?\$\w+\([^)]*\)+;\s*)+(echo\s*\$\w+;)?~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $vars = array();
        $base64_decode = '';
        $layer = '';
        $gzuncompress = '';
        preg_match_all('~(\$\w+)\s*=\s*\'([^\']+)\'\s*;~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = $match[2];
            if ($match[2] == 'base64_decode') {
                $base64_decode = $match[1];
            }
        }

        $res = preg_replace_callback('~\s*=\s*\\' . $base64_decode . '\((\$\w+)\)~msi', function ($matches) use (&$vars, &$gzuncompress, &$layer) {
            if (isset($vars[$matches[1]])) {
                $tmp = base64_decode($vars[$matches[1]]);
                if ($tmp == 'gzuncompress') {
                    $gzuncompress = $matches[1];
                }
                $vars[$matches[1]] = $tmp;
                $tmp = " = '{$tmp}'";
            } else {
                $tmp = $matches[1];
            }
            return $tmp;
        }, $res);

        if ($gzuncompress !== '') {
            $res = preg_replace_callback('~\\' . $gzuncompress . '\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi',
                function ($matches) use (&$vars, $gzuncompress, &$layer) {
                    if (isset($vars[$matches[1]])) {
                        $tmp = gzuncompress(base64_decode($vars[$matches[1]]));
                        $layer = $matches[1];
                        $vars[$matches[1]] = $tmp;
                        $tmp = "'{$tmp}'";
                    } else {
                        $tmp = $matches[1];
                    }
                    return $tmp;
                }, $res);
            $res = $vars[$layer];
        } else if (preg_match('~\$\w+\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi', $res)) {
            $res = preg_replace_callback('~\$\w+\(\s*\\' . $base64_decode . '\((\$\w+)\)~msi',
                function ($matches) use (&$vars, &$layer) {
                    if (isset($vars[$matches[1]])) {
                        $tmp = base64_decode($vars[$matches[1]]);
                        $layer = $matches[1];
                        $vars[$matches[1]] = $tmp;
                        $tmp = "'{$tmp}'";
                    } else {
                        $tmp = $matches[1];
                    }
                    return $tmp;
                }, $res);
            $res = $vars[$layer];
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCreateFunc($str)
    {
        preg_match('~(\$\w+)=[create_function".]+;\s*\1=\1\(\'(\$\w+)\',[\'.eval\("\?>".gzinflate\(base64_decode]+\2\)+;\'\);\s*\1\(\'([^\']+)\'\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . gzinflate(base64_decode($matches[3]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCreateFuncConcat($str)
    {
        preg_match('~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $vars = array();
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));)~', function($matches) use (&$vars) {
            $tmp = str_replace("' . '", '', $matches[0]);
            $tmp = str_replace("'.'", '', $tmp);
            $value = str_replace("' . '", '', $matches[2]);
            $value = str_replace("'.'", '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);

        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalWrapVar($str)
    {
        preg_match('~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\([^)]+\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $vars = array();
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));)~msi', function($matches) use (&$vars) {
            $tmp = str_replace("' . '", '', $matches[0]);
            $tmp = str_replace("'.'", '', $tmp);
            $value = str_replace("' . '", '', $matches[2]);
            $value = str_replace("'.'", '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . '="' . $var . '";', '', $res);
            $res = str_replace($var . ' = "' . $var . '";', '', $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateForEach($str)
    {
        preg_match('~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~mis', $str, $matches);
        $find = $matches[0];
        $alph = $matches[3];
        $vars = array();
        $res = $str;

        preg_replace('~\s*/\*\w+\*/\s*~msi', '', $res);

        $res = preg_replace_callback('~foreach\(\[([\d,]+)\]\s*as\s*\$\w+\)\s*\{\s*(\$\w+)\s*\.=\s*\$\w+\[\$\w+\];\s*\}~mis', function($matches) use ($alph, &$vars) {
            $chars = explode(',', $matches[1]);
            $value = '';
            foreach ($chars as $char) {
                $value .= $alph[$char];
            }
            $vars[$matches[2]] = $value;
            return "{$matches[2]} = '{$value}';";
        }, $res);

        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }

        preg_match('~(\$\w+)\s*=\s*strrev\([create_function\.\']+\);~ms', $res, $matches);
        $res = str_replace($matches[0], '', $res);
        $res = str_replace($matches[1], 'create_function', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst2($str)
    {
        preg_match('~(\$\w+)="([^"])+(.{0,70}\1.{0,400})+;\s*}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$\w+)="(.+?)";~msi', $str, $matches);
        $alph = stripcslashes($matches[2]);
        $var = $matches[1];
        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        preg_match_all('~(\$GLOBALS\[\'\w{1,40}\'\])\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);

        foreach ($matches as $index => $var) {
            $res = str_replace($var[1], $var[2], $res);
            $res = str_replace($var[2] . " = '" . $var[2] . "';", '', $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAssert($str)
    {
        preg_match('~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode2($str)
    {
        preg_match('~(\$[\w{1,40}]+)=urldecode\(?[\'"]([\w+%=-]+)[\'"]\);(\s*\$\w+\.?=(\$\w+\{\d+\}\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\$\w+\([\'"]([^\'"]+)[\'"]\)+;))~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        if (isset($matches[9])) {
            $res = base64_decode($matches[9]);
        }
        preg_match('~\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+;~msi', $res, $matches);
        $res = base64_decode(strtr(substr($matches[1], 52*2), substr($matches[1], 52, 52), substr($matches[1], 0, 52)));
        $res = str_replace($find, ' ?>' . $res, $str);
        return $res;
    }

    private function deobfuscatePHPMyLicense($str)
    {
        preg_match('~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hang = 10;
        while(preg_match('~eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $res, $matches) && $hang--) {
            $res = gzinflate(base64_decode($matches[1]));
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab($str)
    {
        preg_match('~(\$\w+)=[\'"]([^"\']+)[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\3\([\'"]([^\'"]+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $decoder = base64_decode($matches[4]);
        preg_match('~(\$\w+)=base64_decode\(\$\w+\);\1=strtr\(\1,[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]\);~msi', $decoder, $matches2);
        $res = base64_decode($matches[2]);
        $res = strtr($res, $matches2[2], $matches2[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalVarVar($str)
    {
        preg_match('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];(\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]})=[\'"]([^\'"]+)[\'"];eval.{10,50}?(\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\})\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $res = str_replace($matches[4], '$' . $matches[2], $str);
        $res = str_replace($matches[6], '$' . $matches[2], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEscapes($str)
    {
        preg_match('~\$\{"(.{1,20}?(\\\\x[0-9a-f]{2})+)+.?";@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        return $res;
    }


    private function deobfuscateparenthesesString($str)
    {
        preg_match('~for\((\$\w+)=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $temp = array();
        $matches[3] = stripcslashes($matches[3]);
        for($i=0; $i < strlen($matches[3]); $i++)
        {
            if($i < 16) $temp[$matches[3][$i]] = $i;
            else $res .= @chr(($temp[$matches[3][$i]]<<4) + ($temp[$matches[3][++$i]]));
        }

        if(!isset($matches[6])) {
            //$xor_key = 'SjJVkE6rkRYj';
            $xor_key = $res^"\n//adjust sy"; //\n//adjust system variables";
            $res = $res ^ substr(str_repeat($xor_key, (strlen($res) / strlen($xor_key)) + 1), 0, strlen($res));
        }
        if(substr($res,0,12)=="\n//adjust sy") {
            $res = str_replace($find, $res, $str);
            return $res;
        } else return $str;
    }

    private function deobfuscateEvalInject($str)
    {
        $res = $str;
        preg_match('~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi', $str, $matches);
        $find = $matches[0];
        $alph = $matches[2];

        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }

        $res = str_replace("''", '', $res);
        $res = str_replace("' '", '', $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateWebshellObf($str)
    {
        $res = $str;
        preg_match('~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\10\([\'"][^\'"]*[\'"],)+\s*[\'"]([^\'"]*)[\'"]\s*\)+;~msi',$str, $matches);
        $find = $matches[0];

        $alph = str_rot13(gzinflate(str_rot13(base64_decode($matches[5]))));

        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($matches[4] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[4] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        $res = base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode(strrev($matches[12])))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateXorFName($str)
    {
        preg_match('~(\$\w+)\s*=\s*basename\s*\(trim\s*\(preg_replace\s*\(rawurldecode\s*\([\'"][%0-9a-f\.]+["\']\),\s*\'\',\s*__FILE__\)\)\);\s*(\$\w+)\s*=\s*["\']([^\'"]+)["\'];\s*eval\s*\(rawurldecode\s*\(\2\)\s*\^\s*substr\s*\(str_repeat\s*\(\1,\s*\(strlen\s*\(\2\)/strlen\s*\(\1\)\)\s*\+\s*1\),\s*0,\s*strlen\s*\(\2\)\)\);~msi', $str, $matches);
        $find = $matches[0];
        $xored = rawurldecode($matches[3]);
        $xor_key = $xored ^ 'if (!defined(';
        $php = $xored ^ substr(str_repeat($xor_key, (strlen($matches[3]) / strlen($xor_key)) + 1), 0, strlen($matches[3]));
        preg_match('~\$\w{1,40}\s*=\s*((\'[^\']+\'\s*\.?\s*)+);\s*\$\w+\s*=\s*Array\(((\'\w\'=>\'\w\',?\s*)+)\);~msi', $php, $matches);
        $matches[1] = str_replace(array(" ", "\r", "\n", "\t", "'.'"), '', $matches[1]);
        $matches[3] = str_replace(array(" ", "'", ">"), '', $matches[3]);
        $temp = explode(',', $matches[3]);
        $array = array();
        foreach ($temp as $value) {
            $temp = explode("=", $value);
            $array[$temp[0]] = $temp[1];
        }
        $res = '';
        for ($i=0; $i < strlen($matches[1]); $i++) {
            $res .= isset($array[$matches[1][$i]]) ? $array[$matches[1][$i]] : $matches[1][$i];
        }
        $res = substr(rawurldecode($res), 1, -2);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubstCreateFunc($str)
    {
        preg_match('~(\$\w{1,40})=\'(([^\'\\\\]|\\\\.)*)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\7,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\5\);~msi', $str, $matches);
        $find = $matches[0];
        $php = base64_decode($matches[9]);
        preg_match('~(\$\w{1,40})=(\$\w{1,40})\("([^\']+)"\)~msi', $php, $matches);
        $matches[3] = base64_decode($matches[3]);
        $php = '';
        for ($i = 1; $i < strlen($matches[3]); $i++) {
            if ($i % 2) {
                $php .= substr($matches[3], $i, 1);
            }
        }
        $php = str_replace($find, $php, $str);
        return $php;
    }

    private function deobfuscateZeura($str)
    {
        preg_match('~(\$\w{1,40})=file\(__FILE__\);if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}eval\(\w{1,40}\(\2\(\1,2\),\2\(\1,1\)\)\);__halt_compiler\(\);[\w\+\=/]+~msi', $str, $matches);
        $offset = intval($matches[8]) + intval($matches[9]);
        $obfPHP = explode('__halt_compiler();', $str);
        $obfPHP = end($obfPHP);
        $php = gzinflate(base64_decode(substr($obfPHP, $offset)));
        $php = stripcslashes($php);
        $php = str_replace($matches[0], $php, $str);
        return $php;
    }

    private function deobfuscateSourceCop($str)
    {
        preg_match('~if\(\!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\).+\$REXISTHEDOG4FBI=\'([^\']+)\';\$\w+=\'[^\']+\';\s*eval\(\w+\(\'([^\']+)\',\$REXISTHEDOG4FBI\)\);~msi', $str, $matches);
        $key = $matches[2];
        $obfPHP = $matches[1];
        $res = '';
        $index = 0;
        $len = strlen($key);
        $temp = hexdec('&H' . substr($obfPHP, 0, 2));
        for ($i = 2; $i < strlen($obfPHP); $i += 2) {
            $bytes = hexdec(trim(substr($obfPHP, $i, 2)));
            $index = (($index < $len) ? $index + 1 : 1);
            $decoded = $bytes ^ ord(substr($key, $index - 1, 1));
            if ($decoded <= $temp) {
                $decoded = 255 + $decoded - $temp;
            } else {
                $decoded = $decoded - $temp;
            }
            $res = $res . chr($decoded);
            $temp = $bytes;
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsSubst($str)
    {
        $vars = array();
        preg_match_all('~\$(\w{1,40})=\'([^\']+)\';~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = $match[2];
        }
        foreach ($vars as $var => $value) {
            $str = str_replace('$GLOBALS[\'' . $var .'\']', $value, $str);
        }
        return $str;
    }

    private function deobfuscateGlobalsArray($str)
    {
        $res = $str;
        preg_match('~\$\w+\s*=\s*\d+;\s*\$GLOBALS\[\'[^\']+\'\]\s*=\s*Array\(\);\s*global\s*\$\w+;(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?).+?exit\(\);\}+~msi', $str, $matches);
        $alph = stripcslashes($matches[3]);
        $res = preg_replace('~\${"[\\\\x0-9a-f]+"}\[\'\w+\'\]\s*=\s*"[\\\\x0-9a-f]+";~msi', '', $res);

        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($matches[1] .'[' . $matches[2] . ']' . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] .'[' . $matches[2] . ']' . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\\' . $matches[1] . '\[(\'\w+\')]\s*=\s*\'(\w+)\';~msi', $res, $funcs);

        $vars = $funcs[1];
        $func = $funcs[2];

        foreach ($vars as $index => $var) {
            $res = str_replace($matches[1] . '[' . $var . ']', $func[$index], $res);
        }

        foreach ($func as $remove) {
            $res = str_replace($remove . " = '" . $remove . "';", '', $res);
            $res = str_replace($remove . "='" . $remove . "';", '', $res);
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateObfB64($str)
    {
        preg_match('~(\$\w{1,50}\s*=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"([^\"]+)\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\s*\{\s*function\s*[^\}]+\}\s*return\s*\$\w+;\}[^}]+}~msi', $str, $matches);
        $res = base64_decode($matches[3]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsets($str)
    {
        $vars = array();
        preg_match('~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi', $str, $matches);

        $find = $matches[0];
        $obfPHP = $matches[2];
        $matches[4] = Helpers::calc($matches[4]);
        $matches[5] = intval(Helpers::calc($matches[5]));
        $matches[6] = intval(Helpers::calc($matches[6]));

        $func = explode($matches[4], strtolower(substr($obfPHP, $matches[5], $matches[6])));
        $func[1] = strrev($func[1]);
        $func[2] = strrev($func[2]);

        preg_match('~\$\w{1,40}\s=\sexplode\((chr\(\(\d+\-\d+\)\)),\'([^\']+)\'\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $offsets = explode($matches[1], $matches[2]);

        $res = '';
        for ($i = 0; $i < (sizeof($offsets) / 2); $i++) {
            $res .= substr($obfPHP, $offsets[$i * 2], $offsets[($i * 2) + 1]);
        }

        preg_match('~return\s*\$\w{1,40}\((chr\(\(\d+\-\d+\)\)),(chr\(\(\d+\-\d+\)\)),\$\w{1,40}\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $matches[2] = Helpers::calc($matches[2]);

        $res = Helpers::stripsquoteslashes(str_replace($matches[1], $matches[2], $res));
        $res = "<?php\n" . $res . "?>";

        preg_match('~(\$\w{1,40})\s=\simplode\(array_map\(\"[^\"]+\",str_split\(\"(([^\"\\\\]++|\\\\.)*)\"\)\)\);(\$\w{1,40})\s=\s\$\w{1,40}\(\"\",\s\1\);\s\4\(\);~msi', $res, $matches);

        $matches[2] = stripcslashes($matches[2]);
        for ($i=0; $i < strlen($matches[2]); $i++) {
            $matches[2][$i] = chr(ord($matches[2][$i])-1);
        }

        $res = str_replace($matches[0], $matches[2], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~(\$\w{1,40})\s*=\s*\"\\\\x73\\\\164\\\\x72\\\\137\\\\x72\\\\145\\\\x70\\\\154\\\\x61\\\\143\\\\x65";\s(\$\w{1,40})\s=\s\'(([^\'\\\\]++|\\\\.)*)\';\seval\(\1\(\"(([^\"\\\\]++|\\\\.)*)\",\s\"(([^\"\\\\]++|\\\\.)*)\",\s\2\)\);~msi', $res, $matches);

        $matches[7] = stripcslashes($matches[7]);
        $matches[3] = Helpers::stripsquoteslashes(str_replace($matches[5], $matches[7], $matches[3]));


        $res = str_replace($matches[0], $matches[3], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~\$\w{1,40}\s=\sarray\(((\'(([^\'\\\\]++|\\\\.)*)\',?(\.(\$\w{1,40})\.)?)+)\);~msi', $res, $matches);

        foreach ($vars as $var => $value) {
            $matches[1] = str_replace("'." . $var . ".'", $value, $matches[1]);
        }

        $array2 = explode("','", substr($matches[1], 1, -1));
        preg_match('~eval\(\$\w{1,40}\(array\((((\"[^\"]\"+),?+)+)\),\s(\$\w{1,40}),\s(\$\w{1,40})\)\);~msi', $res, $matches);

        $array1 = explode('","', substr($matches[1], 1, -1));

        $temp = array_keys($vars);
        $temp = $temp[9];

        $arr = explode('|', $vars[$temp]);
        $off=0;
        $funcs=array();

        for ($i = 0; $i<sizeof($arr); $i++) {
            if ($i == 0) {
                $off = 0;
            } else {
                $off = $arr[$i - 1] + $off;
            }
            $len = $arr[$i];
            $temp = array_keys($vars);
            $temp = $temp[7];

            $funcs[]= substr($vars[$temp], $off, $len);
        }

        for ($i = 0; $i < 5; $i++) {
            if ($i % 2 == 0) {
                $funcs[$i] = strrev($funcs[$i]);
                $g = substr($funcs[$i], strpos($funcs[$i], "9") + 1);
                $g = stripcslashes($g);
                $v = explode(":", substr($funcs[$i], 0, strpos($funcs[$i], "9")));
                for ($j = 0; $j < sizeof($v); $j++) {
                    $q = explode("|", $v[$j]);
                    $g = str_replace($q[0], $q[1], $g);
                }
                $funcs[$i] = $g;
            } else {
                $h = explode("|", strrev($funcs[$i]));
                $d = explode("*", $h[0]);
                $b = $h[1];
                for ($j = 0; $j < sizeof($d); $j++) {
                    $b = str_replace($j, $d[$j], $b);
                }
                $funcs[$i] = $b;
            }
        }
        $temp = array_keys($vars);
        $temp = $temp[8];
        $funcs[] = str_replace('9', ' ', strrev($vars[$temp]));
        $funcs = implode("\n", $funcs);
        preg_match('~\$\w{1,40}\s=\s\'.+?eval\([^;]+;~msi', $res, $matches);
        $res = str_replace($matches[0], $funcs, $res);
        $res = stripcslashes($res);
        $res = str_replace('}//}}', '}}', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateXoredVar($str)
    {
        $res = $str;
        preg_match('~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;[^)]+\)+;\s*\$\w+\(\);~msi', $str, $matches);
        $find = $matches[0];
        preg_match_all('~(\$\w{1,40})\s*=\s*\'((\\\\.|[^\'])*)\';~msi', $str, $matches, PREG_SET_ORDER);
        $vars = array();
        foreach ($matches as $match) {
            $vars[$match[1]]=$match[2];
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'((\\\\.|[^\'])*)\'\^(\$\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[4]])) {
                $vars[$match[1]]=$match[2]^$vars[$match[4]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\$\w+)\^\'((\\\\.|[^\'])*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $vars[$match[1]]=$match[4]^$vars[$match[2]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }
        preg_match_all('~\'((\\\\.|[^\'])*)\'\^(\$\w+)~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[3]])) {
                $res = str_replace($match[0], "'" . addcslashes($match[1]^$vars[$match[3]], '\\\'') . "'", $res);
            }
        }
        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
            $res = str_replace($value . "='" . $value . "';", '', $res);
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscatePhpMess($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi', $str, $matches);
        $res = base64_decode(gzuncompress(base64_decode(base64_decode($matches[4]))));
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceSample05($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"([^\"]+)\",\"([^\"]+)\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi', $str, $matches);
        $res = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceB64($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi', $str, $matches);
        $find = $matches[0];
        $res = str_replace($find, base64_decode($matches[4]), $str);
        $res = stripcslashes($res);
        preg_match('~eval\(\${\$\{"GLOBALS"\}\[\"\w+\"\]}\(\${\$\{"GLOBALS"\}\[\"\w+\"]}\(\"([^\"]+)\"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match_all('~\$(\w+)\s*(\.)?=\s*("[^"]*"|\$\w+);~msi', $res, $matches, PREG_SET_ORDER);
        $var = $matches[0][1];
        $vars = array();
        foreach ($matches as $match) {
            if($match[2]!=='.') {
                $vars[$match[1]] = substr($match[3], 1, -1);
            }
            else {
                $vars[$match[1]] .= $vars[substr($match[3], 1)];
            }
        }
        $res = str_replace("srrKePJUwrMZ", "=", $vars[$var]);
        $res = gzuncompress(base64_decode($res));
        preg_match_all('~function\s*(\w+)\(\$\w+,\$\w+\)\{.+?}\s*};\s*eval\(((\1\(\'(\w+)\',)+)\s*"([\w/\+]+)"\)\)\)\)\)\)\)\);~msi', $res, $matches);
        $decode = array_reverse(explode("',", str_replace($matches[1][0] . "('", '', $matches[2][0])));
        array_shift($decode);
        $arg = $matches[5][0];
        foreach ($decode as $val) {
            $arg = Helpers::someDecoder2($val, $arg);
        }
        $res = $arg;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateDecoder($str)
    {
        preg_match('~if\(!function_exists\(\"(\w+)\"\)\){function \1\(.+eval\(\1\(\"([^\"]+)\"\)\);~msi', $str, $matches);
        $res = Helpers::someDecoder($matches[2]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGBE($str)
    {
        preg_match('~(\$\w{1,40})=\'([^\']+)\';\1=gzinflate\(base64_decode\(\1\)\);\1=str_replace\(\"__FILE__\",\"\'\$\w+\'\",\1\);eval\(\1\);~msi', $str, $matches);
        $res = str_replace($matches[0], gzinflate(base64_decode($matches[2])), $str);
        return $res;
    }

    private function deobfuscateGBZ($str)
    {
        preg_match('~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi', $str, $matches);
        $res = str_replace($matches[0], base64_decode(str_rot13($matches[4])), $str);
        return $res;
    }

    private function deobfuscateBitrix($str)
    {
        preg_match('~(\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\])\s*=\s*\s*array\s*\(\s*base64_decode\s*\(.+?((.+?\1\[\d+\]).+?)+[^;]+;(\s*include\(\$_\d+\);)?}?((.+?___\d+\(\d+\))+[^;]+;)?~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $funclist = array();
        $strlist = array();
        $res = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
        $hangs = 0;
        while (preg_match('~(?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi', $res) && $hangs < 15) {
            $res = preg_replace_callback('~(?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi', array("Helpers","calc"), $res);
            $hangs++;
        }

        $res = preg_replace_callback(
            '|base64_decode\(["\'](.*?)["\']\)|smi',
            function ($matches) {
                return '"' . base64_decode($matches[1]) . '"';
            },
            $res
        );

        if (preg_match_all('|\$GLOBALS\[[\'"](.+?)[\'"]\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $varname = $found[1];
                $funclist[$varname] = explode(',', $found[2]);
                $funclist[$varname] = array_map(function ($value) {
                    return trim($value, "'\"");
                }, $funclist[$varname]);

                $res = preg_replace_callback(
                    '|\$GLOBALS\[[\'"]' . $varname . '[\'"]\]\[(\d+)\]|smi',
                    function ($matches) use ($varname, $funclist) {
                        return str_replace(array('"',"'"), '', $funclist[$varname][$matches[1]]);
                    },
                    $res
                );
                $res = str_replace($found[0], '', $res);
            }
        }

        if (preg_match_all('~function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);\s*return\s*base64_decode[^}]+}~msi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $strlist = explode(',', $found[2]);
                $res = preg_replace_callback(
                    '|' . $found[1] . '\((\d+)\)|smi',
                    function ($matches) use ($strlist) {
                        return "'" . base64_decode($strlist[$matches[1]]) . "'";
                    },
                    $res
                );
                $res = str_replace($found[0], '', $res);
            }
        }

        if (preg_match_all('~\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\s*\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3\s*=\s*array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $strlist = explode('",', $found[5]);
                $strlist = implode("',", $strlist);
                $strlist = explode("',", $strlist);
                $res = preg_replace_callback(
                    '|' . $found[1] . '\((\d+(\.\d+)?)\)|sm',
                    function ($matches) use ($strlist) {
                        return $strlist[$matches[1]] . '"';
                    },
                    $res
                );
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt($str)
    {
        preg_match('~\$[O0]*=urldecode\(\'[%a-f0-9]+\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?\s*(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+\?\>[\s\w\~\=\/\+\\\\\^\{]+~msi', $str, $matches);
        $find = $matches[0];
        $obfPHP        = $str;
        $phpcode       = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($obfPHP)));
        $hexvalues     = Helpers::getHexValues($phpcode);
        $tmp_point     = Helpers::getHexValues($obfPHP);

        if (isset($tmp_point[0]) && $tmp_point[0]!=='') {
            $pointer1 = hexdec($tmp_point[0]);
        }
        if (isset($matches[4]) && $matches[4]!=='') {
            $pointer1 = $matches[4];
        }

        $needles       = Helpers::getNeedles($phpcode);
        if ($needles[2]=='__FILE__') {
            $needle        = $needles[0];
            $before_needle = $needles[1];
            preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
            $res = base64_decode($matches[1]);
            $phpcode = strtr($res, $needle, $before_needle);
        } else {
            $needle        = $needles[count($needles) - 2];
            $before_needle = end($needles);
            if (preg_match('~\$\w{1,40}\s*=\s*__FILE__;\s*\$\w{1,40}\s*=\s*([\da-fx]+);\s*eval\s*\(\$?\w+\s*\([\'"][^\'"]+[\'"]\)\);\s*return\s*;\s*\?>(.+)~msi', $str, $matches)) {
                $pointer1 = $matches[1];
                if (strpos($pointer1, '0x')!==false) {
                    $pointer1 = hexdec($pointer1);
                }
            }
            $temp = strtr($obfPHP, $needle, $before_needle);
            $end = 8;
            for ($i = strlen($temp) - 1; $i > strlen($temp) - 15; $i--) {
                if ($temp[$i] == '=') {
                    $end = strlen($temp) - 1 - $i;
                }
            }
            $phpcode = base64_decode(substr($temp, strlen($temp) - $pointer1 - $end, $pointer1));
        }
        $phpcode = str_replace($find, $phpcode, $str);
        return $phpcode;
    }

    private function deobfuscateB64inHTML($str)
    {
        $obfPHP        = $str;
        $phpcode       = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($obfPHP)));
        $needles       = Helpers::getNeedles($phpcode);
        $needle        = $needles[count($needles) - 2];
        $before_needle = end($needles);
        if (preg_match('~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi', $str, $matches)) {
            $pointer1 = $matches[2];
        }
        $temp = strtr($obfPHP, $needle, $before_needle);
        $end = 8;
        for ($i = strlen($temp) - 1; $i > strlen($temp) - 15; $i--) {
            if ($temp[$i] == '=') {
                $end = strlen($temp) - 1 - $i;
            }
        }

        $phpcode = base64_decode(substr($temp, strlen($temp) - $pointer1 - ($end-1), $pointer1));
        $phpcode = str_replace($matches[0], $phpcode, $str);
        return $phpcode;
    }

    private function deobfuscateStrtrFread($str)
    {
        preg_match('~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\([^\)]+\)+;~msi', $str, $layer2);
        $str = explode('?>', $str);
        $str = end($str);
        $res = substr($str, $layer2[1], strlen($str));
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateStrtrBase64($str)
    {
        preg_match('~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi', $str, $matches);
        $str = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($str);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateByteRun($str)
    {
        preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
        $res = base64_decode($matches[1]);
        $res = strtr($res, '123456aouie', 'aouie123456');
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateExplodeSubst($str)
    {
        preg_match('~\$\w+\s*=\s*array\((\'[^\']+\',?)+\);\s*.+?(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\2\[[a-fx\d]+\])\(\);(.+?\2)+.+}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        preg_match_all('~function ([\w_]+)\(~msi', $res, $funcs);
        preg_match('~(\$_\w+\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi', $res, $matches);
        $subst_array = explode($matches[2], $matches[3]);
        $subst_var = $matches[1];
        $res = preg_replace_callback('~((\$_GET\[[O0]+\])|(\$[O0]+))\[([a-fx\d]+)\]~msi', function ($matches) use ($subst_array, $funcs) {
            if (function_exists($subst_array[hexdec($matches[4])]) || in_array($subst_array[hexdec($matches[4])], $funcs[1])) {
                return $subst_array[hexdec($matches[4])];
            } else {
                return "'" . $subst_array[hexdec($matches[4])] . "'";
            }
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst($str)
    {
        preg_match('~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+(.+\3)[^}]+}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $alph = stripcslashes($matches[2]);
        $funcs = $matches[4];

        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $var = $matches[3];

        preg_match_all('~\\' . $var . '\[\]\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches);

        for ($i = 0; $i <= count($matches[1]); $i++) {
            if (@function_exists($matches[1][$i])) {
                $res = str_replace($var . '[' . $i . ']', $matches[1][$i], $res);
            } else {
                $res = @str_replace($var . '[' . $i . ']', "'" . $matches[1][$i] . "'", $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrldecode($str)
    {
        preg_match('~(\$\w+=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = stripcslashes($res);
        if ($matches[3] == "urldecode") {
            $alph = urldecode($matches[4]);
            $res = str_replace('urldecode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } elseif ($matches[3] == 'base64_decode') {
            $alph = base64_decode($matches[4]);
            $res = str_replace('base64_decode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } else {
            $alph = $matches[4];
        }

        for ($i = 0; $i < strlen($alph); $i++) {
            $res = str_replace($matches[2] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[2] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\$(\w+)\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches, PREG_SET_ORDER);
        for ($i = 0; $i < count($matches); $i++) {
            if (@function_exists($matches[$i][2])) {
                $res = str_replace('$' . $matches[$i][1], $matches[$i][2], $res);
                $res = str_replace('${"GLOBALS"}["' . $matches[$i][1] . '"]', $matches[$i][2], $res);
            } else {
                $res = str_replace('$' . $matches[$i][1], "'" . $matches[$i][2] . "'", $res);
                $res = str_replace('${"GLOBALS"}["' . $matches[$i][1] . '"]', "'" . $matches[$i][2] . "'", $res);
            }
            $res = str_replace("'" . $matches[$i][2] . "'='" . $matches[$i][2] . "';", '', $res);
            $res = str_replace($matches[$i][2] . "='" . $matches[$i][2] . "';", '', $res);
            $res = str_replace($matches[$i][2] . "=" . $matches[$i][2] . ';', '', $res);
        }
        $res = Helpers::replaceCreateFunction($res);
        preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $matches);
        $res = preg_replace_callback('~\$\{"GLOBALS"}\["' . $matches[1] . '"\]\s*\(\'([^\']+)\'\)~msi', function ($calls) use ($matches) {
            $temp1 = substr($calls[1], $matches[3], $matches[4]);
            $temp2 = substr($calls[1], $matches[5]);
            $temp3 = substr($calls[1], $matches[6],strlen($calls[1]) - $matches[7]);
            return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    public function unwrapFuncs($string, $level = 0)
    {
        $close_tag = false;
        $res = '';

        if (trim($string) == '') {
            return '';
        }
        if ($level > 100) {
            return '';
        }

        if ((($string[0] == '\'') || ($string[0] == '"')) && (substr($string, 1, 2) != '?>')) {
            if($string[0] == '"' && preg_match('~\\\\x\d+~', $string)) {
                return stripcslashes($string);
            } else {
                return substr($string, 1, -2);
            }
        } elseif ($string[0] == '$') {
            preg_match('~\$\w{1,40}~', $string, $string);
            $string = $string[0];
            $matches = array();
            if (!@preg_match_all('~\\' . $string . '\s*=\s*(("([^;"\\\]+)(\\\)?)+");~msi', $this->full_source, $matches)) {
                @preg_match_all('~\\' . $string . '\s*=\s*((\'([^;\'\\\]+)(\\\)?)+\');~msi', $this->full_source, $matches);
                $str = @$matches[1][0];
            } else {
                $str = $matches[1][0];
            }
            $this->cur = str_replace($matches[0][0], '', $this->cur);
            $this->text = str_replace($matches[0][0], '', $this->text);
            return substr($str, 1, -1);
        } else {
            $pos      = strpos($string, '(');
            $function = substr($string, 0, $pos);
            $arg      = $this->unwrapFuncs(substr($string, $pos + 1), $level + 1);
            if (strpos($function, '?>') !== false) {
                $function = str_replace("'?>'.", "", $function);
                $function = str_replace('"?>".', "", $function);
                $function = str_replace("'?>' .", "", $function);
                $function = str_replace('"?>" .', "", $function);
                $close_tag = true;
            }
            $function = str_replace(array('@',' '), '', $function);
            $safe = Helpers::isSafeFunc($function);
            if ($safe) {
                $res = @$function($arg);
            } else {
                $res = $arg;
            }
            if ($close_tag) {
                $res = "?> " . $res;
                $close_tag = false;
            }
            return $res;
        }
    }

    private function deobfuscateEvalFunc($str)
    {
        $res = $str;
        $res = stripcslashes($res);
        preg_match('~function\s*(\w{1,40})\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*\"base64_decode\";\s*(\$\w{1,40})\s*=\s*\"gzinflate\";\s*return\s*\4\(\3\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\(\1\(\"([^\"]*)\"\)\);~msi', $res, $matches);
        $res = gzinflate(base64_decode($matches[5]));
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalHex($str)
    {
        preg_match('~eval\s*\("(\\\\x?\d+[^"]+)"\);~msi', $str, $matches);
        $res = stripcslashes($matches[1]);
        $res = str_replace($matches[1], $res, $res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateEvalVar($str)
    {
        preg_match('~((\$\w+)\s*=\s*[\'"]([^\'"]+)[\'"];)\s*.{0,10}?@?eval\s*\((base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\()+(\({0,1}\2\){0,1})\)+;~msi', $str, $matches);
        $string = str_replace($matches[1], '', $matches[0]);
        $text = "'" . addcslashes(stripcslashes($matches[3]), "\\'") . "'";
        $string = str_replace($matches[5], $text, $string);
        $res = str_replace($matches[0], $string, $str);
        return $res;
    }

    private function deobfuscateEval($str)
    {
        $res = $str;
        if (preg_match('~(preg_replace\(["\']/\.\*?/[^"\']+["\']\s*,\s*)[^\),]+(?:\)+;[\'"])?(,\s*["\'][^"\']+["\'])\)+;~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[2], '', $res);
            return $res;
        }

        if (preg_match('~((\$\w+)\s*=\s*create_function\(\'\',\s*)[^\)]+\)+;\s*(\2\(\);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[3], '', $res);
            return $res;
        }

        if (preg_match('~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi', $res, $matches)) {
            $res = str_replace($matches[0], 'eval(', $res);
            return $res;
        }

        preg_match('~@?eval\s*\(\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi', $res, $matches);
        $string = $matches[0];
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($string, 5, strlen($string) - 7);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEcho($str)
    {
        $res = $str;
        preg_match('~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+.*?[^\'")]+((\s*\.?[\'"]([^\'";]+\s*)+)?\s*[\'"\);]+)+~msi', $res, $matches);
        $string = $matches[0];
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($string, 5, strlen($string) - 7);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateFOPO($str)
    {
        preg_match('~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\([^\)]+\)+\s*;~msi', $str, $matches);
        $phpcode = Helpers::formatPHP($str);
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)));
        if (strpos($phpcode, 'eval') !== false) {
            preg_match_all('~\$\w+\(\$\w+\(\$\w+\("[^"]+"\)+~msi', $phpcode, $matches2);
            @$phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(end(end($matches2))))));
            $old = '';
            $hangs = 0;
            while (($old != $phpcode) && (strlen(strstr($phpcode, 'eval($')) > 0) && $hangs < 30) {
                $old = $phpcode;
                $funcs = explode(';', $phpcode);
                if (count($funcs) == 5) {
                    $phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)))));
                } elseif (count($funcs) == 4) {
                    $phpcode = gzinflate(base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode))));
                }
                $hangs++;
            }
        }
        $res = str_replace($matches[0], substr($phpcode, 2), $str);
        return $res;
    }

    private function deobfuscateFakeIonCube($str)
    {
        $subst_value = 0;
        preg_match('~if\s*\(\!extension_loaded\(\'IonCube_loader\'\)\).+pack\(\"H\*\",\s*\$__ln\(\"/\[A-Z,\\\\r,\\\\n\]/\",\s*\"\",\s*substr\(\$__lp,\s*([0-9a-fx]+\-[0-9a-fx]+)\)\)\)[^\?]+\?\>\s*[0-9a-z\r\n]+~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $subst_value = intval($matches[1])-21;
        $code = @pack("H*", preg_replace("/[A-Z,\r,\n]/", "", substr($str, $subst_value)));
        $res = str_replace($matches[0], $code, $str);
        return $res;
    }

    private function deobfuscateCobra($str)
    {
        preg_match('~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\([^\)]+\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $res
        );

        $res = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $res
        );

        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\"\;\s*\1\s*=\s*explode\(\"([^\"]+)\",\s*\s*\1\);~msi', $res, $matches);
        $var = $matches[1];
        $decrypt = base64_decode(current(explode($matches[3], $matches[2])));
        $decrypt = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $decrypt
        );

        $decrypt = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $decrypt
        );

        preg_match('~if\(\!function_exists\(\"(\w+)\"\)\)\s*\{\s*function\s*\1\(\$string\)\s*\{\s*\$string\s*=\s*base64_decode\(\$string\)\;\s*\$key\s*=\s*\"(\w+)\"\;~msi', $decrypt, $matches);

        $decrypt_func = $matches[1];
        $xor_key = $matches[2];

        $res = preg_replace_callback(
            '~\\' . $var . '\s*=\s*.*?eval\(' . $decrypt_func . '\(\"([^\"]+)\"\)\)\;\"\)\;~msi',
            function ($matches) use ($xor_key) {
                $string = base64_decode($matches[1]);
                $key = $xor_key;
                $xor = "";
                for ($i = 0; $i < strlen($string);) {
                    for ($j = 0; $j < strlen($key); $j++,$i++) {
                        if (isset($string{$i})) {
                            $xor .= $string{$i} ^ $key{$j};
                        }
                    }
                }
                return $xor;
            },
            $res
        );
        $res = str_replace($find, $res, $str);
        return $res;
    }
}


/**
 * Class Factory.
 */
class Factory
{
    /**
     * @var Factory
     */
    private static $instance;
    /**
     * @var array
     */
    private static $config;

    /**
     * Factory constructor.
     *
     * @throws Exception
     */
    private function __construct()
    {

    }

    /**
     * Instantiate and return a factory.
     *
     * @return Factory
     * @throws Exception
     */
    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Configure a factory.
     *
     * This method can be called only once.
     *
     * @param array $config
     * @throws Exception
     */
    public static function configure($config = [])
    {
        if (self::isConfigured()) {
            throw new Exception('The Factory::configure() method can be called only once.');
        }

        self::$config = $config;
    }

    /**
     * Return whether a factory is configured or not.
     *
     * @return bool
     */
    public static function isConfigured()
    {
        return self::$config !== null;
    }

    /**
     * Creates and returns an instance of a particular class.
     *
     * @param string $class
     *
     * @param array $constructorArgs
     * @return mixed
     * @throws Exception
     */
    public function create($class, $constructorArgs = [])
    {
        if (!isset(self::$config[$class])) {
            throw new Exception("The factory is not contains configuration for '{$class}'.");
        }

        if (is_callable(self::$config[$class])) {
            return call_user_func(self::$config[$class], $constructorArgs);
        } else {
            return new self::$config[$class](...$constructorArgs);
        }
    }
}
