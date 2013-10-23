<?php
	/* Tests script for phpcs-security-audit */

	//eval($_GET['a']);
	echo "aaaa";
	echo "bbbb" . $_POST['b'];
	echo "b";
	db_query($_GET['a']);
	preg_replace("/.*/ei", 'aaaaaaa', 'bbbbb');
	preg_replace("/.*/ei", $_GET['a'], 'aaaaaaa');
	preg_replace($_GET['b'], $_GET['a'], $_GET['c']);
	preg_replace($b, $_GET['a'], 'aaaaaa');
	preg_replace("aaa", $_GET['a'], 'ababaaa');

	// CVEs
	xml_parse_into_struct(xml_parser_create_ns(), str_repeat("<blah>", 1000), $a);
	quoted_printable_encode(str_repeat("\xf4", 1000));


	// Easy user input
	$_GET['a'] = 'xss';
	print("aaa" . $_GET['a']);
	echo($_GET['a']);
	echo $_GET['a'];
	echo "{$_GET['a']}";
	print "${_GET['a']}";
	echo a($_GET['b']);
	echo (allo(a($_GET['c'])));
	echo arg(1);
	die( "" . $_GET['a'] );
	exit("exit" . $_GET['a']);
?>
	<?= $_GET['a'] ?>
<?php

	// FilesystemFunctions
	file_create_filename(arg(1));
	symlink($a);


?>

