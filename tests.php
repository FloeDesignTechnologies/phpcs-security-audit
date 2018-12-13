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
	

	// BadFunctions
	md5();
	phpinfo();
	create_function($a);
	ftp_exec($a);
	fread($a);
	array_map($a);
	`$a`;
	`$_GET`;
	include($a);
	assert($a);
	assert($_GET);
	exec($a);
	exec($_GET);
	mysql_query($a);
	mysql_query($_GET);


	// Crypto
	mcrypt_encrypt();
	openssl_public_encrypt($i,$e,$k, OPENSSL_PKCS1_PADDING);

	// CVEs
	xml_parse_into_struct(xml_parser_create_ns(), str_repeat("<blah>", 1000), $a);
	quoted_printable_encode(str_repeat("\xf4", 1000));

	// Misc
	$a->withHeader('Access-Control-Allow-Origin', '*');
	include('abc.xyz');

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
	delete($a);

	// Drupal 7 Dynamic queries SQLi
	$query = db_select('tname', "wn");
	$query->join('node', 'n', $a);
	$query->innerJoin('node', 'n', $a);
	$query->leftJoin('node', 'n', $a);
	$query->rightJoin('node', 'n', $a);
	$query->addExpression($a, 'w');
	$query->groupBy($a);

	$query->orderBy($a, $a);
	$query->range('safe', 'safe');

	$count = $query
		->fields("wn")
		->condition('email', '1', $_GET)
		->condition('email', '1')
		->where($a, array(":aaa" => '2'))
		->havingCondition('email', '', $a)
		->having($a, $args = array(":aaa" => '2'))
		->execute()
		->rowCount();
	echo $count;

	$query = db_update('tname')
	->expression($a, $a)
	->execute();

	$nid = db_insert('tname')
	->fields(array(
		$a => 'safe',
		$b => 'safe',
		'c' => 'safe',

	))
	->values(array(
		'safe' => 'safe',
	))
	->execute();

	$query = db_select('node', 'n');
	$myselect = db_select('mytable')
	  ->fields($_GET)
	  ->condition('myfield', 'myvalue');
	$alias = $query->join($myselect, 'myalias', 'n.nid = myalias.nid');


?>

