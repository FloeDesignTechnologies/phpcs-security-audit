phpcs-security-audit v2
=======================

About
-----
phpcs-security-audit is a set of [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) rules that finds vulnerabilities and weaknesses related to security in PHP code.

It currently has core PHP rules as well as Drupal 7 specific rules.

The tool also checks for CVE issues and security advisories related to CMS/framework. Using it, you can follow the versioning of components during static code analysis.

The main reason of this project for being an extension of PHP_CodeSniffer is to have easy integration into continuous integration systems. It is also able to find security bugs that are not detected with object oriented analysis (like in [RIPS](http://rips-scanner.sourceforge.net/) or [PHPMD](http://phpmd.org/)).

phpcs-security-audit is backed by [Floe design + technologies](https://floedesign.ca/) and written by [Jonathan Marcil](https://twitter.com/jonathanmarcil).

[<img src="https://floedesign.ca/img/thumbs/floe.jpg" alt="Floe design + technologies" width="100">](https://floedesign.ca/)


Install
-------

Requires [PHP CodeSniffer](http://pear.php.net/package/PHP_CodeSniffer/) version 3.x with PHP 5.4 or higher.

Because of the way PHP CodeSniffer works, you need to put the `Security/` folder from phpcs-security-audit in `/usr/share/php/PHP/CodeSniffer/Standards` or do a symlink to it.

The easiest way to install is to git clone and use composer that will create the symlink for you:
```
composer install
./vendor/bin/phpcs --standard=example_base_ruleset.xml tests.php
```

The package is also on [Packagist](https://packagist.org/packages/pheromone/phpcs-security-audit):
```
composer require pheromone/phpcs-security-audit
sh vendor/pheromone/phpcs-security-audit/symlink.sh
./vendor/bin/phpcs --standard=./vendor/pheromone/phpcs-security-audit/example_base_ruleset.xml ./vendor/pheromone/phpcs-security-audit/tests.php
```

If you want to integrate it all with Jenkins, go see http://jenkins-php.org/ for extensive help.


Usage
-----

Simply point to any XML ruleset file and a folder:
```
phpcs --extensions=php,inc,lib,module,info --standard=example_base_ruleset.xml /your/php/files/
```

Specifying extensions is important since for example PHP code is within .module files in Drupal.

To have a quick example of output you can use the provided tests.php file:
```
$ phpcs --extensions=php,inc,lib,module,info --standard=example_base_ruleset.xml tests.php

FILE: tests.php
--------------------------------------------------------------------------------
FOUND 16 ERROR(S) AND 15 WARNING(S) AFFECTING 22 LINE(S)
--------------------------------------------------------------------------------
  6 | WARNING | Possible XSS detected with . on echo
  6 | ERROR   | Easy XSS detected because of direct user input with $_POST on
    |         | echo
  8 | WARNING | db_query() is deprecated except when doing a static query
  8 | ERROR   | Potential SQL injection found in db_query()
  9 | WARNING | Usage of preg_replace with /e modifier is not recommended.

```

#### Drupal note

For the Drupal AdvisoriesContrib you need to change your `/etc/php5/cli/php.ini` to have:
```
short_open_tag = On
```
in order to get rid of "No PHP code was found in this file" warnings.

Please note that only Drupal modules downloaded from drupal.org are supported. If you are using contrib module but from another source, the version checking will probably won't work and will generate warning.


Customize
---------
As in normal PHP CodeSniffer rules, customization is provided in the XML files that are in the top folder of the project.

These global parameters are used in many rules:
* ParanoiaMode: set to 1 to add more checks. 0 for less.
* CmsFramework: set to the name of a folder containings rules and Utils.php (such as Drupal7, Symfony2).

They can be setted in the XML files or in command line for permanent config with `--config-set` or at runtime with `--runtime-set`. Note that the XML override all CLI options so remove it if you want to use it. The CLI usage is as follow `phpcs --runtime-set ParanoiaMode 0 --extensions=php --standard=example_base_ruleset.xml tests.php`;

In some case you can force the paranoia mode on or off with the parameter `forceParanoia` inside the XML rule.


Specialize
----------

If you want to fork and help or just do your own sniffs you can use the utilities provided by phpcs-security-audit rules in order to facilitate the process.

Let's say you have a custom CMS function that is taking user input from `$_GET` when a function call to `get_param()` is done.

You have to create a new Folder in Sniffs/ that will be the name of your framework. Then you'll need
to create a file named Utils.php that will actually be the function that will specialise the generic sniffs. To guide you, just copy the file from another folder such as Drupal7/.

The main function you'll want to change is `is_direct_user_input` where you'll want to return TRUE when `get_param()` is seen:
```php
	public static function is_direct_user_input($var) {
		if (parent::is_direct_user_input($var)) {
			return TRUE;
		} else {
			if ($var == 'get_param') {
				return TRUE;
			}
		}
		return FALSE;
	}
```

Don't forget to set the occurrence of param "CmsFramework" in your XML base configuration in order to select your newly added utilities.

You are not required to do your own sniffs for the modification to be useful, since you are specifying what is a user input for other rules, but you could use the newly created directory to do so.

If you implement any public cms/framework customization please make a pull request to help the project grows.


Annoyances
----------

As any security tools, this one comes with it's share of annoyance. At first a focus on finding vulnerabilities will be done, but later it is planned to have a phase where efforts will be towards reducing annoyances, in particular with the number of false positives.

* It's a generator of false positives. This can actually help you learn what are the weak functions in PHP. Paranoia mode will fix that by doing a major cut-off on warnings when set to 0.
* It's slow. On big Drupal modules and core it can take too much time (and RAM, reconfigure cli/php.ini to use 512M if needed) to run. Not sure if it's because of bugs in PHPCS or this set of rules, but will be investigated last. Meanwhile you can configure PHPCS to ignore big contrib modules (and run another instance of PHPCS for .info parsing only for them). An example is og taking hours, usually everything runs under 1-2 minutes and sometime around 5 minute. You can only use one core in PHP since no multithreading is available. Possible workaround is to use phpcs --ignore=folder to skip scanning of those parts.
* For Drupal advisories checking: a module with multiple versions might be secure if a lesser fixed version exists and you'll still get the error or warning. Keep everything updated at latest as recommended on Drupal's website.



