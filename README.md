About
=====

phpcs-security-audit is a set of [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) rules that finds flaws or weaknesses related to security in PHP and its popular CMS or frameworks.

It currently has core PHP rules as well as Drupal 7 specific rules. Next planned CMS/framework is Symfony 2.

As a bonus set of rules, the tool also check for CVE issues and security advisories related to CMS/framework. You can use it in order to follow the versionning of components during static code analysis.

The main reasons of this project for being an extension of PHP_CodeSniffer is to have easy integration into continuous integration systems and to be able to find security bugs that are not detected with object oriented analysis (like in [RIPS](http://rips-scanner.sourceforge.net/) or [PHPMD](http://phpmd.org/)).

phpcs-security-audit is backed by [Phéromone](http://www.pheromone.ca/) and written by [Jonathan Marcil](http://www.jonathanmarcil.ca/).

[![Phéromone, agence d'interactions](https://www.owasp.org/images/a/ab/Logo-phero.gif)](http://www.pheromone.ca/)


Usage
=====

You need http://pear.php.net/package/PHP_CodeSniffer/ installed first.

Then all you need to do is to configure or use a XML rule file and run it over your code:
```
phpcs --extensions=php,inc,lib,module,info --standard=example_base_ruleset.xml /your/php/files/
```

Specifying extensions is important since for example PHP code is within .module files in Drupal.

If you want to integrate it all with Jenkins, go see http://jenkins-php.org/ for extensive help.

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
 10 | WARNING | Usage of preg_replace with /e modifier is not recommended.

```

Drupal details
--------------

For the Drupal AdvisoriesContrib you need to change your `/etc/php5/cli/php.ini` to have:
```
short_open_tag = On
```
in order to get rid of "No PHP code was found in this file" warnings.

Please note that only Drupal modules downloaded from drupal.org are supported. If you are using contrib module but from another source, the version checking will probably won't work and will generate warning.


Customize
=========
As in normal PHP CodeSniffer rules, customization is provided in the XML files that are in the top folder of the project.

The `example_subset_ruleset.xml` file will give you all the possible choices and let you customize them or removing the ones you don't like.

These parameters are common in many rules (this is a PHP CodeSniffer limitation, sorry for redundency):
* ParanoiaMode: set to 1 to add more checks. 0 for less.
* CmsFramework: set to the name of a folder containings rules and Utils.php (such as Drupal7, Symfony2).


Specialize
==========

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

Don't forget to set the occurence of param "CmsFramework" in your XML base configuration in order to select your newly added utilities.

You are not required to do your own sniffs for the modification to be useful, since you are specifiying what is a user input for other rules, but you could use the newly created directory to do so.

If you implement any public cms/framework customization please make a pull request to help the project grows.


Annoyances
==========

As any security tools, this one comes with it's share of annoyance. At first a focus on finding vulnerabilities will be done, but later it is planned to have a phase where efforts will be towards reducing annoyances, in particular with the number of false positives.

* It's a generator of false positives. This can actually help you learn what are the weak functions in PHP. Paranoya mode will fix that by doing a major cutoff on warnings when set to 0.
* It's slow. On big Drupal modules it can take too much time (and RAM, reconfigure cli/php.ini to use 512M if needed) to run. Not sure if it's because of bugs in PHPCS or this set of rules, but will be investigated last. Meanwhile you can configure PHPCS to ignore big contrib modules (and run another instance of PHPCS for .info parsing only for them). An example is og taking hours, usually everything runs under 1-2 minutes and sometime around 5 minute. You can only use one core in PHP since no multithreading is available.
* For Drupal advisories checking: a module with multiple versions might be secure if a lesser fixed version exists and you'll still get the error or warning. Keep everything updated at latests as recommended on Drupal's website.



