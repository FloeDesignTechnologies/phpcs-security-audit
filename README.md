phpcs-security-audit v3
=======================

<div aria-hidden="true">

[![License: GPLv3](https://poser.pugx.org/pheromone/phpcs-security-audit/license)](https://github.com/FloeDesignTechnologies/phpcs-security-audit/blob/master/LICENSE)
[![Minimum PHP Version](https://img.shields.io/packagist/php-v/pheromone/phpcs-security-audit.svg?maxAge=3600)](https://packagist.org/packages/pheromone/phpcs-security-audit)
[![Latest Stable Version](https://poser.pugx.org/pheromone/phpcs-security-audit/v/stable)](https://packagist.org/packages/pheromone/phpcs-security-audit)
[![Release Date of the Latest Version](https://img.shields.io/github/release-date/FloeDesignTechnologies/phpcs-security-audit.svg?maxAge=1800)](https://github.com/FloeDesignTechnologies/phpcs-security-audit/releases)
[![Packagist Downloads](https://img.shields.io/packagist/dt/Pheromone/phpcs-security-audit)](https://packagist.org/packages/pheromone/phpcs-security-audit)
[![Last Commit to Unstable](https://img.shields.io/github/last-commit/FloeDesignTechnologies/phpcs-security-audit/master.svg)](https://github.com/FloeDesignTechnologies/phpcs-security-audit/commits/master)
[![Travis Build Success](https://img.shields.io/travis/FloeDesignTechnologies/phpcs-security-audit)](https://travis-ci.org/github/FloeDesignTechnologies/phpcs-security-audit)


</div>

About
-----
phpcs-security-audit is a set of [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) rules that finds vulnerabilities and weaknesses related to security in PHP code.

It currently has core PHP rules as well as Drupal 7 specific rules.

The tool also checks for CVE issues and security advisories related to the CMS/framework. This enables you to follow the versioning of components during static code analysis.

The main reason for this project being an extension of PHP_CodeSniffer is to have easy integration into continuous integration systems. It also allows for finding security bugs that are not detected with some object oriented analysis (such as [PHPMD](http://phpmd.org/)).

phpcs-security-audit in its beginning was backed by Pheromone (later on named Floe Design + Technologies) and written by [Jonathan Marcil](https://twitter.com/jonathanmarcil).



Install
-------

Requires [PHP CodeSniffer](http://pear.php.net/package/PHP_CodeSniffer/) version 3.1.0 or higher with PHP 5.4 or higher.

The easiest way to install is using [Composer](https://getcomposer.org/):
```
#WARNING: this currently doesn't work up until the v3 package is released
#See Contribute section bellow for git clone instruction
composer require --dev pheromone/phpcs-security-audit
```

This will also install the [DealerDirect Composer PHPCS plugin](https://github.com/Dealerdirect/phpcodesniffer-composer-installer/) which will register the `Security` standard with PHP_CodeSniffer.

Now run:
```
./vendor/bin/phpcs -i
```

If all went right, you should see `Security` listed in the list of installed coding standards.

If you want to integrate it all with Jenkins, go see http://jenkins-php.org/ for extensive help.


Usage
-----

Simply set the standard to `Security` or point to any XML ruleset file and to a folder to scan:
```
phpcs --extensions=php,inc,lib,module,info --standard=./vendor/pheromone/phpcs-security-audit/example_base_ruleset.xml /your/php/files/
```

Specifying extensions is important since, for example, PHP code is within `.module` files in Drupal.

To have a quick example of output you can use the provided `tests.php` file:
```
$ phpcs --extensions=php,inc,lib,module,info --standard=./vendor/pheromone/phpcs-security-audit/example_base_ruleset.xml ./vendor/pheromone/phpcs-security-audit/tests.php

FILE: tests.php
--------------------------------------------------------------------------------
FOUND 18 ERRORS AND 36 WARNINGS AFFECTING 44 LINES
--------------------------------------------------------------------------------

  6 | WARNING | Possible XSS detected with . on echo
  6 | ERROR   | Easy XSS detected because of direct user input with $_POST on echo
  9 | WARNING | Usage of preg_replace with /e modifier is not recommended.
 10 | WARNING | Usage of preg_replace with /e modifier is not recommended.
 10 | ERROR   | User input and /e modifier found in preg_replace, remote code execution possible.
 11 | ERROR   | User input found in preg_replace, /e modifier could be used for malicious intent.
   ...
```

#### Drupal note

For the Drupal AdvisoriesContrib you need to change your `/etc/php5/cli/php.ini` to have:
```
short_open_tag = On
```
in order to get rid of "No PHP code was found in this file" warnings.

Please note that only Drupal modules downloaded from drupal.org are supported. If you are using contrib module but from another source, the version checking probably won't work and will generate a warning.


Customize
---------
As with the normal PHP CodeSniffer rules, customization is provided in the XML files that are in the top folder of the project.

These global parameters are used in many rules:
* ParanoiaMode: set to 0 to reduce false positive. set to 1 (default) to be a lot more verbose.
* CmsFramework: set to the name of a folder containings rules and Utils.php (such as Drupal7) to target a specific framework.

They can be set in a custom ruleset XML file (such as `example_drupal7_ruleset.xml`), from the command line for permanent config with `--config-set` or at runtime with `--runtime-set`. Note that the XML overrides all CLI options so remove it if you want to use it. The CLI usage is as follows:
```
phpcs --runtime-set ParanoiaMode 0 --extensions=php --standard=./vendor/pheromone/phpcs-security-audit/example_base_ruleset.xml tests.php
```

For some rules, you can force the paranoia mode on or off with the parameter `forceParanoia` inside the XML file.


Contribute
----------
It is possible to install with a `git clone` and play with it in the same folder.
```
composer install
./vendor/bin/phpcs --standard=example_base_ruleset.xml --extensions=php tests.php
```

By default it should set PHPCS to look in the current folder:
```
PHP CodeSniffer Config installed_paths set to ../../../
```

If for any reason you need to change this (should work out of the box) you will need to `phpcs --config-set installed_paths` as explained in [PHP_CodeSniffer docs](https://github.com/squizlabs/PHP_CodeSniffer/wiki/Configuration-Options#setting-the-installed-standard-paths).

Master can contain breaking changes, so people are better off relying on releases for stable versions.

Those release packages are available [here on GitHub](releases) or on [Packagist](https://packagist.org/packages/pheromone/phpcs-security-audit).

Some guidelines if you want to create new rules::
* Ensure that `ParanoiaMode` controls how verbose your sniff is:
	* If the sniff is only some of the time a valid security concern, run it when `paranoia=true` only.
	* Warnings are generally issued instead of Errors for most-of-the-time concerns when `paranoia=false`.
	* Errors are always generated when you are sure about user input being used.
* Prefer false positives (annoying results) over false negatives (missing results).
	* `paranoia=false` should solve false positive, otherwise warn on anything remotely suspicious.
* Include at least one test that triggers your sniff into `tests.php`.
	* Keep the test as a one liner, it doesn't need to make sense.
* Don't forget to include your new sniff in the `example_base_ruleset.xml` and `example_drupal7_ruleset.xml` when it applies.


#### Specialize

If you want to support a specific code base or framework beyond XML configuration, you can use the utilities provided by phpcs-security-audit to facilitate the process.

Let's say you have a custom CMS function that is taking user input from `$_GET` when a function call to `get_param()` is done.

You have to create a new Folder in `Sniffs/` that will be the name of your framework. Then you'll need
to create a file named `Utils.php` that will actually be the function that will specialise the generic sniffs. To guide you, just copy the file from another folder such as `Drupal7/`.

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

In the same fashion, you can also reduce the number of false positive by adding mitigation functions. Those are functions that serve as security controls (either explicitly in the function or by a side effect) that lower the risks. A good example is `htmlentities` for XSS. See `is_XSS_mitigation` function in `Drupal7/Utils.php`.

If you implement any public CMS/Framework customization please make a pull request to help the project grows.

#### Test

The tool now support unit testing with `composer test`.

To test for a specific sniff, use `composer test -- --filter RULENAME` (without the `Sniff` part).

To create a test, create a folder with RULENAME. Inside, have a `RULENAMEUnitTest.inc` file for the code to be scanned and `RULENAMEUnitTest.php` file for the PHPCS validation of findings. For the rule to support a given CMS/Framework, it needs to have a inc file with the following: `RULENAMEUnitTest.CMSFRAMEWORK.inc`. See `Security/Tests/BadFunctions` for a complete example.


Annoyances
----------

As with any security tool, this one comes with it's share of annoyance. At first a focus on finding vulnerabilities will be done, but later it is planned to have a phase where efforts will be towards reducing annoyances, in particular with the number of false positives.

* It's a generator of false positives created for people doing secure code reviews. It can help you learn what are the weak functions in PHP but can be counter productive in CI/CD environments. Set `ParanoiaMode` to `0` for a major cut-off on warnings.
* This tool was created around 10 years ago. Some of its parts might look outdated, and support for old PHP code will still be present. The reality is that many code base scanned with it might be as old as the tool.
* It's slow. On big Drupal modules and core it can take too much time (and RAM, reconfigure `cli/php.ini` to use 512M if needed) to run. Not sure if it's because of bugs in PHPCS or this set of rules, but will be investigated last. Meanwhile you can configure PHPCS to ignore big contrib modules (and run another instance of PHPCS for `.info` parsing only for them). An example is og taking hours, usually everything runs under 1-2 minutes and sometimes around 5 minute. You can try using the `--parallel=8` (or another number) option to try and speed things up on supported OSes. Possible work-around is to use `phpcs --ignore=folder` to skip scanning of those parts.
* For Drupal advisories checking: a module with multiple versions might be secure if a lesser fixed version exists and you'll still get the error or warning. Keep everything updated on latest as recommended on Drupal's website.



