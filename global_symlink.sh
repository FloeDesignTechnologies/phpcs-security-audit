PREFIX="$(composer config home)/vendor"

if [ ! -d "$PREFIX/squizlabs/php_codesniffer/src/Standards/Security" ]; then
	if [ -d "$PREFIX/pheromone" ]; then
		ln -s ../../../../pheromone/phpcs-security-audit/Security $PREFIX/squizlabs/php_codesniffer/src/Standards/Security
	else
		ln -s ../../../../../Security $PREFIX/squizlabs/php_codesniffer/src/Standards/Security
	fi
	if [ -n "$WINDIR" ]; then
		echo "Looks like you're on Windows... folder copied."
	else
		echo "Symlink created."
	fi
fi
