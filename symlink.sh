if [ ! -d "vendor/squizlabs/php_codesniffer/src/Standards/Security" ]; then
	if [ -d "vendor/pheromone" ]; then
		ln -s ../../../../pheromone/phpcs-security-audit/Security vendor/squizlabs/php_codesniffer/src/Standards/Security
	else
		ln -s ../../../../../Security vendor/squizlabs/php_codesniffer/src/Standards/Security
	fi
	if [ -n "$WINDIR" ]; then
		echo "Looks like you're on Windows... folder copied."
	else
		echo "Symlink created."
	fi
fi
