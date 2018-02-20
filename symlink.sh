if [ ! -d "vendor/squizlabs/php_codesniffer/src/Standards/Security" ]; then
	if [ -d "vendor/pheromone" ]; then
		ln -s ../../../../pheromone/phpcs-security-audit/Security vendor/squizlabs/php_codesniffer/src/Standards/Security
	else
		ln -s ../../../../../Security vendor/squizlabs/php_codesniffer/src/Standards/Security
	fi
	echo "Symlink created."
fi
