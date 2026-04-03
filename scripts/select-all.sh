sqlite3 -init init.sqlite ./blackadder.db -batch -bail << EOT
SELECT * FROM binaries;
SELECT * FROM binary_locators;
SELECT * FROM sections;
SELECT * FROM symbols;
EOT
