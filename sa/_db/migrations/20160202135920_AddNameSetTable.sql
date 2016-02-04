
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

CREATE TABLE `nameSets` (
       `id` int(11) NOT NULL AUTO_INCREMENT,
       -- SHA256 hash of alphabetically sorted, lowercased, comma joined
       -- DNS names contained in a certificate
       `setHash` BINARY(32) NOT NULL,
       `serial` VARCHAR(255) NOT NULL,
       `notBefore` DATETIME NOT NULL,
       PRIMARY KEY (`id`),
       KEY `setHash`
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE `nameSets`;

