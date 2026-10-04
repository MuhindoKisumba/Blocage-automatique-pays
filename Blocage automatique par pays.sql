/* =====================================================
    BLOCAGE AUTOMATIQUE PAR PAYS
   (GeoIP + Multi-Firewall)
===================================================== */

-------------------------------------------------------
-- 1 Table pays interdits
-------------------------------------------------------

CREATE TABLE IF NOT EXISTS blocked_countries (
    country_code TEXT PRIMARY KEY,
    country_name TEXT
);

-- Exemple de pays bloqués
INSERT INTO blocked_countries VALUES
('RU','Russia'),
('KP','North Korea'),
('IR','Iran'),
('CN','China')
ON CONFLICT DO NOTHING;

-------------------------------------------------------
-- 2 Fonction : obtenir pays depuis IP
-------------------------------------------------------

CREATE OR REPLACE FUNCTION get_country_from_ip(ip TEXT)
RETURNS TEXT AS $$
DECLARE
    result JSON;
    country TEXT;
BEGIN

    IF ip IS NULL THEN
        RETURN 'UNKNOWN';
    END IF;

    result := maxmind_lookup(
        '/usr/share/GeoIP/GeoLite2-Country.mmdb',
        ip
    );

    country := result->'country'->>'iso_code';

    IF country IS NULL THEN
        RETURN 'UNKNOWN';
    END IF;

    RETURN country;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 3 Fonction vérification pays interdit
-------------------------------------------------------

CREATE OR REPLACE FUNCTION is_country_blocked(country TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    blocked BOOLEAN;
BEGIN

    SELECT EXISTS(
        SELECT 1
        FROM blocked_countries
        WHERE country_code = country
    ) INTO blocked;

    RETURN blocked;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 4 Fonction sécurité géographique
-------------------------------------------------------

CREATE OR REPLACE FUNCTION geo_firewall_block()
RETURNS TRIGGER AS $$
DECLARE
    ip TEXT;
    country TEXT;
BEGIN

    ip := NEW.client_addr;

    IF ip IS NULL THEN
        RETURN NEW;
    END IF;

    country := get_country_from_ip(ip);

    IF is_country_blocked(country) THEN

        -- journaliser événement
        INSERT INTO audit_log(username, action, table_name, query, client_addr)
        VALUES (
            NEW.username,
            'COUNTRY_BLOCK',
            'SECURITY',
            'Connexion depuis pays interdit : ' || country,
            ip
        );

        -- blocage multi-firewall
        PERFORM block_ip_everywhere(
            ip,
            'Pays interdit : ' || country
        );

    END IF;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;

-------------------------------------------------------
-- 5 Trigger surveillance géographique
-------------------------------------------------------

DROP TRIGGER IF EXISTS geo_country_monitor ON audit_log;

CREATE TRIGGER geo_country_monitor
AFTER INSERT ON audit_log
FOR EACH ROW
EXECUTE FUNCTION geo_firewall_block();

-------------------------------------------------------
-- 6 Vue monitoring sécurité
-------------------------------------------------------

CREATE OR REPLACE VIEW blocked_country_activity AS
SELECT
    username,
    client_addr,
    query,
    date_action
FROM audit_log
WHERE action = 'COUNTRY_BLOCK'
ORDER BY date_action DESC;

-------------------------------------------------------
-- 7 Vérification
-------------------------------------------------------

-- Voir les tentatives depuis pays interdits
-- SELECT * FROM blocked_country_activity;

-- Voir la liste des pays bloqués
-- SELECT * FROM blocked_countries;
