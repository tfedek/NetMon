# NetMon v4 – Network Location Availability Monitoring System

Projekat za predmet **Bezbednost u elektronskom poslovanju**  
Visoka tehnička škola strukovnih studija – Subotica

---

## Zahtevi

- PHP 8.1+
- MySQL 5.7+ / MariaDB 10.4+
- Apache sa `mod_rewrite`
- Composer (https://getcomposer.org)

---

## Instalacija

### 1. Raspakovati u htdocs
```
C:\xampp\htdocs\netmon_v4\
```

### 2. Instalirati zavisnosti (Composer)
```bash
cd C:\xampp\htdocs\netmon_v4
composer install
```
Ovo instalira:
- **phpmailer/phpmailer** – slanje emailova
- **mobiledetect/mobiledetectlib** – detekcija uređaja
- **fakerphp/faker** – generisanje test podataka (dev)

### 3. Kreirati bazu
phpMyAdmin → SQL tab → pokrenuti `sql/schema.sql`

### 4. Podesiti konfiguraciju
Otvoriti `includes/config.php` i proveriti:
```php
define('DB_USER', 'root');
define('DB_PASS', '');
define('APP_URL', 'http://localhost/netmon_v4');
```

### 5. Seed test podaci
```
http://localhost/netmon_v4/seed.php
```

### 6. Prijava
```
http://localhost/netmon_v4/login.php
```
- Admin: `admin@netmon.local` / `Admin1234!`
- User:  `jsmith@example.com` / `Pass1234!`

---

## Struktura projekta

```
netmon_v4/
├── api/
│   └── locations.php       ← REST API (CRUD + JWT)
├── includes/
│   ├── bootstrap.php       ← Autoloader
│   ├── config.php          ← Konfiguracija
│   ├── Database.php        ← PDO singleton
│   ├── security.php        ← CSRF, JWT, CSP, session
│   ├── device.php          ← Mobile_Detect + IP geolokacija (cURL)
│   ├── checker.php         ← TCP/HTTP provera dostupnosti
│   ├── mailer.php          ← PHPMailer wrapper
│   └── MobileDetect/       ← Fallback ako Composer nije pokrenut
├── public/
│   ├── css/app.css
│   └── js/app.js
├── views/
│   ├── header.php
│   └── footer.php
├── sql/
│   └── schema.sql          ← Šema baze podataka
├── login.php
├── register.php
├── logout.php
├── forgot-password.php
├── reset-password.php
├── index.php               ← Dashboard
├── locations.php           ← CRUD (samo admin)
├── admin.php               ← Admin panel
├── check.php               ← Manuelna provera
├── seed.php                ← Punjenje baze
├── composer.json
└── NetMon_API.postman_collection.json
```

---

## REST API

### Autentikacija
```
POST /api/auth/token
Content-Type: application/json
{"email": "admin@netmon.local", "password": "Admin1234!"}
```

### Endpointi

| Metod  | URL                          | Opis                  | Rola  |
|--------|------------------------------|-----------------------|-------|
| POST   | /api/auth/token              | Dohvati JWT token     | —     |
| GET    | /api/locations               | Lista lokacija        | svi   |
| GET    | /api/locations/{id}          | Jedna lokacija        | svi   |
| POST   | /api/locations               | Kreiraj lokaciju      | admin |
| PUT    | /api/locations/{id}          | Ažuriraj lokaciju     | admin |
| DELETE | /api/locations/{id}          | Obriši lokaciju       | admin |
| POST   | /api/locations/{id}/check    | Pokreni proveru       | svi   |

---

## Bezbednosni mehanizmi

| Mehanizam           | Implementacija                                    |
|---------------------|---------------------------------------------------|
| bcrypt lozinke      | `password_hash()` cost=12                         |
| CSRF zaštita        | HMAC `hash_hmac` token vezan za URL putanju       |
| CSP header          | `Content-Security-Policy` sa nonce               |
| SQL injection       | PDO prepared statements + `bindParam` svuda      |
| XSS zaštita         | `htmlspecialchars()` na svim outputima           |
| Session sigurnost   | `session_regenerate_id()`, HTTPOnly, SameSite    |
| Session invalidacija| `session_version` – promena role odjavljuje korisnika |
| Rate limiting       | 5 pokušaja → 15 min blokada                      |
| JWT API auth        | HS256, 1h expiry                                  |
| Login audit         | IP, uređaj, OS, browser, zemlja, grad, ISP       |
| Email enumeracija   | Forgot-password uvek vraća isti odgovor          |

---

## Korišćene tehnologije i biblioteke

| Biblioteka                   | Verzija | Svrha                        | Instalacija        |
|------------------------------|---------|------------------------------|--------------------|
| phpmailer/phpmailer          | ^6.9    | Slanje emailova              | `composer install` |
| mobiledetect/mobiledetectlib | ^2.8    | Detekcija uređaja            | `composer install` |
| fakerphp/faker               | ^1.23   | Test podaci (dev)            | `composer install` |
| Bootstrap                    | 5.3.3   | UI framework                 | CDN                |
| ip-api.com                   | —       | IP geolokacija (besplatni)   | HTTP API           |

---

## Literatura

1. OWASP Top Ten – https://owasp.org/www-project-top-ten/
2. PHP The Right Way – https://phptherightway.com/
3. PHPMailer dokumentacija – https://github.com/PHPMailer/PHPMailer
4. Mobile Detect – http://mobiledetect.net/
5. JWT.io – https://jwt.io/
6. REST API Tutorial – https://www.restapitutorial.com/
7. PDO dokumentacija – https://www.php.net/manual/en/book.pdo.php
8. ip-api.com – https://ip-api.com/docs
9. FakerPHP – https://fakerphp.org/
