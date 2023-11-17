# BlackHawk
---

## Description
---

BlackHawk is a sophisticated host-based vulnerability scanner designed to enhance cybersecurity measures. At its core, it leverages the powerful capabilities of the Vulners NSE script to meticulously scan and identify vulnerabilities. The scanner operates by probing discovered ports and analyzing the service versions running on them. This process enables BlackHawk to detect a wide range of potential security weaknesses, providing users with vital insights into their system's vulnerability landscape. Its integration with the Vulners NSE script ensures comprehensive coverage and up-to-date vulnerability detection, making it an invaluable tool for maintaining robust security in dynamic digital environments.

## Installation
---

Quick setup:
```
docker-compose up --build
```

or

1. Clone the repository:
```
git clone --recurse-submodules -j8 https://github.com/bsdrip/BlackHawk.git
```

3. Install the Python packages in the Pipfile and create a shell:
```
pipenv install && pipenv shell
```

5. Run `celery` in another `pipenv`:
```
celery -A blackhawk worker --loglevel=info
```

6. Run the migrations:
```
python3 manage.py makemigrations VulnerabilityScanner
python3 manage.py migrate
```

7. Run the server:
```
python3 manage.py runserver 8080
```

Now the application is available on `http://localhost:8080`
