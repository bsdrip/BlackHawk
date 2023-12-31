# BlackHawk

## Description

BlackHawk is a sophisticated host-based vulnerability scanner designed to enhance cybersecurity measures. At its core, it leverages the powerful capabilities of the Vulners NSE script to meticulously scan and identify vulnerabilities. The scanner operates by probing discovered ports and analyzing the service versions running on them. This process enables BlackHawk to detect a wide range of potential security weaknesses, providing users with vital insights into their system's vulnerability landscape. Its integration with the Vulners NSE script ensures comprehensive coverage and up-to-date vulnerability detection, making it an invaluable tool for maintaining robust security in dynamic digital environments.

## Installation

1. Clone the repository:
```
git clone --recurse-submodules -j8 https://github.com/bsdrip/BlackHawk.git
```

2. Quick setup:
```
docker-compose up --build
```

The application is available on `http://localhost:1337`


or


2. Install the Python packages in the Pipfile and create a shell:
```
pipenv install && pipenv shell
```

3. Run the migrations:
```
python3 manage.py makemigrations VulnerabilityScanner
python3 manage.py migrate
```

4. Run `celery` in another `pipenv shell`:
```
celery -A blackhawk worker --loglevel=info
```

5. Run the server:
```
python3 manage.py runserver 1337
```

The application is available on `http://localhost:1337`
