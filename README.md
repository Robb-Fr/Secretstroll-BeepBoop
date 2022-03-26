# Secretstroll-BeepBoop
Secretstroll project of CS-523 Advanced Topics on Privacy Enhacing Technologies course at EPFL. Spring 2022.

See https://github.com/Robb-Fr/Secretstroll-BeepBoop-Report for the report repository.

Make sure all requirements are installed: `pip install -r requirements.txt`
Run tests:

```bash
# runs credentials tests with 2 workers, 100 iterations per test
python3 -m pytest secretstroll/credential.py --count=100 -n 2 --benchmark-disable
```

Run benchmark:
```bash
# runs with the credential.py benchmark, skips tests and produces histogram
python3 -m pytest secretstroll/credential.py --benchmark-enable --benchmark-only --benchmark-histogram
```
Run tests for whole system:
```bash
cd secretstroll
chmod 777 tor
docker compose build
docker compose up -d
docker exec --workdir /server cs523-server chmod 700 /var/lib/tor/hidden_service/
docker exec --workdir /client cs523-client pip install -r requirements.txt
docker exec --workdir /server cs523-server python3 server.py setup -S restaurant -S bar -S sushi
docker exec -d --workdir /server cs523-server python3 server.py run
docker exec --workdir /client cs523-client pytest test_stroll.py::test_success_run_1
docker compose down
docker compose up -d
docker exec --workdir /client cs523-client pip install -r requirements.txt
docker exec --workdir /server cs523-server python3 server.py setup -S cybercafe -S hotel
docker exec -d --workdir /server cs523-server python3 server.py run
docker exec --workdir /client cs523-client pytest test_stroll.py::test_success_run_2
docker compose down
```