# rhel-downspeeds

Compares errata delivery of RHEL downstreams such as AlmaLinux and Rocky Linux using Python and [Chart.js](https://www.chartjs.org/)

## Usage

Run the [`gather_data.py`](gather_data.py) script, it will access errata databases and create a data result file:

```command
$ ./gather_data.py
$ ./gather_data.py -r8
```

Run a simple Python webserver to access the files (opening it without a server will cause CORS issues on most browsers):

```command
$ python3 -m http.server
```

Access the following pages:

- [http://localhost:8000/el8.html (EL8)](http://localhost:8000/el8.html)
- [http://localhost:8000/el9.html (EL9)](http://localhost:8000/el9.html)

## URLs

| Distribution | Release | Link | Notes |
| ------------ | ------- | ---- | ----- |
| RHEL | 8 | see source code | requires pagination (`rows`, `p`), but currently has no hit limit |
| RHEL | 9 | see source code | requires pagination (`rows`, `p`), but currently has no hit limit |
| AlmaLinux | 8 | [click!](https://errata.almalinux.org/8/errata.json) | JSON file |
| AlmaLinux | 9 | [click!](https://errata.almalinux.org/9/errata.json) | JSON file |
| RockyLinux | 8 | [click!](http://errata.rockylinux.org/api/v2/advisories?filters.product=Rocky%20Linux%208&filters.type=TYPE_SECURITY&filters.fetchRelated=false&page=0&limit=100) | requires pagination (`page`, `limit`), max. 100 hits per page |
| RockyLinux | 9 | [click!](http://errata.rockylinux.org/api/v2/advisories?filters.product=Rocky%20Linux%209&filters.type=TYPE_SECURITY&filters.fetchRelated=false&page=0&limit=100) | requires pagination (`page`, `limit`), max. 100 hits per page |
