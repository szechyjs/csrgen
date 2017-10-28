### Config

On startup the `csr.yml` file will be loaded from the current directory.
This file allows you to specify attribute defaults and requirements.

The following attributes are available for configuration:

- country
- province
- locality
- organization
- organizationalUnit

Each attribute has the following options:

- default: The default value
- required: Require this attribute to have a value
- lock: Force the default value, don't allow user to change

```yml
country:
  default: US
  lock: true
province:
  default: Ohio
  required: false
locality:
  default: Smalltown
  required: false
organization:
  default: Example Corp
  lock: true
organizationalUnit:
  default: PKI
  required: false
```

Note: If an attribute has a default value but is not required, a `-` can be
entered to remove the attribute from the CSR.
