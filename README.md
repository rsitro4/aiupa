# AWS IAM User Permission Auditor (aiupa)

Create a report to view all AWS IAM user permissions in your account.

## Installation
1. Install python3.5 or greater
2. Clone this repo
3. run ```python3 setup.py install```

## Prerequisites
AWS keys set in your ~/.aws/configure file. 

Key must be able to:
1. list_users
2. list_attached_user_policies
3. list_groups_for_user
4. list_attached_group_policies
5. list_policy_versions
6. get_policy_version

## Usage

```bash
usage: aiupa [-h] [-o {stdout,csv,json}]

optional arguments:
  -h, --help            show this help message and exit
  -o {stdout,csv,json}, --output_type {stdout,csv,json}
                        The output data format
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)