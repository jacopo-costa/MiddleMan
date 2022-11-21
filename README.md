# MiddleMan

Add, create and update information by Sophos Cloud Central to the given Zabbix Server through API calls.

### Prerequisities

In order to run this container you'll need docker installed.

* [Windows](https://docs.docker.com/windows/started)
* [OS X](https://docs.docker.com/mac/started/)
* [Linux](https://docs.docker.com/linux/started/)

### Usage

#### Environment Variables

This environment variables are mandatory, the container doesn't start if these are not set.

* `SOPHOS_ID` - ID of the Sophos Tenant
* `SOPHOS_SECRET` - Secret of the Sophos Tenant
* `ZABBIX_HOSTNAME` - Hostname or IP of the Zabbix server
* `ZABBIX_PORT` - Port of the Zabbix Server
* `ZABBIX_PASS` - Password of the Zabbix User
* `ZABBIX_USER` - Username of the Zabbix User
* `TENANT_NAME` - Name of the Tenant, used for naming the template group, templates and host groups

#### Volumes

None

## Built With

* Python v3.7.15

## Find Us

* [GitHub](https://github.com/jacopo-costa/MiddleMan)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull
requests to us.

## Authors

* **Jacopo Costa** - *Initial work* - [jacopo-costa](https://github.com/jacopo-costa)

See also the list of [contributors](https://github.com/jacopo-costa/MiddleMan/contributors) who
participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* Vincenzo Morrone and all the people of [WhySecurity](https://www.whysecurity.it/)
