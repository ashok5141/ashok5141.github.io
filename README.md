# This Portfolio Customization

- Insinspired by just the docs jekyll theme


##### Navigation 
- Here is Sample Navigation file
```bash
- title: Ashok Introduction
  url: /
- title: AppSec
  subitems:
    - title: Command Injection
      url: /docs/appsec/command-injection
    - title: XSS
      url: /docs/appsec/xss
- title: Cloud Security
  subitems:
    - title: IaaS Security
      url: /docs/cloud/iaas
    - title: Serverless Security
      url: /docs/cloud/serverless
- title: DevSecOps
  subitems:
    - title: Security in Docker
      url: /docs/devsecops/docker
    - title: Security in Kubernetes
      url: /docs/devsecops/kubernetes
- title: Mobile Security
  subitems:
    - title: Android
      url: /docs/mobile/android
    - title: OWASP Mobile
      url: /docs/mobile/owasp
- title: Network Security
  subitems:
    - title: Reconnaissance
      url: /docs/network/reconnaissance
    - title: Scanning
      url: /docs/network/scanning
- title: Active Directory
  subitems:
    - title: Kerberoasting
      url: /docs/active-directory/kerberoasting
    - title: Pass the Hash
      url: /docs/active-directory/pass-the-hash
- title: OSCP
  url: /docs/oscp
  ```


#### Changes to made
- Make tile in the `_config.yml` file, Change the layout in the `_layout/default.html`


##### Optional Step
- Below `docker` command is optional, I want check locally in Windows OS, I can use this command in project path

```bash
docker run --rm -v "$(pwd):/srv/jekyll" -p 4000:4000 jekyll/jekyll /bin/sh -c "gem install webrick && jekyll serve --livereload"
```
- Access at [http://127.0.0.1:4000/](http://127.0.0.1:4000/)