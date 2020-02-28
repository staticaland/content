FROM demisto/akamai:1.0.0.5063


RUN OS_RELEASE=$(cat /etc/os-release); if echo "$OS_RELEASE" | grep -q "alpine"; then apk add build-base; fi;

RUN mkdir -p /devwork/

RUN printf ' apipkg==1.5\nastroid==2.3.3\natomicwrites==1.3.0\nattrs==19.3.0\ncertifi==2019.11.28\nchardet==3.0.4\nexecnet==1.7.1\nfreezegun==0.3.12\nidna==2.8\nimportlib-metadata==1.3.0\nisort==4.3.21\nlazy-object-proxy==1.4.3\nmccabe==0.6.1\nmore-itertools==8.0.2\npackaging==19.2\npluggy==0.13.1\npy==1.8.0\npylint==2.4.4\npyparsing==2.4.6\npytest==5.0.1\npytest-asyncio==0.10.0\npytest-datadir-ng==1.1.1\npytest-forked==1.1.3\npytest-mock==1.13.0\npytest-xdist==1.31.0\npython-dateutil==2.8.1\nrequests==2.22.0\nrequests-mock==1.7.0\nsix==1.13.0\ntyped-ast==1.4.0\nurllib3==1.25.7\nwcwidth==0.1.7\nwrapt==1.11.2\nzipp==0.6.0' > /devwork/test-requirements.txt
RUN python -m pip install -r /devwork/test-requirements.txt

COPY  / /devwork/Integrations/
RUN rm -f /devwork/Integrations/__init__.py > /dev/null

RUN chown -R :4000 /devwork/
RUN chmod -R 775 /devwork

WORKDIR /devwork/Integrations

ENTRYPOINT ["/bin/sh", "-c"]