FROM demisto/boto3py3:1.0.0.4409

ENV CI True

RUN OS_RELEASE=$(cat /etc/os-release); if echo "$OS_RELEASE" | grep -q "alpine"; then apk add build-base; fi;

RUN mkdir -p /devwork/

RUN  python -m pip install pylint

COPY  / /devwork/Beta_Integrations/
RUN rm -f /devwork/Beta_Integrations/__init__.py > /dev/null

RUN chown -R :4000 /devwork/
RUN chmod -R 775 /devwork

WORKDIR /devwork/Beta_Integrations

ENTRYPOINT ["/bin/sh", "-c"]