FROM ubuntu:14.04
RUN apt-get update && apt-get install -y openssh-server
USER root
ENV MYSQL_ROOT_PASSWORD=super_secret_db_password_123
CMD ["bash"]
