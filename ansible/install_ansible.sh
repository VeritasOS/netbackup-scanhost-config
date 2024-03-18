#!/bin/bash
wget https://files.pythonhosted.org/packages/fe/0b/c28a50e7fbb7f6c6eb7bef4f023c5b408b0ff70934c2682be85e412b454d/ansible_core-2.16.2-py3-none-any.whl

yum install sshpass python3.11 python3.11-pip -y

pip3.11 install ansible_core-2.16.2-py3-none-any.whl
pip3.11 install pywinrm requests

ansible-galaxy collection install community.windows

ansible --version
