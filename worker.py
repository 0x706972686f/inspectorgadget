import os
import time
from utils import secrets
from utils.ipv4ioc import ipv4ioc
from utils.sha256ioc import sha256ioc
from utils.urlioc import urlioc
from celery import Celery


celery = Celery("celerystick")
celery.conf.broker_url = "redis://localhost:6379"
celery.conf.result_backend = "redis://localhost:6379"
"""
Additional Options that can be set:
celery.conf.accept_content = ["application/json"]
celery.conf.task_serializer = "json"
celery.conf.result_serializer = "json"
celery.conf.timezone = "Australia/Sydney"
"""


@celery.task(name="get_ipv4_ioc")
def get_ipv4_ioc(indicator: str):
    ip_ioc_obj = ipv4ioc(indicator)
    return ip_ioc_obj.get_result()


@celery.task(name="get_sha256_ioc")
def get_sha256_ioc(indicator: str):
    sha_ioc_obj = sha256ioc(indicator)
    return sha_ioc_obj.get_result()


@celery.task(name="get_url_ioc")
def get_url_ioc(indicator: str):
    url_ioc_obj = urlioc(indicator)
    return url_ioc_obj.get_result()