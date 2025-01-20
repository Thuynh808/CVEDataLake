#!/bin/bash

ansible-playbook setup_infra.yaml -vv

python ~/CVEDataLake/scripts/cve_data_pipeline.py
