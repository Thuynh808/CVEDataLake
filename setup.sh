#!/bin/bash

ansible-playbook setup_infra.yaml -vv

python ~/cvedatalake/scripts/cve_data_pipeline.py
