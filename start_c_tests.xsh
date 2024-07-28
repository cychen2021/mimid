#!/usr/bin/env xonsh
import os.path

CWD = os.path.dirname(__file__)
cd @(CWD)/Cmimid
make precision fuzz