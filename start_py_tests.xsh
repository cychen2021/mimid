#!/usr/bin/env xonsh

jupyter nbconvert --to notebook --execute src/PymimidBook.ipynb --ExecutePreprocessor.timeout=36000 --output=PymimidBook_.ipynb
jupyter nbconvert --to html src/PymimidBook_.ipynb --output=~/PymimidBook.html