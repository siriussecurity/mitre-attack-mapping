# mitre-attack-mapping
Mapping your datasources and detections to the MITRE ATT&amp;CK Navigator framework.

This project is a bit outdated and not maintained anymore. There are two alternatives:
- Sirius Blue https://sirius.blue 
- DeTT&CT https://github.com/rabobank-cdc/DeTTECT

## Requirements
Python 3 and just a few libraries are needed, check requirements.txt for that.

pip install -r requirements.txt

## Usage
MitreAttackMapping is functionality to map your datasources and detections to the MITRE framework and to generate layer
files that can be loaded into the MITRE ATT&CK Navigator at https://mitre.github.io/attack-navigator/enterprise/

Start with the mitre-mapping.xlsx file to fill in your organisation's datasources and detections. Then run this python
script and mitrenize your organisation.

mitre-attack-mapping.py is having one optional parameter: the filename of the mapping Excel file.

## Example

![](images/screenshot.png?raw=true)
