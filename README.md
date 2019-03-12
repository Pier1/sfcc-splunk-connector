## Salesforce Commerce Cloud (Demandware) Splunk Connector

This is a scripted input that reads one or more logs from Salesforce Commerce Cloud (SFCC) into Splunk. This script can be configured to pull many different log types from SFCC into different indexes or source types.

### Getting Started
1. Install the splunk app into your `/etc/apps/` directory of splunk
2. Open `bin/config.py` and enter the required inforation. 
3. Open `default/inputs.conf` and edit the regular expression pattern passed into the script. The example is looking for customerror-blade logs. Configure the interval in seconds that Splunk will poll the webdav directory for new logs. Change index, sourcetype, and source if you would like.
4. If you want to pull additional logs, copy all of the lines in `default/inputs.conf` and add them to the bottom with a different regex, index, sourcetype, etc...
5. Restart your splunk instance. You should now see your new scripted input in the splunk admin interface under `Data inputs > Scripts`

Learn more about scripted inputs here: https://docs.splunk.com/Documentation/Splunk/7.2.4/AdvancedDev/ScriptSetup

Pull requests welcome!
