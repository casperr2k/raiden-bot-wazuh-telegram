# Screaming Raiden Bot for Wazuh
Send wazuh alert to telegram by telegram bot (Markdown-enabled, Russia market-oriented (KSC/SearchInform/etc.).

This fork has optimized code and implements useful alert generation by default (i.e. Kaspersky virus alerting in easy readable Markdown format).

You can get decoders and rules for Kaspersky <a href=https://github.com/tread-lightly/KSC_decoders_and_rules_for_Wazuh>here</a>

<b>What's already done:</b>

- Kaspersky alerts based on custom rules
- Critical and high vulnerability alerts (using wazuh vulnerability-detector)

More alerting rules to be added as soon as I parse the correct parameters.

<h2>Installation:</h2>

1. First requirement is you should have working Telegram bot with **API KEY** and **CHAT ID** and also fully working Wazuh server.

2. Check reqirements with this command :
```
#pip install requests
```

3. Insert your **CHAT ID** to **custom-raiden-bot.py**. Copy **custom-raiden-bot** and **custom-raiden-bot.py** to **/var/ossec/integrations/**

4. Set correct permission to those files:
```
#chown root:wazuh /var/ossec/integrations/custom-raiden-bot*
#chmod 750 /var/ossec/integrations/custom-raiden-bot*
```

5. Insert your API KEY to these line and copy those lines to **/var/ossec/etc/ossec.conf**
```
    <integration>
        <name>custom-raiden-bot</name>
        <level>12</level>
        <hook_url>https://api.telegram.org/bot<API_KEY>/sendMessage</hook_url>
        <alert_format>json</alert_format>
    </integration>
```
6. Restart wazuh server
```
#systemctl restart wazuh-manager
```
