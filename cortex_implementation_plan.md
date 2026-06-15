# Cortex Containment Integration Plan

You spotted the missing link! While we successfully built the translation logic for when an analyst fires a Cortex Responder, your current sandbox architecture (`docker-compose.yml`) does not actually have Cortex installed yet. 

To enable your analysts to manually click "Responders" and choose "Block IP" inside TheHive, we need to spin up the Cortex active-response engine alongside TheHive.

## Proposed Architecture Changes

### 1. `docker-compose.yml`
We will add a new Cortex service to your Docker stack:
- **Image**: `thehiveproject/cortex:3.1.7-1` (compatible with TheHive 4)
- **Database**: Cortex requires Elasticsearch. We can piggyback on your existing `elasticsearch` container to save RAM, using a separate index.
- **Port**: Exposed on `9001` so you can access the Cortex UI to configure the responders.

### 2. `thehive/application.conf`
We must tell TheHive where Cortex lives so the UI unlocks the "Responders" button.
- We will add the Cortex URL (`http://cortex:9001`) and a static API key to TheHive's configuration file.

### 3. Cortex Responders Configuration
Once Cortex is booted, it needs to know *how* to block an IP. 
- Cortex comes with a "Wazuh" responder built-in.
- If you don't want to wire up the real Wazuh API right now, we can enable a simple "Mock" responder or a custom webhook responder. When the analyst clicks "Block IP" in the UI, Cortex will simulate the block, and TheHive will instantly send the `ResponderActionCreate` payload to our ATTENSE engine, successfully triggering the `CONTAINING` state.

## Open Questions
> [!IMPORTANT]
> To keep the sandbox lightweight, I recommend using a **Mock Responder** or configuring the built-in Wazuh responder to just print the block request to logs. Does that work for your graduation project demo, or do you need it to literally fire an Active Response script on your `target-agent` container?
