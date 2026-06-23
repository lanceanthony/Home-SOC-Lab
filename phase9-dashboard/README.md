# Phase 9 — SOC Overview Dashboard

**Duration:** Week 11 | **Status:** ✅ Complete

Built a single-pane SOC Overview Dashboard in Splunk that visualizes
all 5 Phase 8 detection alerts as live panels, with interactive
filtering, drilldown navigation, and 60-second auto-refresh.

## Dashboard Panels

| # | Panel | Type | Maps To |
|---|-------|------|---------|
| 1 | Total Events (Selected Range) | Single Value | Overall lab activity |
| 2 | Event Timeline by Sourcetype | Line Chart | Visibility across all sources |
| 3 | Brute Force Login Attempts | Table | Alert 1 — T1110 |
| 4 | New Admin Account Activity | Table | Alert 2 — T1136.001 |
| 5 | Suspicious Process Creation | Table | Alert 3 — T1059 |
| 6 | Lateral Movement (PsExec/SMB) | Table | Alert 4 — T1021 |
| 7 | Port Scan Detections | Table | Alert 5 — T1046 |

## Interactive Features

- **Time Range Picker** — global token filter applied across all 7 panels simultaneously
- **Computer Dropdown** — dynamically populated from ComputerName field, filters all panels to a single host
- **Drilldown** — clicking Brute Force table cells sets `eventcode_tok` to 4625; clicking Port Scan rows sets `computer_tok` to the selected host
- **Automatic Click Tokens** — `$click.value$` and `$row.ComputerName$` used for drilldown token-passing
- **Auto-Refresh** — dashboard refreshes every 60 seconds for live SOC monitoring
- **Active Token Filters Panel** — HTML panel displaying current token values so analysts can see active filters at a glance

## Dashboard Source

Full Simple XML source: [soc_overview_dashboard.xml](soc_overview_dashboard.xml)

## Key Splunk Concepts Demonstrated

- Global time token (`$global_time.earliest$` / `$global_time.latest$`) applied across all panel searches
- Dynamic dropdown populated via inline search returning `ComputerName` values
- Cell-level drilldown (`<option name="drilldown">cell</option>`) setting tokens on click
- Row-level drilldown (`<option name="drilldown">row</option>`) passing `$row.ComputerName$`
- Automatic click tokens (`$click.value$`, `$click.value2$`)
- HTML panel for displaying active token state to the analyst
- `refresh="60"` attribute for auto-refresh
- `autoRun="true"` for immediate search execution on load
- `searchWhenChanged="true"` for instant panel updates on input change

## Validation

All 7 panels confirmed returning data with Last 30 days time range. Computer dropdown dynamically populates with WIN-QL3E6D8BOAK.soclab.local. Drilldown confirmed setting EventCode Filter: 4625 on Brute Force cell click.

## Tools

- Splunk Enterprise 9.3.2
- Simple XML (Classic Dashboards)
- Windows Server 2022 (data source)
- Sysmon v15.20 (telemetry)

## Screenshots

| Screenshot | Description |
|------------|-------------|
| `phase9_dashboard_created.png` | Empty dashboard editor after creation |
| `phase9_dashboard_all_time.png` | Full dashboard, All Time, all 7 panels populated — portfolio money shot |
| `phase9_computer_filter.png` | Dashboard filtered to WIN-QL3E6D8BOAK via Computer dropdown |
| `phase9_drilldown_test.png` | Active Token Filters showing EventCode Filter: 4625 after Brute Force cell click |
| `phase9_autorefresh_xml.png` | Source editor showing refresh="60" attribute |
| `phase9_dashboard_last24h.png` | Final dashboard view, Last 30 days, all panels populated |
