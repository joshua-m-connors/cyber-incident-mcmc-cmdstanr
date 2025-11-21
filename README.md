
# FAIR–MITRE ATT&CK Quantitative Risk Model (R / CmdStanR Version)

This repository provides an R-based implementation of the FAIR–MITRE ATT&CK quantitative cyber‑risk model. It integrates MITRE ATT&CK defensive coverage, stochastic attacker progression, Bayesian inference, and FAIR financial loss modeling into a single reproducible workflow using **R**, **CmdStanR**, and **Monte Carlo simulation**.

This is a R implementation of the model in this repository: https://github.com/joshua-m-connors/cyber-incident-mcmc-pymc

---

## 1. Overview

This model performs the following functions:

1. **Loads MITRE ATT&CK technique and mitigation data**
2. **Builds technique relevance templates** for specific threat actors or campaigns  
3. **Aggregates mitigation control strengths** into tactic-level defensive ranges  
4. **Builds a stochastic cyber‑attacker simulation** over the selected ATT&CK tactics  
5. **Applies FAIR‑aligned loss modeling** using lognormal bodies and heavy-tailed legal/reputation components  
6. **Generates full annualized loss exposure (AAL) distributions**, loss exceedance curves, and summary CSV outputs

This R version mirrors the logic of the Python/PyMC implementation but uses:
- **CmdStanR** for Bayesian inference  
- **data.table / tidyverse** for manipulation  
- **ggplot2** for diagnostics  
- **Monte Carlo simulation** implemented natively in R

---

## 2. Repository Structure

```
.
├── build_technique_relevance_template.R
├── build_mitigation_influence_template.R
├── mitre_control_strength_dashboard.R
├── cyber_incident_cmdstanr.R
├── data/
│   └── enterprise-attack.json       (MITRE ATT&CK bundle; user provides)
├── output_YYYY-MM-DD/               (auto-generated outputs)
└── README_R.md                      (this file)
```

---

## 3. Requirements

### System Requirements
- R >= 4.2
- CmdStan installed (see Installation section)
- 8 GB RAM recommended for full-scale Bayesian runs

### R Packages
Install required dependencies:

```r
install.packages(c("data.table", "jsonlite", "dplyr", "ggplot2", 
                   "readr", "stringr", "cmdstanr", "tidyr"))
cmdstanr::check_cmdstan_toolchain()
cmdstanr::install_cmdstan()
```

---

## 4. Workflow

### Step 1: Provide ATT&CK Dataset

Download MITRE ATT&CK Enterprise JSON:

```bash
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Place it in the `/data` directory or the working directory.

---

### Step 2: Build Technique Relevance Template

```r
source("build_technique_relevance_template.R")

build_technique_relevance(
  enterprise_json = "enterprise-attack.json",
  procedure = c("APT29"),      # optional
  campaign  = c("C0017")       # optional
)
```

Output:

```
output_YYYY-MM-DD/technique_relevance.csv
output_YYYY-MM-DD/technique_relevance_evidence.json
```

You may manually adjust the “Relevant” column to tune scope.

---

### Step 3: Build Mitigation Influence Template

```r
source("build_mitigation_influence_template.R")
build_mitigation_influence("enterprise-attack.json")
```

This produces:

```
mitigation_influence_template.csv
output_YYYY-MM-DD/mitigation_template_build_log.txt
```

---

### Step 4: Generate Tactic‑Level Control Strength Dashboard

```r
source("mitre_control_strength_dashboard.R")

dashboard <- build_mitre_dashboard(
  dataset = "enterprise-attack.json",
  mitigation_csv = "mitigation_influence_template.csv",
  relevance_csv = "output_YYYY-MM-DD/technique_relevance.csv"
)
```

Outputs:

- HTML dashboard of control strengths  
- tactic_control_strengths.csv  
- filtered_summary.csv  

---

### Step 5: Run the FAIR–MITRE Risk Model (R / CmdStanR)

```r
source("cyber_incident_cmdstanr.R")

results <- run_fair_mitre_model(
  dataset = "enterprise-attack.json",
  mitigation_csv = "mitigation_influence_template.csv",
  relevance_csv = "output_YYYY-MM-DD/technique_relevance.csv",
  samples = 2000
)
```

Outputs:

```
output_YYYY-MM-DD/cyber_risk_simulation_results_*.csv
output_YYYY-MM-DD/cyber_risk_simulation_summary_*.csv
output_YYYY-MM-DD/exceedance_curve_*.png
output_YYYY-MM-DD/dashboard_2x2_*.png
```

---

## 5. Outputs

| File | Description |
|------|-------------|
| technique_relevance.csv | Checklist of ATT&CK techniques for the selected actor |
| mitigation_influence_template.csv | Default control ranges and mitigation weights |
| tactic_control_strengths.csv | Tactic‑level defensive strength inputs |
| cyber_risk_simulation_results.csv | Per‑draw losses, λ, and success outcomes |
| cyber_risk_simulation_summary.csv | Mean AAL, credible intervals, loss per incident |
| dashboard_2x2.png | Posterior visualizations |
| loss_exceedance_curve.png | LEC for annual losses |

---

## 6. Model Components

### Bayesian Frequency Model
Lognormal prior calibrated to a 90 percent confidence range for attack attempts per year.

### Stage‑wise Attacker Simulation
- Retry logic  
- Detection and fallback  
- Threat capability  
- Optional adaptability  
- Only runs stages marked as relevant in the ATT&CK subset  

### FAIR Loss Modeling
Each successful attack draws category losses from:
- Lognormal body (P5 to P95 calibrated)  
- Bounded Pareto tail for heavy‑loss categories  
- Output is aggregated per draw to produce annual loss distributions  

---

## 7. Example Script Invocation

```r
Rscript cyber_incident_cmdstanr.R   --dataset enterprise-attack.json   --strengths mitigation_influence_template.csv   --relevance output_2025-01-15/technique_relevance.csv   --samples 3000   --no_plot
```

---

## 8. License

FAIR–MITRE ATT&CK Quantitative Cyber Risk Framework

Copyright 2025 Joshua M. Connors

Licensed under the Apache License, Version 2.0.

This software incorporates public data from the MITRE ATT&CK® framework.


